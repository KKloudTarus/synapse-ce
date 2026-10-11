package notification

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type notificationMetricSpy struct {
	sent, failed, dead, fallback int
	channel                      domain.ChannelType
}

func (m *notificationMetricSpy) ObserveNotificationAttempt(channel domain.ChannelType, _ time.Duration, delivered, fallback bool) {
	m.channel = channel
	if delivered {
		m.sent++
	} else {
		m.failed++
	}
	if fallback {
		m.fallback++
	}
}
func (m *notificationMetricSpy) ObserveNotificationDeadLetter(channel domain.ChannelType) {
	m.channel = channel
	m.dead++
}

type metricsDeliveryRepo struct {
	*fakeRepo
	mu        sync.Mutex
	finishErr error
	noopDead  bool
}

func (r *metricsDeliveryRepo) FinishAttempt(ctx context.Context, tenant, did shared.ID, job string, fence int64, aid shared.ID, at time.Time, outcome string, status int, code string, next *time.Time) error {
	if r.finishErr != nil {
		return r.finishErr
	}
	if err := r.fakeRepo.FinishAttempt(ctx, tenant, did, job, fence, aid, at, outcome, status, code, next); err != nil {
		return err
	}
	switch outcome {
	case "delivered":
		r.work.Delivery.State = domain.DeliverySucceeded
	case "failed":
		r.work.Delivery.State = domain.DeliveryDead
	case "retrying":
		r.work.Delivery.State = domain.DeliveryRetrying
	}
	return nil
}
func (r *metricsDeliveryRepo) GetDelivery(context.Context, shared.ID, shared.ID) (domain.Delivery, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.work.Delivery, nil
}
func (r *metricsDeliveryRepo) DeadLetterDelivery(context.Context, shared.ID, shared.ID, int64, string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.noopDead || r.work.Delivery.State == domain.DeliveryDead {
		return false, nil
	}
	r.work.Delivery.State = domain.DeliveryDead
	return true, nil
}

func metricTestWork() ports.NotificationWork {
	return ports.NotificationWork{
		Delivery: domain.Delivery{ID: "delivery", ChannelType: domain.ChannelSlack, State: domain.DeliveryPending},
		Event:    domain.Event{TenantID: "tenant", ID: "event", Type: domain.EventTest, Data: json.RawMessage(`{}`)},
		Channel:  domain.Channel{ID: "channel", Type: domain.ChannelSlack, Enabled: true, SecretVersion: 1},
	}
}

func TestNotificationMetricsOnlyAfterPersistedAttempt(t *testing.T) {
	for _, tc := range []struct {
		name         string
		result       ports.NotificationSendResult
		finishErr    bool
		wantSent     int
		wantFailed   int
		wantDead     int
		wantFallback int
	}{
		{"delivered and fallback", ports.NotificationSendResult{StatusCode: 200, TemplateFallback: true}, false, 1, 0, 0, 1},
		{"retryable failure", ports.NotificationSendResult{StatusCode: 503, ErrorCode: "http_503", Retryable: true}, false, 0, 1, 0, 0},
		{"terminal failure", ports.NotificationSendResult{StatusCode: 403, ErrorCode: "http_403"}, false, 0, 1, 1, 0},
		{"failed commit is not counted", ports.NotificationSendResult{StatusCode: 200, TemplateFallback: true}, true, 0, 0, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &metricsDeliveryRepo{fakeRepo: &fakeRepo{relevant: true, work: metricTestWork()}}
			if tc.finishErr {
				repo.finishErr = errors.New("database commit failed")
			}
			now := time.Unix(1_700_000_000, 0).UTC()
			svc, err := NewService(repo, fakeProtector{raw: []byte(`{}`)}, fakeSender{result: tc.result}, fakeAudit{}, fakeClock{now}, &fakeIDs{})
			if err != nil {
				t.Fatal(err)
			}
			spy := &notificationMetricSpy{}
			svc.SetDeliveryObserver(spy)
			err = svc.HandleJob(shared.WithTenant(context.Background(), "tenant"), ports.QueuedJob{
				ID: "notification-delivery", TenantID: "tenant", Attempts: 1, Fence: 2,
				Payload: []byte(`{"delivery_id":"delivery"}`),
			})
			if tc.finishErr && !errors.Is(err, repo.finishErr) {
				t.Fatalf("got %v, want finish error", err)
			}
			if spy.sent != tc.wantSent || spy.failed != tc.wantFailed || spy.dead != tc.wantDead || spy.fallback != tc.wantFallback {
				t.Fatalf("metrics sent=%d failed=%d dead=%d fallback=%d", spy.sent, spy.failed, spy.dead, spy.fallback)
			}
			if tc.wantSent+tc.wantFailed+tc.wantDead > 0 && spy.channel != domain.ChannelSlack {
				t.Fatalf("wrong channel: %q", spy.channel)
			}
		})
	}
}

func TestNotificationDeadLetterObserverIsIdempotent(t *testing.T) {
	for _, noop := range []bool{false, true} {
		repo := &metricsDeliveryRepo{fakeRepo: &fakeRepo{work: metricTestWork()}, noopDead: noop}
		svc, err := NewService(repo, fakeProtector{}, fakeSender{}, fakeAudit{}, fakeClock{time.Now()}, &fakeIDs{})
		if err != nil {
			t.Fatal(err)
		}
		spy := &notificationMetricSpy{}
		svc.SetDeliveryObserver(spy)
		job := ports.QueuedJob{TenantID: "tenant", Payload: []byte(`{"delivery_id":"delivery"}`)}
		if err := svc.OnDeadLetter(context.Background(), job, errors.New("transport failed")); err != nil {
			t.Fatal(err)
		}
		if err := svc.OnDeadLetter(context.Background(), job, errors.New("transport failed")); err != nil {
			t.Fatal(err)
		}
		want := 1
		if noop {
			want = 0
		}
		if spy.dead != want {
			t.Fatalf("noop=%v counted %d dead-letter transitions, want %d", noop, spy.dead, want)
		}
	}
}

// This exercised the race missed by sequential replay tests: all callbacks
// read pending before the first transaction completes on some schedules.
// Exactly one persisted transition may increment the dead-letter counter.
func TestConcurrentDeadLetterCallbacksCountOneTransition(t *testing.T) {
	repo := &metricsDeliveryRepo{fakeRepo: &fakeRepo{work: metricTestWork()}}
	svc, err := NewService(repo, fakeProtector{}, fakeSender{}, fakeAudit{}, fakeClock{time.Now()}, &fakeIDs{})
	if err != nil {
		t.Fatal(err)
	}
	spy := &notificationMetricSpy{}
	svc.SetDeliveryObserver(spy)
	job := ports.QueuedJob{TenantID: "tenant", Payload: []byte(`{"delivery_id":"delivery"}`)}
	const callbacks = 32
	var wg sync.WaitGroup
	errs := make(chan error, callbacks)
	for i := 0; i < callbacks; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- svc.OnDeadLetter(context.Background(), job, errors.New("failed"))
		}()
	}
	wg.Wait()
	close(errs)
	for callErr := range errs {
		if callErr != nil {
			t.Fatal(callErr)
		}
	}
	if spy.dead != 1 {
		t.Fatalf("concurrent callbacks counted %d dead-letter transitions, want 1", spy.dead)
	}
}

var _ ports.NotificationDeliveryObserver = (*notificationMetricSpy)(nil)
