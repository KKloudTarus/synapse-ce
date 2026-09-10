package notification

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeRepo struct {
	ports.NotificationRepository
	work      ports.NotificationWork
	relevant  bool
	cancelled bool
	finished  string
	next      *time.Time
}

func (f *fakeRepo) LoadWork(context.Context, shared.ID, shared.ID) (ports.NotificationWork, error) {
	return f.work, nil
}
func (f *fakeRepo) DeliveryStillRelevant(context.Context, ports.NotificationWork) (bool, error) {
	return f.relevant, nil
}
func (f *fakeRepo) BeginAttempt(_ context.Context, _, _ shared.ID, _ string, _ int64, id shared.ID, at time.Time) (domain.Attempt, error) {
	return domain.Attempt{ID: id, Number: 1, StartedAt: at}, nil
}
func (f *fakeRepo) FinishAttempt(_ context.Context, _, _ shared.ID, _ string, _ int64, _ shared.ID, _ time.Time, outcome string, _ int, _ string, next *time.Time) error {
	f.finished = outcome
	f.next = next
	return nil
}
func (f *fakeRepo) CancelDelivery(context.Context, shared.ID, shared.ID, string, int64, string) error {
	f.cancelled = true
	return nil
}
func (f *fakeRepo) DeadLetterDelivery(context.Context, shared.ID, shared.ID, string) error {
	return nil
}

type fakeProtector struct{ raw []byte }

func (f fakeProtector) Seal(v, _ []byte) (string, error)        { return string(v), nil }
func (f fakeProtector) Open(_ string, _ []byte) ([]byte, error) { return f.raw, nil }

type fakeSender struct{ result ports.NotificationSendResult }

func (f fakeSender) Send(context.Context, ports.NotificationWork, ports.NotificationChannelConfig) ports.NotificationSendResult {
	return f.result
}

type fakeClock struct{ now time.Time }

func (f fakeClock) Now() time.Time { return f.now }

type fakeIDs struct{ n int }

func (f *fakeIDs) NewID() shared.ID { f.n++; return shared.ID("id" + string(rune('0'+f.n))) }

type fakeAudit struct{}

func (fakeAudit) Record(context.Context, ports.AuditEntry) error { return nil }

func TestHandleJobPersistsRetryWithoutSleeping(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	cfg, _ := json.Marshal(ports.NotificationChannelConfig{URL: "https://example.com", Secret: "0123456789abcdef"})
	repo := &fakeRepo{relevant: true, work: ports.NotificationWork{Delivery: domain.Delivery{ID: "delivery", State: domain.DeliveryPending}, Event: domain.Event{TenantID: "tenant", ID: "event", Type: domain.EventTest, Data: json.RawMessage(`{}`)}, Channel: domain.Channel{ID: "channel", Type: domain.ChannelWebhook, Enabled: true, SecretVersion: 1}}}
	svc, err := NewService(repo, fakeProtector{raw: cfg}, fakeSender{result: ports.NotificationSendResult{StatusCode: 503, ErrorCode: "http_503", Retryable: true}}, fakeAudit{}, fakeClock{now}, &fakeIDs{})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]string{"delivery_id": "delivery"})
	err = svc.HandleJob(shared.WithTenant(context.Background(), "tenant"), ports.QueuedJob{ID: "notification-delivery", TenantID: "tenant", Kind: JobKind, Payload: payload, Attempts: 1, Fence: 2})
	var directive *DeliveryError
	if !errors.As(err, &directive) || directive.Terminal() || directive.RetryAfter() <= 0 {
		t.Fatalf("err=%v", err)
	}
	if repo.finished != "retrying" || repo.next == nil {
		t.Fatalf("finish=%q next=%v", repo.finished, repo.next)
	}
}

func TestHandleJobCancelsRecoveredSource(t *testing.T) {
	repo := &fakeRepo{relevant: false, work: ports.NotificationWork{Delivery: domain.Delivery{ID: "delivery", State: domain.DeliveryPending}, Channel: domain.Channel{ID: "channel", Type: domain.ChannelEmail, Enabled: true}}}
	svc, _ := NewService(repo, fakeProtector{}, fakeSender{}, fakeAudit{}, fakeClock{time.Now()}, &fakeIDs{})
	payload, _ := json.Marshal(map[string]string{"delivery_id": "delivery"})
	if err := svc.HandleJob(context.Background(), ports.QueuedJob{ID: "job", TenantID: "tenant", Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if !repo.cancelled {
		t.Fatal("irrelevant source was not cancelled")
	}
}

func TestValidateChannelRejectsUnsafeEndpoints(t *testing.T) {
	for _, input := range []ChannelInput{{Name: "hook", Type: domain.ChannelWebhook, URL: "http://127.0.0.1/hook", Secret: "0123456789abcdef"}, {Name: "slack", Type: domain.ChannelSlack, URL: "https://example.com/services/x"}, {Name: "mail", Type: domain.ChannelEmail, Recipients: []string{"ok@example.com\r\nBcc:evil@example.com"}}} {
		if _, _, _, err := validateChannel(input, true); err == nil {
			t.Fatalf("accepted unsafe input: %+v", input)
		}
	}
}

func TestHandleJobRetryBudgetAndTerminalReplay(t *testing.T) {
	for _, tc := range []struct {
		name     string
		state    domain.DeliveryState
		attempt  int
		terminal bool
	}{{"eighth failure", domain.DeliveryPending, 8, true}, {"ninth claim", domain.DeliveryPending, 9, true}, {"persisted dead", domain.DeliveryDead, 2, true}, {"persisted success", domain.DeliverySucceeded, 2, false}} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &fakeRepo{relevant: true, work: ports.NotificationWork{Delivery: domain.Delivery{ID: "delivery", State: tc.state}, Channel: domain.Channel{ID: "channel", Enabled: true}}}
			svc, _ := NewService(repo, fakeProtector{raw: []byte(`{}`)}, fakeSender{result: ports.NotificationSendResult{StatusCode: 500, Retryable: true, ErrorCode: "http_500"}}, fakeAudit{}, fakeClock{time.Now()}, &fakeIDs{})
			err := svc.HandleJob(context.Background(), ports.QueuedJob{TenantID: "tenant", Payload: []byte(`{"delivery_id":"delivery"}`), Attempts: tc.attempt})
			var directive *DeliveryError
			if tc.terminal {
				if !errors.As(err, &directive) || !directive.Terminal() {
					t.Fatalf("%v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if tc.attempt > 8 || tc.state != domain.DeliveryPending {
				if repo.finished != "" {
					t.Fatal("replay performed another attempt")
				}
			}
		})
	}
}
