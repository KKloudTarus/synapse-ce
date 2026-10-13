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

type providerRequestCountingSender struct{ calls int }

func (s *providerRequestCountingSender) Send(context.Context, ports.NotificationWork, ports.NotificationChannelConfig) ports.NotificationSendResult {
	s.calls++
	return ports.NotificationSendResult{StatusCode: 202, ProviderRequestRef: "test-request"}
}

type providerRequestFinishingRepo struct {
	fakeRepo
	providerRequestRefs []string
}

func (r *providerRequestFinishingRepo) FinishAttemptWithProviderRefs(ctx context.Context, tenant, delivery shared.ID, jobID string, fence int64, attempt shared.ID, at time.Time, outcome string, status int, code string, next *time.Time, remoteRef, providerRequestRef string) error {
	r.providerRequestRefs = append(r.providerRequestRefs, providerRequestRef)
	return r.FinishAttempt(ctx, tenant, delivery, jobID, fence, attempt, at, outcome, status, code, next)
}

func (r *providerRequestFinishingRepo) RedriveDelivery(_ context.Context, _ shared.ID, _ shared.ID, fence int64) (domain.Delivery, domain.Channel, error) {
	r.redriveCalls++
	r.redriveFence = fence
	r.work.Delivery.State = domain.DeliveryPending
	r.work.Delivery.RedriveFence = fence + 1
	return r.work.Delivery, r.work.Channel, nil
}

type providerRequestRecordingSender struct {
	calls  int
	work   ports.NotificationWork
	result ports.NotificationSendResult
}

func (s *providerRequestRecordingSender) Send(_ context.Context, work ports.NotificationWork, _ ports.NotificationChannelConfig) ports.NotificationSendResult {
	s.calls++
	s.work = work
	return s.result
}

func TestHandleJobFailsClosedForJSMWithoutProviderRequestFinisher(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	cfg, err := json.Marshal(ports.JSMChannelConfig{APIKey: "test-api-key"})
	if err != nil {
		t.Fatal(err)
	}
	repo := &fakeRepo{relevant: true, work: ports.NotificationWork{
		Delivery: domain.Delivery{ID: "delivery", State: domain.DeliveryPending},
		Event:    domain.Event{TenantID: "tenant", ID: "event", Type: domain.EventTest, Data: json.RawMessage(`{}`)},
		Channel:  domain.Channel{ID: "channel", Type: domain.ChannelJSM, Enabled: true, SecretVersion: 1},
	}}
	sender := &providerRequestCountingSender{}
	svc, err := NewService(repo, fakeProtector{raw: cfg}, sender, fakeAudit{}, fakeClock{now}, &fakeIDs{})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]string{"delivery_id": "delivery"})
	if err != nil {
		t.Fatal(err)
	}
	err = svc.HandleJob(shared.WithTenant(context.Background(), "tenant"), ports.QueuedJob{
		ID: "notification-delivery", TenantID: "tenant", Kind: JobKind, Payload: payload, Attempts: 1, Fence: 2,
	})
	var directive *DeliveryError
	if !errors.As(err, &directive) || !directive.Terminal() || err.Error() != "provider_resume_unavailable" {
		t.Fatalf("err=%v", err)
	}
	if sender.calls != 0 {
		t.Fatalf("sender calls=%d, want 0", sender.calls)
	}
	if repo.finished != "failed" || repo.next != nil {
		t.Fatalf("finish=%q next=%v", repo.finished, repo.next)
	}
}

func TestHandleJobPreservesAcceptedJSMReferenceOnLocalTerminalFailures(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	for _, tc := range []struct {
		name      string
		protector fakeProtector
		send      ports.NotificationSendResult
		attempts  int
		code      string
	}{
		{name: "sealed configuration unavailable", protector: fakeProtector{err: errors.New("test vault unavailable")}, attempts: 1, code: "channel_secret_unavailable"},
		{name: "configuration invalid", protector: fakeProtector{raw: []byte(`{`)}, attempts: 1, code: "channel_config_invalid"},
		{name: "retry budget exhausted", protector: fakeProtector{raw: []byte(`{"api_key":"test-api-key"}`)}, send: ports.NotificationSendResult{StatusCode: 503, ErrorCode: "network_error", Retryable: true, ProviderRequestRef: "request-create"}, attempts: 8, code: "network_error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &providerRequestFinishingRepo{fakeRepo: fakeRepo{relevant: true, work: ports.NotificationWork{
				Delivery: domain.Delivery{ID: "delivery", State: domain.DeliveryRetrying, ProviderRequestRef: "request-create"},
				Event:    domain.Event{TenantID: "tenant", ID: "event", Type: domain.EventTest, Data: json.RawMessage(`{}`)},
				Channel:  domain.Channel{ID: "channel", Type: domain.ChannelJSM, Enabled: true, SecretVersion: 1},
			}}}
			sender := &providerRequestRecordingSender{result: tc.send}
			svc, err := NewService(repo, tc.protector, sender, fakeAudit{}, fakeClock{now}, &fakeIDs{})
			if err != nil {
				t.Fatal(err)
			}
			err = svc.HandleJob(shared.WithTenant(context.Background(), "tenant"), ports.QueuedJob{ID: "notification-delivery", TenantID: "tenant", Kind: JobKind, Payload: []byte(`{"delivery_id":"delivery"}`), Attempts: tc.attempts, Fence: 2})
			var directive *DeliveryError
			if !errors.As(err, &directive) || !directive.Terminal() || err.Error() != tc.code {
				t.Fatalf("err=%v", err)
			}
			if len(repo.providerRequestRefs) != 1 || repo.providerRequestRefs[0] != "request-create" || repo.finished != "failed" || repo.next != nil {
				t.Fatalf("refs=%q outcome=%q next=%v", repo.providerRequestRefs, repo.finished, repo.next)
			}
			if tc.code != "network_error" && sender.calls != 0 {
				t.Fatalf("local failure called sender %d times", sender.calls)
			}
		})
	}
}

func TestHandleJobReceivesAcceptedJSMReferenceAfterCredentialRepairRedrive(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	const requestRef = "request-create"
	repo := &providerRequestFinishingRepo{fakeRepo: fakeRepo{
		relevant: true,
		delivery: domain.Delivery{ID: "delivery", State: domain.DeliveryDead, ChannelType: domain.ChannelJSM, RedriveFence: 7, ProviderRequestRef: requestRef},
		work: ports.NotificationWork{
			Delivery: domain.Delivery{ID: "delivery", State: domain.DeliveryDead, ChannelType: domain.ChannelJSM, ProviderRequestRef: requestRef, RedriveFence: 7},
			Event:    domain.Event{TenantID: "tenant", ID: "event", Type: domain.EventTest, Data: json.RawMessage(`{}`)},
			Channel:  domain.Channel{ID: "channel", Type: domain.ChannelJSM, Enabled: true, SecretVersion: 1},
		},
	}}
	sender := &providerRequestRecordingSender{result: ports.NotificationSendResult{StatusCode: 202, RemoteRef: "alert-alias"}}
	svc, err := NewService(repo, fakeProtector{raw: []byte(`{"api_key":"repaired-test-key"}`)}, sender, fakeAudit{}, fakeClock{now}, &fakeIDs{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := shared.WithTenant(context.Background(), "tenant")
	if _, err = svc.RedriveDelivery(ctx, "admin", "delivery", RedriveInput{Reason: "credentials repaired", ExpectedFence: 7}); err != nil {
		t.Fatal(err)
	}
	if err = svc.HandleJob(ctx, ports.QueuedJob{ID: "notification-delivery", TenantID: "tenant", Kind: JobKind, Payload: []byte(`{"delivery_id":"delivery"}`), Attempts: 1, Fence: 8}); err != nil {
		t.Fatal(err)
	}
	if sender.calls != 1 || sender.work.Delivery.ProviderRequestRef != requestRef {
		t.Fatalf("sender calls=%d work=%+v", sender.calls, sender.work.Delivery)
	}
	if len(repo.providerRequestRefs) != 1 || repo.providerRequestRefs[0] != "" || repo.finished != "delivered" {
		t.Fatalf("refs=%q outcome=%q", repo.providerRequestRefs, repo.finished)
	}
}
