package notification

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type threadingRepo struct {
	fakeRepo
	anchor       string
	anchorCalls  int
	persistedRef string
}

func (r *threadingRepo) SubjectAnchor(_ context.Context, tenant, channel shared.ID, version int, kind, id string) (string, error) {
	r.anchorCalls++
	if tenant != "tenant" || channel != "channel" || version != 1 || kind != "finding" || id != "finding-1" {
		return "", nil
	}
	return r.anchor, nil
}

func (r *threadingRepo) FinishAttemptWithRemoteRef(ctx context.Context, tenant, delivery shared.ID, jobID string, fence int64, attempt shared.ID, at time.Time, outcome string, status int, code string, next *time.Time, remoteRef string) error {
	r.persistedRef = remoteRef
	return r.FinishAttempt(ctx, tenant, delivery, jobID, fence, attempt, at, outcome, status, code, next)
}

type threadingSender struct{ work ports.NotificationWork }

func (s *threadingSender) Send(_ context.Context, work ports.NotificationWork, _ ports.NotificationChannelConfig) ports.NotificationSendResult {
	s.work = work
	return ports.NotificationSendResult{StatusCode: 200, RemoteRef: "new-message"}
}

func TestHandleJobUsesSubjectAnchorAndPersistsAcknowledgedReference(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	cfg, _ := json.Marshal(ports.TelegramChannelConfig{BotToken: "123456789:synthetic-token", ChatID: "12345"})
	repo := &threadingRepo{anchor: "earliest-message", fakeRepo: fakeRepo{
		relevant: true,
		work: ports.NotificationWork{
			Delivery: domain.Delivery{ID: "delivery", State: domain.DeliveryPending},
			Event:    domain.Event{TenantID: "tenant", ID: "event", Type: domain.EventTest, SourceKind: "channel_test", SourceID: "test", SchemaVersion: 1, OccurredAt: now, Data: json.RawMessage(`{}`), SubjectKind: "finding", SubjectID: "finding-1"},
			Channel:  domain.Channel{ID: "channel", Type: domain.ChannelTelegram, Enabled: true, SecretVersion: 1},
		},
	}}
	sender := &threadingSender{}
	svc, err := NewService(repo, fakeProtector{raw: cfg}, sender, fakeAudit{}, fakeClock{now}, &fakeIDs{})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]string{"delivery_id": "delivery"})
	if err := svc.HandleJob(shared.WithTenant(context.Background(), "tenant"), ports.QueuedJob{ID: "job", TenantID: "tenant", Kind: JobKind, Payload: payload, Fence: 1}); err != nil {
		t.Fatal(err)
	}
	if sender.work.SubjectAnchor != "earliest-message" || sender.work.SubjectResolved {
		t.Fatalf("threading work = %+v", sender.work)
	}
	if repo.anchorCalls != 1 || repo.persistedRef != "new-message" || repo.finished != "delivered" {
		t.Fatalf("anchor calls=%d persisted=%q outcome=%q", repo.anchorCalls, repo.persistedRef, repo.finished)
	}
}

func TestPrepareSubjectThreadDoesNotInferClosureFromEventData(t *testing.T) {
	repo := &threadingRepo{fakeRepo: fakeRepo{}}
	svc, err := NewService(repo, fakeProtector{}, nil, fakeAudit{}, fakeClock{}, &fakeIDs{})
	if err != nil {
		t.Fatal(err)
	}
	work := ports.NotificationWork{Event: domain.Event{TenantID: "tenant", Type: domain.EventTest, SubjectKind: "finding", SubjectID: "finding-1", Data: json.RawMessage(`{"state":"resolved"}`)}, Channel: domain.Channel{ID: "channel", SecretVersion: 1}}
	if err := svc.prepareSubjectThread(context.Background(), &work); err != nil {
		t.Fatal(err)
	}
	if work.SubjectResolved {
		t.Fatal("untyped event data declared a subject resolved")
	}
}

func TestSubjectThreadDoesNotReadAnchorsForOtherChannels(t *testing.T) {
	repo := &threadingRepo{}
	svc, err := NewService(repo, fakeProtector{}, nil, fakeAudit{}, fakeClock{}, &fakeIDs{})
	if err != nil {
		t.Fatal(err)
	}
	for _, channel := range []domain.ChannelType{domain.ChannelEmail, domain.ChannelWebhook, domain.ChannelMattermost, domain.ChannelRocketChat, domain.ChannelGoogleChat} {
		work := ports.NotificationWork{Channel: domain.Channel{Type: channel}, Event: domain.Event{SubjectKind: "finding", SubjectID: "test-finding"}}
		if err := svc.prepareSubjectThread(context.Background(), &work); err != nil {
			t.Fatal(err)
		}
	}
	if repo.anchorCalls != 0 {
		t.Fatalf("unnecessary anchor reads: %d", repo.anchorCalls)
	}
}
