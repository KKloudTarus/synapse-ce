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

type auditSpy struct{ entries []ports.AuditEntry }

func (a *auditSpy) Record(_ context.Context, e ports.AuditEntry) error {
	a.entries = append(a.entries, e)
	return nil
}

type txSpy struct{ runs int }

func (t *txSpy) Run(ctx context.Context, _ shared.ID, fn func(context.Context) error) error {
	t.runs++
	return fn(ctx)
}

// sequenceSender returns one scripted result per Send.
type sequenceSender struct {
	results []ports.NotificationSendResult
	sent    int
}

func (s *sequenceSender) Send(context.Context, ports.NotificationWork, ports.NotificationChannelConfig) ports.NotificationSendResult {
	r := s.results[s.sent]
	s.sent++
	return r
}

func healthTestService(t *testing.T, sender ports.NotificationSender, threshold int) (*Service, *fakeRepo, *auditSpy, *txSpy) {
	t.Helper()
	cfg, _ := json.Marshal(ports.WebhookChannelConfig{URL: "https://example.com/hook", Secret: "0123456789abcdef"})
	repo := &fakeRepo{relevant: true, work: ports.NotificationWork{
		Delivery: domain.Delivery{ID: "delivery", ChannelType: domain.ChannelWebhook, State: domain.DeliveryPending},
		Event:    domain.Event{TenantID: "tenant", ID: "event", Type: domain.EventTest, Data: json.RawMessage(`{}`)},
		Channel:  domain.Channel{ID: "channel", Type: domain.ChannelWebhook, Enabled: true, SecretVersion: 1, Health: domain.ChannelHealth{State: domain.ChannelActive}},
	}}
	audit := &auditSpy{}
	svc, err := NewService(repo, fakeProtector{raw: cfg}, sender, audit, fakeClock{time.Unix(1700000000, 0).UTC()}, &fakeIDs{})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SetPauseThreshold(threshold); err != nil {
		t.Fatal(err)
	}
	tx := &txSpy{}
	svc.SetTransactionRunner(tx)
	return svc, repo, audit, tx
}

func runJob(t *testing.T, svc *Service, repo *fakeRepo) error {
	t.Helper()
	repo.work.Delivery.State = domain.DeliveryPending
	return svc.HandleJob(context.Background(), ports.QueuedJob{ID: "job", TenantID: "tenant", Kind: JobKind, Payload: []byte(`{"delivery_id":"delivery"}`), Attempts: 1, Fence: 1})
}

func TestHandleJobPausesAfterThresholdPermanentFailuresOnce(t *testing.T) {
	blocked := ports.NotificationSendResult{ErrorCode: "destination_blocked"}
	sender := &sequenceSender{results: []ports.NotificationSendResult{
		blocked,
		{StatusCode: 503, ErrorCode: "http_503", Retryable: true}, // transient: neither counts nor resets
		{StatusCode: 429, ErrorCode: "http_429", Retryable: true},
		blocked,
		blocked,
	}}
	svc, repo, audit, tx := healthTestService(t, sender, 3)
	for i := 0; i < 5; i++ {
		_ = runJob(t, svc, repo)
	}
	h := repo.work.Channel.Health
	if !h.Paused() || h.ConsecutiveFailures != 3 || h.LastFailureCode != "destination_blocked" || h.PausedReason != domain.PauseReasonPermanentFailures {
		t.Fatalf("health after 3 permanent + 2 transient failures = %+v", h)
	}
	if len(repo.outcomes) != 3 {
		t.Fatalf("recorded %d outcomes; transient failures must not reach channel health", len(repo.outcomes))
	}
	for _, o := range repo.outcomes {
		if o.ChannelID != "channel" || o.DeliveryID != "delivery" || o.AttemptID.IsZero() || o.Threshold != 3 || o.Class != domain.AttemptPermanent {
			t.Fatalf("outcome = %+v", o)
		}
	}
	paused := 0
	for _, e := range audit.entries {
		if e.Action == "notification.channel.paused" {
			paused++
			if e.Actor != "system" || e.Metadata["failure_code"] != "destination_blocked" || e.Metadata["failures"] != "3" || e.Metadata["delivery_id"] != "delivery" {
				t.Fatalf("pause audit = %+v", e)
			}
		}
	}
	if paused != 1 {
		t.Fatalf("pause audited %d times, want exactly once", paused)
	}
	if tx.runs != 5 {
		t.Fatalf("attempt results and health were not committed together: %d runs", tx.runs)
	}

	// A paused channel refuses the next send and cancels the delivery with a bounded reason.
	sent := sender.sent
	if err := runJob(t, svc, repo); err != nil {
		t.Fatal(err)
	}
	if sender.sent != sent || !repo.cancelled || repo.cancelReason != "channel_paused" {
		t.Fatalf("paused channel sent=%d cancelled=%v reason=%q", sender.sent-sent, repo.cancelled, repo.cancelReason)
	}
}

func TestHandleJobSuccessResetsAndExhaustedRetriesNeverCount(t *testing.T) {
	sender := &sequenceSender{results: []ports.NotificationSendResult{
		{StatusCode: 404, ErrorCode: "http_404"},
		{StatusCode: 204},
		{StatusCode: 500, ErrorCode: "http_500", Retryable: true},
		{ErrorCode: "smtp_not_configured"}, // operator-side final failure
	}}
	svc, repo, _, _ := healthTestService(t, sender, 2)
	_ = runJob(t, svc, repo)
	if repo.work.Channel.Health.ConsecutiveFailures != 1 {
		t.Fatalf("404 did not count: %+v", repo.work.Channel.Health)
	}
	if err := runJob(t, svc, repo); err != nil {
		t.Fatal(err)
	}
	if repo.work.Channel.Health.ConsecutiveFailures != 0 {
		t.Fatalf("success did not reset: %+v", repo.work.Channel.Health)
	}
	// The eighth 5xx is terminal for the delivery but still transient for the channel.
	repo.work.Delivery.State = domain.DeliveryPending
	_ = svc.HandleJob(context.Background(), ports.QueuedJob{ID: "job", TenantID: "tenant", Kind: JobKind, Payload: []byte(`{"delivery_id":"delivery"}`), Attempts: 8, Fence: 1})
	_ = runJob(t, svc, repo)
	if h := repo.work.Channel.Health; h.ConsecutiveFailures != 0 || h.Paused() {
		t.Fatalf("an exhausted retry or an operator failure counted: %+v", h)
	}
}

func TestHandleJobThresholdZeroNeverPauses(t *testing.T) {
	results := make([]ports.NotificationSendResult, 10)
	for i := range results {
		results[i] = ports.NotificationSendResult{StatusCode: 410, ErrorCode: "http_410"}
	}
	svc, repo, _, _ := healthTestService(t, &sequenceSender{results: results}, 0)
	for range results {
		_ = runJob(t, svc, repo)
	}
	if h := repo.work.Channel.Health; h.Paused() || h.ConsecutiveFailures != 10 {
		t.Fatalf("threshold 0: %+v", h)
	}
	if err := svc.SetPauseThreshold(domain.MaxPauseThreshold + 1); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("out-of-range threshold accepted: %v", err)
	}
}

type resumeRepo struct {
	fakeRepo
	channel  domain.Channel
	resumed  int
	revision int
	actor    string
}

func (r *resumeRepo) GetChannel(context.Context, shared.ID, shared.ID) (domain.Channel, error) {
	return r.channel, nil
}
func (r *resumeRepo) ResumeChannel(_ context.Context, _, _ shared.ID, revision int, actor string, _ time.Time) (domain.Channel, error) {
	if revision != r.channel.Revision {
		return domain.Channel{}, shared.ErrConflict
	}
	next, err := r.channel.Health.Resume()
	if err != nil {
		return domain.Channel{}, err
	}
	r.resumed++
	r.revision, r.actor = revision, actor
	r.channel.Health, r.channel.Revision = next, revision+1
	return r.channel, nil
}

func TestResumeChannelIsAuditedAndRevisionGuarded(t *testing.T) {
	at := time.Unix(1700000000, 0).UTC()
	repo := &resumeRepo{channel: domain.Channel{ID: "channel", Type: domain.ChannelSlack, Revision: 4, Health: domain.ChannelHealth{State: domain.ChannelPaused, PausedAt: &at, PausedReason: domain.PauseReasonPermanentFailures, ConsecutiveFailures: 5, LastFailureCode: "http_404"}}}
	audit := &auditSpy{}
	svc, _ := NewService(repo, fakeProtector{}, nil, audit, fakeClock{at}, &fakeIDs{})
	ctx := shared.WithTenant(context.Background(), "tenant")
	if _, err := svc.ResumeChannel(ctx, "admin", "channel", ResumeInput{Revision: 0}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing revision: %v", err)
	}
	if _, err := svc.ResumeChannel(ctx, "admin", "channel", ResumeInput{Revision: 3}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale revision: %v", err)
	}
	got, err := svc.ResumeChannel(ctx, "admin", "channel", ResumeInput{Revision: 4})
	if err != nil || got.Health.Paused() || got.Health.ConsecutiveFailures != 0 || got.Revision != 5 || repo.actor != "admin" {
		t.Fatalf("resume = %+v, %v", got, err)
	}
	if len(audit.entries) != 1 || audit.entries[0].Action != "notification.channel.resumed" || audit.entries[0].Actor != "admin" || audit.entries[0].Metadata["failure_code"] != "http_404" || audit.entries[0].Metadata["failures"] != "5" {
		t.Fatalf("resume audit = %+v", audit.entries)
	}
	if _, err := svc.ResumeChannel(ctx, "admin", "channel", ResumeInput{Revision: 5}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("resuming an active channel: %v", err)
	}
	if _, err := svc.ResumeChannel(context.Background(), "admin", "channel", ResumeInput{Revision: 5}); err == nil {
		t.Fatal("resume accepted a missing tenant")
	}
}
