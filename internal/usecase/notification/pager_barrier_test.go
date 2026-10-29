package notification_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type pagerBarrierClock struct{ nanos atomic.Int64 }

func (c *pagerBarrierClock) Now() time.Time          { return time.Unix(0, c.nanos.Load()).UTC() }
func (c *pagerBarrierClock) advance(d time.Duration) { c.nanos.Add(int64(d)) }

type pagerBarrierAudit struct{}

func (pagerBarrierAudit) Record(context.Context, ports.AuditEntry) error { return nil }

type pagerBarrierSender struct {
	mu      sync.Mutex
	calls   []ports.NotificationWork
	entered chan struct{}
	release chan struct{}
}

func (s *pagerBarrierSender) Send(_ context.Context, work ports.NotificationWork, _ ports.NotificationChannelConfig) ports.NotificationSendResult {
	s.mu.Lock()
	s.calls = append(s.calls, work)
	s.mu.Unlock()
	if work.Event.PagerLifecycle.Episode == 1 && !work.SubjectResolved && work.Delivery.ProviderRequestRef == "" {
		close(s.entered)
		<-s.release
		return ports.NotificationSendResult{StatusCode: 202, ErrorCode: "jsm_request_unconfirmed", Retryable: true, ProviderRequestRef: "request-one"}
	}
	if work.Delivery.ProviderRequestRef != "" {
		return ports.NotificationSendResult{StatusCode: 200, RemoteRef: "episode-one-alias"}
	}
	if work.SubjectResolved {
		return ports.NotificationSendResult{StatusCode: 200, RemoteRef: work.SubjectAnchor}
	}
	return ports.NotificationSendResult{StatusCode: 200, RemoteRef: "episode-two-alias"}
}
func (s *pagerBarrierSender) snapshot() []ports.NotificationWork {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]ports.NotificationWork(nil), s.calls...)
}
func barrierEvent(id string, episode, revision int64, terminal bool, at time.Time) domain.Event {
	typ := domain.EventFindingCreated
	if terminal {
		typ = domain.EventFindingStatusChanged
	}
	return domain.Event{TenantID: "pager-barrier", ID: shared.ID(id), Type: typ, SourceKind: "finding_status", SourceID: id, SubjectKind: "finding", SubjectID: "finding-one", PagerLifecycle: domain.PagerLifecycle{Episode: episode, Revision: revision, Terminal: terminal}, OccurredAt: at, SchemaVersion: 1, Data: json.RawMessage(`{"title":"Finding"}`)}
}
func TestPagerServiceTwoWorkersLateReceipt(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "pager-barrier")
	clock := &pagerBarrierClock{}
	clock.nanos.Store(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC).UnixNano())
	jobs := memory.NewJobQueue(idgen.RandomID{}, clock.Now)
	repo := memory.NewNotificationRepository(jobs, clock.Now)
	cipher, err := vault.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	sender := &pagerBarrierSender{entered: make(chan struct{}), release: make(chan struct{})}
	svc, err := notificationuc.NewService(repo, cipher, sender, pagerBarrierAudit{}, clock, idgen.RandomID{})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetTransactionRunner(memory.NewTenantTransactionRunner())
	channel, err := svc.CreateChannel(ctx, "admin", notificationuc.ChannelInput{Name: "Pager", Type: domain.ChannelJSM, Enabled: true, Secret: "0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.CreateRule(ctx, "admin", notificationuc.RuleInput{Name: "Created", Enabled: true, EventType: domain.EventFindingCreated, ChannelIDs: []shared.ID{channel.ID}})
	if err != nil {
		t.Fatal(err)
	}
	firstIDs, err := repo.Publish(ctx, barrierEvent("trigger-one", 1, 1, false, clock.Now()))
	if err != nil || len(firstIDs) != 1 {
		t.Fatalf("first %v %v", firstIDs, err)
	}
	first, err := jobs.Claim(ctx, time.Second, notificationuc.JobKind)
	if err != nil || first == nil {
		t.Fatalf("first claim %v %v", first, err)
	}
	result := make(chan error, 1)
	go func() { result <- svc.HandleJob(ctx, *first) }()
	select {
	case <-sender.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first sender did not enter")
	}
	t.Cleanup(func() {
		select {
		case <-sender.release:
		default:
			close(sender.release)
		}
	})
	if ids, err := repo.Publish(ctx, barrierEvent("terminal-one", 1, 2, true, clock.Now())); err != nil || len(ids) != 0 {
		t.Fatalf("terminal %v %v", ids, err)
	}
	nextIDs, err := repo.Publish(ctx, barrierEvent("trigger-two", 2, 3, false, clock.Now()))
	if err != nil || len(nextIDs) != 1 {
		t.Fatalf("reopen %v %v", nextIDs, err)
	}
	clock.advance(2 * time.Second)
	second, err := jobs.Claim(ctx, time.Minute, notificationuc.JobKind)
	if err != nil || second == nil || second.ID != first.ID {
		t.Fatalf("second claim %v %v", second, err)
	}
	secondErr := svc.HandleJob(ctx, *second)
	if secondErr == nil || len(sender.snapshot()) != 1 {
		t.Fatalf("second result %v; sent %d", secondErr, len(sender.snapshot()))
	}
	if err := jobs.Deadletter(ctx, second.ID, second.Fence); err != nil {
		t.Fatal(err)
	}
	if err := svc.OnDeadLetter(ctx, *second, secondErr); err != nil {
		t.Fatal(err)
	}
	close(sender.release)
	if err := <-result; !errors.Is(err, ports.ErrStaleLease) {
		t.Fatalf("first completion expected stale lease, got %v", err)
	}
	// The late request receipt requeues a confirmation, even though the delivery and job were dead.
	var processed int
	for processed < 3 {
		clock.advance(2 * time.Second)
		job, err := jobs.Claim(ctx, time.Minute, notificationuc.JobKind)
		if err != nil || job == nil {
			t.Fatalf("claim %d: %v %v", processed, job, err)
		}
		if err := svc.HandleJob(ctx, *job); err != nil {
			t.Fatalf("handle %d: %v", processed, err)
		}
		if err := jobs.Complete(ctx, job.ID, job.Fence); err != nil {
			t.Fatal(err)
		}
		processed++
	}
	calls := sender.snapshot()
	if len(calls) != 4 {
		t.Fatalf("sender calls %d, want one write, one poll, one new episode, one close", len(calls))
	}
	seen := map[string]bool{}
	for _, call := range calls {
		label := fmt.Sprintf("%d/%t/%s", call.Event.PagerLifecycle.Episode, call.SubjectResolved, call.Delivery.ProviderRequestRef)
		if seen[label] {
			t.Fatalf("duplicate call %s", label)
		}
		seen[label] = true
		if call.SubjectResolved && (call.Event.PagerLifecycle.Episode != 1 || call.SubjectAnchor != "episode-one-alias") {
			t.Fatalf("wrong close episode/anchor: %s %q", label, call.SubjectAnchor)
		}
		if call.Event.PagerLifecycle.Episode == 2 && call.SubjectAnchor != "" {
			t.Fatal("new episode reused old anchor")
		}
	}
	if !seen["1/false/request-one"] || !seen["1/true/"] || !seen["2/false/"] {
		t.Fatalf("missing calls: %v", seen)
	}
}
