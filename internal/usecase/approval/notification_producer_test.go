package approval_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/approval"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type approvalFacts struct{}

func (approvalFacts) SnapshotNotificationLifecycleFacts(context.Context, shared.ID, shared.ID, string) (ports.NotificationLifecycleFacts, error) {
	return ports.NotificationLifecycleFacts{EngagementName: "Approval assessment", LeadUserID: "lead"}, nil
}

type hostileApprovalFacts struct{}

func (hostileApprovalFacts) SnapshotNotificationLifecycleFacts(context.Context, shared.ID, shared.ID, string) (ports.NotificationLifecycleFacts, error) {
	return ports.NotificationLifecycleFacts{EngagementName: "eng https://alice:secret@example.test", ActorName: "Bearer top-secret", ActorUserID: "actor", LeadUserID: "lead"}, nil
}
func (hostileApprovalFacts) SnapshotNotificationApprovers(context.Context, shared.ID) ([]shared.ID, error) {
	return []shared.ID{"reviewer-a", "reviewer-b"}, nil
}

type mutableClock struct{ current time.Time }

func (c *mutableClock) Now() time.Time { return c.current }

type failGetAfterDecisionStore struct {
	*memory.ApprovalStore
	fail bool
}

// forcedEnqueueConflictStore models the narrow PostgreSQL race where the first
// read sees no row, Enqueue loses its ON CONFLICT race, and the second read must
// recover the other request's immutable proposal.
type forcedEnqueueConflictStore struct {
	*memory.ApprovalStore
	hideNextGet bool
}

func (s *forcedEnqueueConflictStore) Get(ctx context.Context, id shared.ID) (agent.ProposedAction, agent.ApprovalDecision, error) {
	if s.hideNextGet {
		s.hideNextGet = false
		return agent.ProposedAction{}, agent.ApprovalDecision{}, fmt.Errorf("approval %s: %w", id, shared.ErrNotFound)
	}
	return s.ApprovalStore.Get(ctx, id)
}

func (s *failGetAfterDecisionStore) Get(ctx context.Context, id shared.ID) (agent.ProposedAction, agent.ApprovalDecision, error) {
	if s.fail {
		return agent.ProposedAction{}, agent.ApprovalDecision{}, errors.New("read after decision failed")
	}
	return s.ApprovalStore.Get(ctx, id)
}

func (s *failGetAfterDecisionStore) Decide(ctx context.Context, decision agent.ApprovalDecision) error {
	if err := s.ApprovalStore.Decide(ctx, decision); err != nil {
		return err
	}
	s.fail = true
	return nil
}
func (approvalFacts) SnapshotNotificationApprovers(context.Context, shared.ID) ([]shared.ID, error) {
	return []shared.ID{"reviewer"}, nil
}

type rosterApprovalFacts struct{ ids []shared.ID }

func (f rosterApprovalFacts) SnapshotNotificationLifecycleFacts(context.Context, shared.ID, shared.ID, string) (ports.NotificationLifecycleFacts, error) {
	return ports.NotificationLifecycleFacts{EngagementName: "Approval assessment", LeadUserID: "lead"}, nil
}

func (f rosterApprovalFacts) SnapshotNotificationApprovers(context.Context, shared.ID) ([]shared.ID, error) {
	return append([]shared.ID(nil), f.ids...), nil
}

func TestApprovalNotificationRequestReloadsCanonicalProposalAfterEnqueueConflict(t *testing.T) {
	tenant := shared.ID("approval-enqueue-conflict")
	ctx := shared.WithTenant(context.Background(), tenant)
	base := memory.NewApprovalStore()
	stored := proposal("same-action", agent.RiskIntrusive, now)
	stored.SessionID, stored.EngagementID, stored.ProposedAt = "agent-session", "stored-engagement", now.Add(-time.Minute)
	if err := base.Enqueue(ctx, stored); err != nil {
		t.Fatal(err)
	}
	store := &forcedEnqueueConflictStore{ApprovalStore: base, hideNextGet: true}
	outbox := memory.NewNotificationOutbox()
	outbox.Activate(tenant, now.Add(-time.Second))
	svc, err := approval.NewService(store, &fakeAudit{}, fixedClock{now}, agent.ModeAuto, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SetNotifications(memory.NewTenantTransactionRunner(), outbox, approvalFacts{}, approvalFacts{}); err != nil {
		t.Fatal(err)
	}
	retry := stored
	retry.Risk, retry.SessionID, retry.EngagementID, retry.ProposedAt = agent.RiskRead, "response:low-risk-retry", "retry-engagement", now
	decision, err := svc.Request(ctx, retry)
	if err != nil || decision.State != agent.ApprovalPending {
		t.Fatalf("low-risk retry auto-approved stored high-risk action: %+v err=%v", decision, err)
	}
	got, current, err := base.Get(ctx, stored.ID)
	if err != nil || got.Risk != stored.Risk || got.SessionID != stored.SessionID || got.EngagementID != stored.EngagementID || !got.ProposedAt.Equal(stored.ProposedAt) || current.State != agent.ApprovalPending {
		t.Fatalf("canonical stored approval=%+v decision=%+v err=%v", got, current, err)
	}
	records := outbox.Records(tenant)
	if len(records) != 1 || records[0].EventType != notification.EventApprovalRequested {
		t.Fatalf("records=%+v", records)
	}
	var data map[string]any
	if err := json.Unmarshal(records[0].Data, &data); err != nil {
		t.Fatal(err)
	}
	if data["engagement_id"] != stored.EngagementID.String() || data["kind"] != "agent" {
		t.Fatalf("retry facts leaked into source data=%+v", data)
	}
}

func TestApprovalNotificationRequestSkipsTerminalEnqueueConflict(t *testing.T) {
	tenant := shared.ID("approval-terminal-enqueue-conflict")
	ctx := shared.WithTenant(context.Background(), tenant)
	base := memory.NewApprovalStore()
	stored := proposal("terminal-action", agent.RiskIntrusive, now)
	if err := base.Enqueue(ctx, stored); err != nil {
		t.Fatal(err)
	}
	terminal := agent.ApprovalDecision{ActionID: stored.ID, State: agent.ApprovalDenied, DecidedBy: "reviewer", Reason: "denied", DecidedAt: now}
	if err := base.Decide(ctx, terminal); err != nil {
		t.Fatal(err)
	}
	store := &forcedEnqueueConflictStore{ApprovalStore: base, hideNextGet: true}
	outbox := memory.NewNotificationOutbox()
	outbox.Activate(tenant, now.Add(-time.Second))
	svc, err := approval.NewService(store, &fakeAudit{}, fixedClock{now}, agent.ModeAuto, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SetNotifications(memory.NewTenantTransactionRunner(), outbox, approvalFacts{}, approvalFacts{}); err != nil {
		t.Fatal(err)
	}
	decision, err := svc.Request(ctx, proposal("terminal-action", agent.RiskRead, now))
	if err != nil || decision.State != agent.ApprovalDenied {
		t.Fatalf("terminal retry=%+v err=%v", decision, err)
	}
	if records := outbox.Records(tenant); len(records) != 0 {
		t.Fatalf("terminal retry appended duplicate sources=%+v", records)
	}
}

func TestApprovalNotificationSnapshotsStayCanonicalAndSanitized(t *testing.T) {
	tenant := shared.ID("approval-snapshot-tenant")
	ctx := shared.WithTenant(context.Background(), tenant)
	store := memory.NewApprovalStore()
	outbox := memory.NewNotificationOutbox()
	outbox.Activate(tenant, now.Add(-time.Second))
	svc, err := approval.NewService(store, &fakeAudit{}, fixedClock{now}, agent.ModeManual, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SetNotifications(memory.NewTenantTransactionRunner(), outbox, hostileApprovalFacts{}, hostileApprovalFacts{}); err != nil {
		t.Fatal(err)
	}
	p := proposal("approval-canonical", agent.RiskActive, now)
	if _, err := svc.Request(ctx, p); err != nil {
		t.Fatal(err)
	}
	changed := p
	changed.Target.Value = "should-not-replace.example"
	changed.Tool = "different"
	if got, err := svc.Request(ctx, changed); err != nil || got.State != agent.ApprovalPending {
		t.Fatalf("idempotent retry = %+v, %v", got, err)
	}
	stored, _, err := svc.Get(ctx, p.ID)
	if err != nil || stored.Tool != p.Tool || stored.Target.Value != p.Target.Value {
		t.Fatalf("retry replaced immutable proposal: %+v err=%v", stored, err)
	}
	if _, err := svc.Decide(ctx, "reviewer", p.ID, false, "raw rationale must never enter snapshot"); err != nil {
		t.Fatal(err)
	}
	records := outbox.Records(tenant)
	seen := map[notification.EventType]bool{}
	for _, record := range records {
		seen[record.EventType] = true
	}
	if len(records) != 2 || !seen[notification.EventApprovalRequested] || !seen[notification.EventApprovalDecided] {
		t.Fatalf("records = %+v", records)
	}
	for _, record := range records {
		var data map[string]any
		if err := json.Unmarshal(record.Data, &data); err != nil {
			t.Fatal(err)
		}
		if _, ok := data["approver_count"]; !ok {
			t.Fatalf("%s lacks captured approver count: %s", record.EventType, record.Data)
		}
		blob := string(record.Data) + string(record.Context)
		if containsAny(blob, "secret", "top-secret", "rationale") {
			t.Fatalf("unsafe snapshot: %s", blob)
		}
		context, err := notification.DecodeTemplateContext(record.Context)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"event_type", "event_label", "occurred_at", "title", "summary"} {
			if context.Vars[key] == "" {
				t.Fatalf("%s context lacks %s: %+v", record.EventType, key, context.Vars)
			}
		}
	}
}

func TestApprovalNotificationsAutoAndTimeoutSources(t *testing.T) {
	tenant := shared.ID("approval-terminal-tenant")
	ctx := shared.WithTenant(context.Background(), tenant)
	clock := &mutableClock{current: now}
	store := memory.NewApprovalStore()
	outbox := memory.NewNotificationOutbox()
	outbox.Activate(tenant, now.Add(-time.Second))
	svc, err := approval.NewService(store, &fakeAudit{}, clock, agent.ModeAuto, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SetNotifications(memory.NewTenantTransactionRunner(), outbox, approvalFacts{}, approvalFacts{}); err != nil {
		t.Fatal(err)
	}
	if decision, err := svc.Request(ctx, proposal("approval-auto", agent.RiskRead, now)); err != nil || decision.State != agent.ApprovalApproved {
		t.Fatalf("auto decision=%+v err=%v", decision, err)
	}
	manual := proposal("approval-timeout", agent.RiskIntrusive, now)
	if _, err := svc.Request(ctx, manual); err != nil {
		t.Fatal(err)
	}
	clock.current = now.Add(time.Minute)
	if expired, err := svc.SweepExpired(ctx, manual.EngagementID); err != nil || expired != 1 {
		t.Fatalf("exact timeout boundary expired=%d err=%v", expired, err)
	}
	counts := map[notification.EventType]int{}
	for _, record := range outbox.Records(tenant) {
		counts[record.EventType]++
		var data map[string]any
		if err := json.Unmarshal(record.Data, &data); err != nil {
			t.Fatal(err)
		}
		if _, ok := data["approver_count"]; !ok {
			t.Fatalf("%s lacks approver count", record.EventType)
		}
	}
	if counts[notification.EventApprovalRequested] != 2 || counts[notification.EventApprovalDecided] != 1 || counts[notification.EventApprovalTimedOut] != 1 {
		t.Fatalf("event counts = %+v", counts)
	}
}

func TestApprovalDecisionGetFailureRollsBackDecisionAndOutbox(t *testing.T) {
	tenant := shared.ID("approval-get-failure-tenant")
	ctx := shared.WithTenant(context.Background(), tenant)
	base := memory.NewApprovalStore()
	store := &failGetAfterDecisionStore{ApprovalStore: base}
	outbox := memory.NewNotificationOutbox()
	outbox.Activate(tenant, now.Add(-time.Second))
	svc, err := approval.NewService(store, &fakeAudit{}, fixedClock{now}, agent.ModeManual, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SetNotifications(memory.NewTenantTransactionRunner(), outbox, approvalFacts{}, approvalFacts{}); err != nil {
		t.Fatal(err)
	}
	p := proposal("approval-get-failure", agent.RiskActive, now)
	if _, err := svc.Request(ctx, p); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Decide(ctx, "reviewer", p.ID, true, "ok"); err == nil {
		t.Fatal("want load failure after decision")
	}
	store.fail = false
	_, decision, err := base.Get(ctx, p.ID)
	if err != nil || decision.State != agent.ApprovalPending {
		t.Fatalf("decision escaped rollback: %+v err=%v", decision, err)
	}
	if records := outbox.Records(tenant); len(records) != 1 {
		t.Fatalf("terminal source escaped rollback: %+v", records)
	}
}

func TestApprovalStoreTenantIsolationAndRollback(t *testing.T) {
	store := memory.NewApprovalStore()
	runner := memory.NewTenantTransactionRunner()
	tenantA, tenantB := shared.ID("approval-a"), shared.ID("approval-b")
	ctxA, ctxB := shared.WithTenant(context.Background(), tenantA), shared.WithTenant(context.Background(), tenantB)
	pA, pB := proposal("approval-a-id", agent.RiskActive, now), proposal("approval-b-id", agent.RiskActive, now)
	pB.ID = "approval-b-id"
	if err := store.Enqueue(ctxB, pB); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Get(ctxA, pB.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("foreign get = %v", err)
	}
	if err := store.Enqueue(ctxA, pB); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("foreign enqueue = %v", err)
	}
	if err := runner.Run(ctxA, tenantA, func(tx context.Context) error {
		if err := store.Enqueue(tx, pA); err != nil {
			return err
		}
		return fmt.Errorf("force rollback")
	}); err == nil {
		t.Fatal("want rollback")
	}
	if _, _, err := store.Get(ctxA, pA.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("tenant A rollback failed: %v", err)
	}
	if got, decision, err := store.Get(ctxB, pB.ID); err != nil || got.ID != pB.ID || decision.State != agent.ApprovalPending {
		t.Fatalf("tenant B was erased by A rollback: %+v %+v %v", got, decision, err)
	}
}

func TestApprovalTimeoutAndHumanDecisionHaveOneTerminalWinner(t *testing.T) {
	tenant := shared.ID("approval-terminal-race-tenant")
	ctx := shared.WithTenant(context.Background(), tenant)
	store := memory.NewApprovalStore()
	outbox := memory.NewNotificationOutbox()
	outbox.Activate(tenant, now.Add(-time.Second))
	svc, err := approval.NewService(store, &fakeAudit{}, fixedClock{now}, agent.ModeManual, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SetNotifications(memory.NewTenantTransactionRunner(), outbox, approvalFacts{}, approvalFacts{}); err != nil {
		t.Fatal(err)
	}
	p := proposal("approval-terminal-race", agent.RiskActive, now.Add(-time.Minute))
	if _, err := svc.Request(ctx, p); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var group sync.WaitGroup
	results := make(chan error, 2)
	group.Add(2)
	go func() {
		defer group.Done()
		<-start
		_, err := svc.Decide(ctx, "reviewer", p.ID, false, "deny")
		results <- err
	}()
	go func() { defer group.Done(); <-start; _, err := svc.SweepExpired(ctx, p.EngagementID); results <- err }()
	close(start)
	group.Wait()
	close(results)
	for err := range results {
		if err != nil && !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("race error: %v", err)
		}
	}
	_, decision, err := store.Get(ctx, p.ID)
	if err != nil || (decision.State != agent.ApprovalDenied && decision.State != agent.ApprovalTimeout) {
		t.Fatalf("terminal winner = %+v, %v", decision, err)
	}
	terminal := 0
	for _, record := range outbox.Records(tenant) {
		if record.EventType == notification.EventApprovalDecided || record.EventType == notification.EventApprovalTimedOut {
			terminal++
		}
	}
	if terminal != 1 {
		t.Fatalf("terminal events=%d, want exactly one", terminal)
	}
}

func TestApprovalNotificationKeepsLargeRosterPrivateAndFirstSourceWins(t *testing.T) {
	tenant := shared.ID("approval-large-roster")
	ctx := shared.WithTenant(context.Background(), tenant)
	runner := memory.NewTenantTransactionRunner()
	outbox := memory.NewNotificationOutbox()
	outbox.Activate(tenant, now.Add(-time.Second))

	first := approvalRoster(1_000)
	svc, err := approval.NewService(memory.NewApprovalStore(), &fakeAudit{}, fixedClock{now}, agent.ModeManual, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// Fact readers normally query one row per user, but the producer still
	// normalizes an imperfect result so its public count matches the private
	// recipient snapshot.
	facts := rosterApprovalFacts{ids: append(append([]shared.ID(nil), first...), first[0], "")}
	if err := svc.SetNotifications(runner, outbox, facts, facts); err != nil {
		t.Fatal(err)
	}
	p := proposal("approval-large-roster", agent.RiskActive, now)
	if _, err := svc.Request(ctx, p); err != nil {
		t.Fatal(err)
	}

	records := outbox.Records(tenant)
	if len(records) != 1 {
		t.Fatalf("records=%d, want one", len(records))
	}
	if len(records[0].Data) > 16*1024 {
		t.Fatalf("public approval data is %d bytes, exceeds event budget", len(records[0].Data))
	}
	var data map[string]any
	if err := json.Unmarshal(records[0].Data, &data); err != nil {
		t.Fatal(err)
	}
	if count, ok := data["approver_count"].(float64); !ok || count != 1_000 {
		t.Fatalf("approver count=%v, want 1000", data["approver_count"])
	}
	if _, leaked := data["approver_user_ids"]; leaked {
		t.Fatalf("public data leaked private roster: %s", records[0].Data)
	}
	stored, err := outbox.ApprovalNotificationRecipients(ctx, tenant, "approval_requested", p.ID.String())
	if err != nil || len(stored) != 1_000 {
		t.Fatalf("captured roster=%d err=%v", len(stored), err)
	}

	// The same source identity is the immutable boundary. A later replay with a
	// changed membership view cannot union recipients into the first roster.
	second := append(approvalRoster(51), shared.ID("reviewer-new"))
	if err := runner.Run(ctx, tenant, func(tx context.Context) error {
		return outbox.AppendApprovalSource(tx, records[0], second)
	}); err != nil {
		t.Fatal(err)
	}
	stored, err = outbox.ApprovalNotificationRecipients(ctx, tenant, "approval_requested", p.ID.String())
	if err != nil || len(stored) != 1_000 {
		t.Fatalf("replayed roster=%d err=%v", len(stored), err)
	}
	for _, id := range stored {
		if id == "reviewer-new" {
			t.Fatal("replay expanded immutable approval roster")
		}
	}

	rollback := records[0]
	rollback.SourceID = "approval-large-rollback"
	if err := runner.Run(ctx, tenant, func(tx context.Context) error {
		if err := outbox.AppendApprovalSource(tx, rollback, approvalRoster(51)); err != nil {
			return err
		}
		return errors.New("force recipient snapshot rollback")
	}); err == nil {
		t.Fatal("want rollback error")
	}
	rolledBack, err := outbox.ApprovalNotificationRecipients(ctx, tenant, rollback.SourceKind, rollback.SourceID)
	if err != nil || len(rolledBack) != 0 {
		t.Fatalf("rolled-back roster=%d err=%v", len(rolledBack), err)
	}
}

func approvalRoster(n int) []shared.ID {
	ids := make([]shared.ID, n)
	for index := range ids {
		ids[index] = shared.ID(fmt.Sprintf("reviewer-%04d", index))
	}
	return ids
}

func containsAny(value string, values ...string) bool {
	for _, needle := range values {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

type failingApprovalOutbox struct{ next *memory.NotificationOutbox }

func (o failingApprovalOutbox) Append(ctx context.Context, record notification.SourceRecord) error {
	if err := o.next.Append(ctx, record); err != nil {
		return err
	}
	return errors.New("outbox unavailable")
}

func (o failingApprovalOutbox) AppendApprovalSource(ctx context.Context, record notification.SourceRecord, recipients []shared.ID) error {
	if err := o.next.AppendApprovalSource(ctx, record, recipients); err != nil {
		return err
	}
	return errors.New("outbox unavailable")
}

type countOnlyApprovalOutbox struct{}

func (countOnlyApprovalOutbox) Append(context.Context, notification.SourceRecord) error { return nil }

func TestApprovalNotificationsRequireRecipientSnapshotOutbox(t *testing.T) {
	svc, err := approval.NewService(memory.NewApprovalStore(), &fakeAudit{}, fixedClock{now}, agent.ModeManual, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	err = svc.SetNotifications(memory.NewTenantTransactionRunner(), countOnlyApprovalOutbox{}, approvalFacts{}, approvalFacts{})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("count-only approval outbox configuration = %v, want validation error", err)
	}
}

func TestNotificationRequestCapturesApprovalFactsAndRollsBackFailure(t *testing.T) {
	tenant := shared.ID("approval-notification-tenant")
	makeService := func(outbox ports.NotificationOutbox) (*approval.Service, *memory.ApprovalStore) {
		store := memory.NewApprovalStore()
		svc, err := approval.NewService(store, &fakeAudit{}, fixedClock{now}, agent.ModeManual, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if err := svc.SetNotifications(memory.NewTenantTransactionRunner(), outbox, approvalFacts{}, approvalFacts{}); err != nil {
			t.Fatal(err)
		}
		return svc, store
	}
	outbox := memory.NewNotificationOutbox()
	outbox.Activate(tenant, now.Add(-time.Second))
	svc, _ := makeService(outbox)
	ctx := shared.WithTenant(context.Background(), tenant)
	p := proposal("approval-notification", agent.RiskActive, now)
	if _, err := svc.Request(ctx, p); err != nil {
		t.Fatal(err)
	}
	records := outbox.Records(tenant)
	if len(records) != 1 || records[0].EventType != notification.EventApprovalRequested || records[0].CaptureVersion != 3 {
		t.Fatalf("approval records=%+v", records)
	}

	failingBase := memory.NewNotificationOutbox()
	failingBase.Activate(tenant, now.Add(-time.Second))
	failingSvc, failingStore := makeService(failingApprovalOutbox{next: failingBase})
	if _, err := failingSvc.Request(ctx, proposal("approval-rollback", agent.RiskActive, now)); err == nil {
		t.Fatal("want outbox failure")
	}
	if _, _, err := failingStore.Get(ctx, "approval-rollback"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("approval escaped rollback: %v", err)
	}
	if records := failingBase.Records(tenant); len(records) != 0 {
		t.Fatalf("outbox escaped rollback: %+v", records)
	}
}
