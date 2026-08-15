package memory

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sla"
)

var slaStoreEpoch = time.Date(2026, 8, 15, 10, 0, 0, 0, time.UTC)

func slaContext(tenant shared.ID) context.Context {
	return shared.WithTenant(context.Background(), tenant)
}

func slaAssessmentFor(t *testing.T, tenant, engagement, finding shared.ID, epss float64, at time.Time) sla.Assessment {
	t.Helper()
	item, err := sla.Evaluate(sla.AssessmentInput{
		TenantID: tenant, EngagementID: engagement, FindingID: finding,
		Risk: sla.Inputs{Severity: shared.SeverityHigh, CVSSScore: 8.1, EPSS: epss, Feasibility: sla.FeasibilityPatchAvailable},
	}, sla.DefaultConfig(), at)
	if err != nil {
		t.Fatal(err)
	}
	return item
}

func slaPolicyFor(t *testing.T, tenant shared.ID, version, actor string, at time.Time) sla.Policy {
	t.Helper()
	cfg := sla.DefaultConfig()
	cfg.Version = version
	policy, err := sla.NewPolicy(tenant, cfg, actor, at)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func TestSLAStorePolicyActivationHistoryAndIdempotency(t *testing.T) {
	store := NewSLAStore()
	ctx := slaContext("tenant-a")
	v1 := slaPolicyFor(t, "tenant-a", "sla-v1", "alice", slaStoreEpoch)
	created, err := store.PutPolicy(ctx, v1, true)
	if err != nil || !created {
		t.Fatalf("put v1 created=%v err=%v", created, err)
	}
	created, err = store.PutPolicy(ctx, v1, true)
	if err != nil || created {
		t.Fatalf("replay v1 created=%v err=%v", created, err)
	}
	v2 := slaPolicyFor(t, "tenant-a", "sla-v2", "bob", slaStoreEpoch.Add(time.Hour))
	if created, err = store.PutPolicy(ctx, v2, true); err != nil || !created {
		t.Fatalf("put v2 created=%v err=%v", created, err)
	}
	active, err := store.ActivePolicy(ctx, "tenant-a")
	if err != nil || active.Config.Version != "sla-v2" {
		t.Fatalf("active=%+v err=%v", active, err)
	}
	history, err := store.PolicyHistory(ctx, "tenant-a")
	if err != nil || len(history) != 2 || history[0].Config.Version != "sla-v2" || history[1].Config.Version != "sla-v1" {
		t.Fatalf("history=%+v err=%v", history, err)
	}
}

func TestSLAStorePolicyVersionCannotBeRewritten(t *testing.T) {
	store := NewSLAStore()
	ctx := slaContext("tenant-a")
	policy := slaPolicyFor(t, "tenant-a", "policy-1", "alice", slaStoreEpoch)
	if _, err := store.PutPolicy(ctx, policy, true); err != nil {
		t.Fatal(err)
	}
	changed := sla.DefaultConfig()
	changed.Version = "policy-1"
	changed.Thresholds.High++
	forged, err := sla.NewPolicy("tenant-a", changed, "bob", slaStoreEpoch.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutPolicy(ctx, forged, true); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("policy rewrite should conflict, got %v", err)
	}
}

func TestSLAStoreAssessmentReplayPreservesOriginalDeadlines(t *testing.T) {
	store := NewSLAStore()
	ctx := slaContext("tenant-a")
	first := slaAssessmentFor(t, "tenant-a", "eng-1", "finding-1", 0.4, slaStoreEpoch)
	stored, err := store.UpsertAssessment(ctx, first)
	if err != nil || !stored.Created {
		t.Fatalf("first upsert=%+v err=%v", stored, err)
	}
	replay := slaAssessmentFor(t, "tenant-a", "eng-1", "finding-1", 0.4, slaStoreEpoch.Add(48*time.Hour))
	if replay.ID != first.ID || replay.Result.RemediateBy == first.Result.RemediateBy {
		t.Fatal("test setup does not represent same material input at a later clock")
	}
	stored, err = store.UpsertAssessment(ctx, replay)
	if err != nil || stored.Created {
		t.Fatalf("replay upsert=%+v err=%v", stored, err)
	}
	if !stored.Assessment.Result.RemediateBy.Equal(first.Result.RemediateBy) || !stored.Assessment.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("replay moved durable deadline: first=%+v replay=%+v", first, stored.Assessment)
	}
	current, err := store.Current(ctx, "tenant-a", "eng-1", "finding-1")
	if err != nil || current.Lifecycle.Status != sla.RemediationOpen || current.Lifecycle.Version != 1 {
		t.Fatalf("current=%+v err=%v", current, err)
	}
}

func TestSLAStoreMaterialRefreshLinksHistoryAndPreservesHumanState(t *testing.T) {
	store := NewSLAStore()
	ctx := slaContext("tenant-a")
	first := slaAssessmentFor(t, "tenant-a", "eng-1", "finding-1", 0.1, slaStoreEpoch)
	if _, err := store.UpsertAssessment(ctx, first); err != nil {
		t.Fatal(err)
	}
	current, _ := store.Current(ctx, "tenant-a", "eng-1", "finding-1")
	expires := slaStoreEpoch.Add(30 * 24 * time.Hour)
	nextState, event, err := sla.ApplyTransition(current.Lifecycle, "event-1", sla.TransitionCommand{
		To: sla.RemediationAcceptedRisk, Actor: "alice", Reason: "vendor exception", ExpectedVersion: 1,
		CompensatingControl: "WAF", AcceptanceExpiresAt: &expires,
	}, slaStoreEpoch.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveTransition(ctx, nextState, event); err != nil {
		t.Fatal(err)
	}
	refresh := slaAssessmentFor(t, "tenant-a", "eng-1", "finding-1", 0.9, slaStoreEpoch.Add(2*time.Hour))
	upserted, err := store.UpsertAssessment(ctx, refresh)
	if err != nil || !upserted.Created || upserted.Assessment.PreviousAssessmentID != first.ID {
		t.Fatalf("refresh=%+v err=%v", upserted, err)
	}
	if !upserted.Assessment.DeadlineAnchorAt.Equal(first.DeadlineAnchorAt) ||
		upserted.Assessment.Result.RemediateBy.After(first.Result.RemediateBy) {
		t.Fatalf("refresh reset or extended SLA clock: first=%+v refresh=%+v", first, upserted.Assessment)
	}
	current, err = store.Current(ctx, "tenant-a", "eng-1", "finding-1")
	if err != nil {
		t.Fatal(err)
	}
	state := current.Lifecycle
	if state.AssessmentID != refresh.ID || state.Status != sla.RemediationAcceptedRisk || state.Version != 2 ||
		state.AcceptedBy != "alice" || state.AcceptanceExpiresAt == nil || !state.AcceptanceExpiresAt.Equal(expires) ||
		state.UpdatedBy != "alice" {
		t.Fatalf("machine refresh clobbered human state: %+v", state)
	}
	history, err := store.AssessmentHistory(ctx, "tenant-a", "eng-1", "finding-1")
	if err != nil || len(history) != 2 || history[0].ID != refresh.ID || history[1].ID != first.ID {
		t.Fatalf("history=%+v err=%v", history, err)
	}
}

func TestSLAStoreTransitionIsAtomicAndOptimistic(t *testing.T) {
	store := NewSLAStore()
	ctx := slaContext("tenant-a")
	assessment := slaAssessmentFor(t, "tenant-a", "eng-1", "finding-1", 0.1, slaStoreEpoch)
	if _, err := store.UpsertAssessment(ctx, assessment); err != nil {
		t.Fatal(err)
	}
	current, _ := store.Current(ctx, "tenant-a", "eng-1", "finding-1")
	next, event, err := sla.ApplyTransition(current.Lifecycle, "event-1", sla.TransitionCommand{
		To: sla.RemediationMitigating, Actor: "alice", Reason: "change scheduled", ExpectedVersion: 1,
	}, slaStoreEpoch.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveTransition(ctx, next, event); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveTransition(ctx, next, event); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale replay should conflict, got %v", err)
	}
	events, err := store.LifecycleEvents(ctx, "tenant-a", "eng-1", "finding-1")
	if err != nil || len(events) != 1 || events[0].ID != "event-1" {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	got, _ := store.Current(ctx, "tenant-a", "eng-1", "finding-1")
	if got.Lifecycle.Version != 2 || got.Lifecycle.Status != sla.RemediationMitigating {
		t.Fatalf("unexpected current state: %+v", got.Lifecycle)
	}
}

func TestSLAStoreTransitionConflictsWithConcurrentRiskRefresh(t *testing.T) {
	store := NewSLAStore()
	ctx := slaContext("tenant-a")
	first := slaAssessmentFor(t, "tenant-a", "eng-1", "finding-1", 0.1, slaStoreEpoch)
	if _, err := store.UpsertAssessment(ctx, first); err != nil {
		t.Fatal(err)
	}
	stale, _ := store.Current(ctx, "tenant-a", "eng-1", "finding-1")
	next, event, err := sla.ApplyTransition(stale.Lifecycle, "event-stale-risk", sla.TransitionCommand{
		To: sla.RemediationMitigating, Actor: "alice", Reason: "scheduled from old risk view", ExpectedVersion: 1,
	}, slaStoreEpoch.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	refresh := slaAssessmentFor(t, "tenant-a", "eng-1", "finding-1", 0.95, slaStoreEpoch.Add(30*time.Minute))
	if _, err := store.UpsertAssessment(ctx, refresh); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveTransition(ctx, next, event); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("transition from stale risk view should conflict, got %v", err)
	}
	current, err := store.Current(ctx, "tenant-a", "eng-1", "finding-1")
	if err != nil {
		t.Fatal(err)
	}
	if current.Assessment.ID != refresh.ID || current.Lifecycle.AssessmentID != refresh.ID ||
		current.Lifecycle.Status != sla.RemediationOpen || current.Lifecycle.Version != 1 {
		t.Fatalf("stale transition rolled back refreshed provenance: %+v", current)
	}
	events, err := store.LifecycleEvents(ctx, "tenant-a", "eng-1", "finding-1")
	if err != nil || len(events) != 0 {
		t.Fatalf("conflicting transition appended events=%+v err=%v", events, err)
	}
}

func TestSLAStoreListOrdersByDueDateThenFinding(t *testing.T) {
	store := NewSLAStore()
	ctx := slaContext("tenant-a")
	inputs := []struct {
		id   shared.ID
		epss float64
	}{
		{id: "finding-low", epss: 0},
		{id: "finding-hot-b", epss: 0.9},
		{id: "finding-hot-a", epss: 0.9},
	}
	for _, input := range inputs {
		if _, err := store.UpsertAssessment(ctx, slaAssessmentFor(t, "tenant-a", "eng-1", input.id, input.epss, slaStoreEpoch)); err != nil {
			t.Fatal(err)
		}
	}
	items, err := store.ListCurrent(ctx, "tenant-a", "eng-1")
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, len(items))
	for i := range items {
		got[i] = items[i].Assessment.FindingID.String()
	}
	want := []string{"finding-hot-a", "finding-hot-b", "finding-low"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("order=%v, want %v", got, want)
	}
}

func TestSLAStoreFailsClosedAcrossTenantBoundaries(t *testing.T) {
	store := NewSLAStore()
	ctxA := slaContext("tenant-a")
	ctxB := slaContext("tenant-b")
	assessment := slaAssessmentFor(t, "tenant-a", "eng-1", "finding-1", 0.2, slaStoreEpoch)
	if _, err := store.UpsertAssessment(context.Background(), assessment); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing tenant context should fail, got %v", err)
	}
	if _, err := store.UpsertAssessment(ctxB, assessment); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("mismatched tenant should fail, got %v", err)
	}
	if _, err := store.UpsertAssessment(ctxA, assessment); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Current(ctxB, "tenant-a", "eng-1", "finding-1"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("cross-tenant read should fail, got %v", err)
	}
	if _, err := store.Current(ctxB, "tenant-b", "eng-1", "finding-1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("tenant B should see not found, got %v", err)
	}
}

func TestSLAStoreReturnsDefensiveCopies(t *testing.T) {
	store := NewSLAStore()
	ctx := slaContext("tenant-a")
	assessment := slaAssessmentFor(t, "tenant-a", "eng-1", "finding-1", 0.2, slaStoreEpoch)
	assessment.Result.Breakdown.Overrides = []string{"one"}
	// Recompute validation identity is unaffected because overrides are output. This deliberately
	// exercises adapter cloning rather than the scorer.
	if _, err := store.UpsertAssessment(ctx, assessment); err != nil {
		t.Fatal(err)
	}
	first, _ := store.Current(ctx, "tenant-a", "eng-1", "finding-1")
	first.Assessment.Result.Breakdown.Overrides[0] = "mutated"
	second, _ := store.Current(ctx, "tenant-a", "eng-1", "finding-1")
	if second.Assessment.Result.Breakdown.Overrides[0] != "one" {
		t.Fatal("caller mutated store-owned assessment slice")
	}
}
