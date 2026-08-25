package baselineuc

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/baseline"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeAudit struct{ actions []string }

func (f *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	f.actions = append(f.actions, e.Action)
	return nil
}

const tenant = shared.ID("t1")

func obs(spawn, fanout, newexec, priv, files int64) baseline.Observation {
	return baseline.Observation{Values: [baseline.NumFeatures]int64{spawn, fanout, newexec, priv, files}}
}

func okWin() baseline.LearnWindow { return baseline.LearnWindow{Coverage: 90, MinCoverage: 60} }

func newSvc(t *testing.T) (*Service, *fakeAudit, context.Context) {
	t.Helper()
	audit := &fakeAudit{}
	svc, err := NewService(memory.NewBaselineStore(), audit, func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
		Policy{MinObservations: 3, DriftScore: 65, DriftThreshold: 3})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc, audit, shared.WithTenant(context.Background(), tenant)
}

func key() baseline.Key { return baseline.Key{Tenant: tenant, Group: "web-tier"} }

func TestColdStartActivatesThenScores(t *testing.T) {
	svc, audit, ctx := newSvc(t)
	steady := obs(2, 5, 1, 0, 3)
	// First 3 eligible observations are cold-start: abstain, then activate on the 3rd fold.
	for i := 0; i < 3; i++ {
		a, err := svc.Observe(ctx, "analyst", key(), steady, okWin())
		if err != nil {
			t.Fatal(err)
		}
		if a.Scoreable {
			t.Fatalf("observation %d during cold-start must abstain", i)
		}
	}
	// Now active — a steady observation scores low; a wild one scores high.
	low, err := svc.Observe(ctx, "analyst", key(), steady, okWin())
	if err != nil {
		t.Fatal(err)
	}
	if !low.Scoreable || low.State != baseline.StateActive {
		t.Fatalf("baseline must be active + scoreable, got scoreable=%v state=%s", low.Scoreable, low.State)
	}
	high, err := svc.Observe(ctx, "analyst", key(), obs(50, 80, 20, 9, 40), okWin())
	if err != nil {
		t.Fatal(err)
	}
	if !high.Scoreable || high.Behavior < 65 {
		t.Fatalf("a wild deviation must yield a high Behavior factor, got %d (scoreable=%v)", high.Behavior, high.Scoreable)
	}
	if low.Behavior > high.Behavior {
		t.Fatalf("steady (%d) must not exceed wild (%d)", low.Behavior, high.Behavior)
	}
	// Activation was audited.
	var activated bool
	for _, act := range audit.actions {
		if act == "baseline.activated" {
			activated = true
		}
	}
	if !activated {
		t.Fatal("activation must be audited")
	}
}

func TestSustainedDriftTransitionsAndThenAbstains(t *testing.T) {
	svc, audit, ctx := newSvc(t)
	steady := obs(2, 5, 1, 0, 3)
	for i := 0; i < 3; i++ {
		if _, err := svc.Observe(ctx, "analyst", key(), steady, okWin()); err != nil {
			t.Fatal(err)
		}
	}
	// Three consecutive wild windows => sustained drift.
	wild := obs(50, 80, 20, 9, 40)
	var last Assessment
	for i := 0; i < 3; i++ {
		a, err := svc.Observe(ctx, "analyst", key(), wild, okWin())
		if err != nil {
			t.Fatal(err)
		}
		last = a
	}
	if last.State != baseline.StateDrifted {
		t.Fatalf("sustained drift must transition to drifted, got %s", last.State)
	}
	// Once drifted the baseline abstains (coverage-honesty), not fabricating a score.
	after, err := svc.Observe(ctx, "analyst", key(), steady, okWin())
	if err != nil {
		t.Fatal(err)
	}
	if after.Scoreable {
		t.Fatal("a drifted baseline must abstain")
	}
	var drifted bool
	for _, act := range audit.actions {
		if act == "baseline.drifted" {
			drifted = true
		}
	}
	if !drifted {
		t.Fatal("drift must be audited")
	}
}

func TestAntiPoisoningWindowIsNotLearned(t *testing.T) {
	svc, _, ctx := newSvc(t)
	steady := obs(2, 5, 1, 0, 3)
	// An incident-active window must not be folded — it scores (abstains, still learning) but does not learn.
	for i := 0; i < 5; i++ {
		if _, err := svc.Observe(ctx, "analyst", key(), steady, baseline.LearnWindow{IncidentActive: true, Coverage: 90, MinCoverage: 60}); err != nil {
			t.Fatal(err)
		}
	}
	rec, err := memoryLoad(t, svc, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != baseline.StateLearning {
		t.Fatalf("baseline must still be learning (nothing was learned from tainted windows), got %s", rec.State)
	}
	if rec.Summaries[0].Count != 0 {
		t.Fatalf("no observations should have been folded from tainted windows, got %d", rec.Summaries[0].Count)
	}
}

func TestRebaselineClearsAndRelearns(t *testing.T) {
	svc, _, ctx := newSvc(t)
	steady := obs(2, 5, 1, 0, 3)
	for i := 0; i < 3; i++ {
		if _, err := svc.Observe(ctx, "analyst", key(), steady, okWin()); err != nil {
			t.Fatal(err)
		}
	}
	// Force drift.
	wild := obs(50, 80, 20, 9, 40)
	for i := 0; i < 3; i++ {
		if _, err := svc.Observe(ctx, "analyst", key(), wild, okWin()); err != nil {
			t.Fatal(err)
		}
	}
	if err := svc.Rebaseline(ctx, "analyst", key()); err != nil {
		t.Fatalf("rebaseline: %v", err)
	}
	rec, err := memoryLoad(t, svc, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != baseline.StateLearning || rec.Summaries[0].Count != 0 || rec.Drifted {
		t.Fatalf("rebaseline must reset to a clean learning baseline, got state=%s count=%d drifted=%v", rec.State, rec.Summaries[0].Count, rec.Drifted)
	}
	// Rebaselining a healthy (learning/active) baseline is rejected.
	if err := svc.Rebaseline(ctx, "analyst", key()); err == nil {
		t.Fatal("re-baselining a non-drifted baseline must be rejected")
	}
}

func TestObserveValidation(t *testing.T) {
	svc, _, ctx := newSvc(t)
	if _, err := svc.Observe(ctx, "", key(), obs(1, 1, 1, 1, 1), okWin()); err == nil {
		t.Fatal("missing actor must be rejected")
	}
	if _, err := svc.Observe(ctx, "a", baseline.Key{Group: "g"}, obs(1, 1, 1, 1, 1), okWin()); err == nil {
		t.Fatal("invalid key must be rejected")
	}
}

func TestNewServiceValidation(t *testing.T) {
	audit := &fakeAudit{}
	now := func() time.Time { return time.Unix(1, 0).UTC() }
	store := memory.NewBaselineStore()
	if _, err := NewService(nil, audit, now, DefaultPolicy()); err == nil {
		t.Fatal("nil store must be rejected")
	}
	if _, err := NewService(store, nil, now, DefaultPolicy()); err == nil {
		t.Fatal("nil audit must be rejected")
	}
	if _, err := NewService(store, audit, nil, DefaultPolicy()); err == nil {
		t.Fatal("nil clock must be rejected")
	}
	if _, err := NewService(store, audit, now, Policy{MinObservations: 0, DriftScore: 65, DriftThreshold: 3}); err == nil {
		t.Fatal("zero MinObservations must be rejected")
	}
	if _, err := NewService(store, audit, now, Policy{MinObservations: 5, DriftScore: 200, DriftThreshold: 3}); err == nil {
		t.Fatal("out-of-range drift score must be rejected")
	}
	if _, err := NewService(store, audit, now, DefaultPolicy()); err != nil {
		t.Fatalf("default policy must be valid: %v", err)
	}
}

// memoryLoad reads the persisted record straight from the store for assertions.
func memoryLoad(t *testing.T, svc *Service, ctx context.Context) (ports.BaselineRecord, error) {
	t.Helper()
	return svc.store.Load(ctx, key())
}
