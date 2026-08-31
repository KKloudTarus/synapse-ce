package response

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/approval"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/execution"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/safety"
)

// fakeEngRepo returns one in-scope, authorized engagement for every id — enough to drive the REAL
// admission gate (guard + approval + evidence) in this end-to-end test.
type fakeEngRepo struct{ eng *engagement.Engagement }

func (f *fakeEngRepo) Create(context.Context, *engagement.Engagement) error { return nil }
func (f *fakeEngRepo) Update(context.Context, *engagement.Engagement) error { return nil }
func (f *fakeEngRepo) Delete(context.Context, shared.ID) error              { return nil }
func (f *fakeEngRepo) GetByID(context.Context, shared.ID) (*engagement.Engagement, error) {
	return f.eng, nil
}
func (f *fakeEngRepo) GetByIDInTenant(context.Context, shared.ID, shared.ID) (*engagement.Engagement, error) {
	return f.eng, nil
}
func (*fakeEngRepo) GetByProjectID(context.Context, shared.ID, shared.ID) (*engagement.Engagement, error) {
	return nil, shared.ErrNotFound
}
func (*fakeEngRepo) ProjectContexts(context.Context, shared.ID, []shared.ID) (map[shared.ID]*engagement.Engagement, error) {
	return map[shared.ID]*engagement.Engagement{}, nil
}
func (*fakeEngRepo) List(context.Context, shared.ID) ([]*engagement.Engagement, error) {
	return nil, nil
}

// stillAliveVerifier simulates a telemetry check that finds the target's process STILL RUNNING after the
// stop command applied — the canonical #638 case where CommandApplied ≠ VerifiedSucceeded.
type stillAliveVerifier struct{ calls int }

func (v *stillAliveVerifier) Verify(context.Context, rdom.Action, shared.ID) (rdom.Verification, error) {
	v.calls++
	return rdom.VerificationFailed, nil
}

type e2eIDs struct{ n int }

func (g *e2eIDs) NewID() shared.ID { g.n++; return shared.ID("ev-" + string(rune('0'+g.n))) }

func e2eEngagement(now time.Time) *engagement.Engagement {
	e, _ := engagement.New(shared.ID("eng-1"), shared.ID("t1"), "Acme", "Acme", now)
	from, to := now.Add(-time.Hour), now.Add(time.Hour)
	_ = e.SetAuthorizationWindow(&from, &to, "UTC", now)
	e.Scope = engagement.Scope{InScope: []engagement.Target{{Kind: engagement.TargetDomain, Value: "app.acme.io"}}}
	return e
}

// TestGovernedResponseEndToEnd drives the FULL governed-response loop through the REAL admission gate and
// a SIMULATION executor (no host is ever touched): propose → manual approval suspends it → a human
// approves → admit → simulated execute → telemetry-verified post-condition. It proves the golden-rule
// path end-to-end — nothing executes without a HUMAN approval and an in-scope target — and it proves the
// #638 invariant: the command records as APPLIED while the effect verifies as FAILED (the process is
// still alive), so CommandApplied is never silently read as success. No real host executor exists; the
// simulation executor stands in so the whole loop is exercisable safely.
func TestGovernedResponseEndToEnd(t *testing.T) {
	now := time.Unix(1_000_000, 0).UTC()
	clock := fixedClock{t: now}
	audit := &fakeAudit{}
	ctx := tctx()

	guard, err := execution.NewGuard(&fakeEngRepo{eng: e2eEngagement(now)}, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	appr, err := approval.NewService(memory.NewApprovalStore(), audit, clock, agent.ModeManual, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := evidence.NewService(memory.NewEvidenceStore(), nil, audit, clock, &e2eIDs{})
	if err != nil {
		t.Fatal(err)
	}
	gate, err := safety.NewGate(guard, appr, ev)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(gate, SimulationExecutor{}, memory.NewResponseStore(), audit, clock)
	if err != nil {
		t.Fatal(err)
	}
	verifier := &stillAliveVerifier{}
	svc.SetEffectVerifier(verifier)

	action, err := rdom.NewAction("resp-1", rdom.KindStopProcess, "app.acme.io")
	if err != nil {
		t.Fatalf("build action: %v", err)
	}
	target := engagement.Target{Kind: engagement.TargetDomain, Value: "app.acme.io"}

	// 1) Manual mode: the FIRST apply suspends — nothing executes without a human decision.
	if _, err := svc.Apply(ctx, "eng-1", action, target, "alice"); !errors.Is(err, safety.ErrPendingApproval) {
		t.Fatalf("unapproved apply must suspend with ErrPendingApproval, got %v", err)
	}
	if verifier.calls != 0 {
		t.Fatal("nothing may be verified before the action is admitted+executed")
	}

	// 2) A HUMAN approves (a machine never could — enforced elsewhere; here bob is the human approver).
	if _, err := appr.Decide(ctx, "bob", action.ID, true, "confirmed malicious process"); err != nil {
		t.Fatalf("human approve: %v", err)
	}

	// 3) Re-apply: admitted → simulated execute → verified. The command APPLIED; the effect FAILED
	//    verification (process still alive) — the #638 invariant, end-to-end.
	rec, err := svc.Apply(ctx, "eng-1", action, target, "alice")
	if err != nil {
		t.Fatalf("approved apply must proceed: %v", err)
	}
	if rec.State != StateApplied {
		t.Fatalf("the command must record applied, got %s", rec.State)
	}
	if rec.Verification != VerificationFailed {
		t.Fatalf("CommandApplied != VerifiedSucceeded: want verification failed, got %q", rec.Verification)
	}
	if verifier.calls != 1 {
		t.Fatalf("the post-condition must be verified exactly once, got %d", verifier.calls)
	}
	if !audit.has("response.applied") || !audit.has("response.verification_failed") {
		t.Error("the applied action + its failed verification must both be audited")
	}

	// 4) Out-of-scope target is refused by the gate FIRST — no approval can widen scope.
	oos, _ := rdom.NewAction("resp-2", rdom.KindStopProcess, "evil.example.com")
	if _, err := svc.Apply(ctx, "eng-1", oos, engagement.Target{Kind: engagement.TargetDomain, Value: "evil.example.com"}, "alice"); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("out-of-scope response must be forbidden, got %v", err)
	}
}
