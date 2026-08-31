package response

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	offensivepolicyuc "github.com/KKloudTarus/synapse-ce/internal/usecase/offensivepolicy"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/safety"
)

// The response service satisfies the kill switch's ResponseHalter seam (#425 AC9) — proven at compile
// time so the #418 kill switch can halt response actions exactly as it halts offensive work.
var _ offensivepolicyuc.ResponseHalter = (*Service)(nil)

// ---- fakes ------------------------------------------------------------------------------------------

type fakeAdmitter struct {
	mu    sync.Mutex
	calls []string // proposed action ids admitted, in order
	err   error    // when set, Admit refuses (nothing must execute)
}

func (f *fakeAdmitter) Admit(_ context.Context, p agent.ProposedAction, _ string) (safety.AdmittedAction, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, p.ID.String())
	return safety.AdmittedAction{}, f.err
}

type fakeExec struct {
	mu       sync.Mutex
	runs     []ExecRequest
	observed offensivepolicy.Radius
	affected int
	already  bool
}

func (e *fakeExec) Execute(_ context.Context, req ExecRequest) (ExecOutcome, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.runs = append(e.runs, req)
	obs := req.Declared
	if e.observed != "" {
		obs = e.observed
	}
	affected := 1
	if e.affected != 0 {
		affected = e.affected
	}
	return ExecOutcome{ObservedRadius: obs, AffectedCount: affected, AlreadyApplied: e.already}, nil
}
func (e *fakeExec) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.runs)
}

type fakeAudit struct {
	mu      sync.Mutex
	actions []string
}

func (a *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.actions = append(a.actions, e.Action)
	return nil
}
func (a *fakeAudit) has(action string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, x := range a.actions {
		if x == action {
			return true
		}
	}
	return false
}

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

type harness struct {
	svc   *Service
	admit *fakeAdmitter
	exec  *fakeExec
	audit *fakeAudit
	store ports.ResponseStore
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	admit := &fakeAdmitter{}
	exec := &fakeExec{}
	audit := &fakeAudit{}
	store := memory.NewResponseStore()
	svc, err := NewService(admit, exec, store, audit, fixedClock{t: time.Unix(1000, 0)})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{svc: svc, admit: admit, exec: exec, audit: audit, store: store}
}

func tctx() context.Context { return shared.WithTenant(context.Background(), "t1") }

func act(id string) rdom.Action {
	sp, _ := rdom.SpecFor(rdom.KindIsolateHost)
	return rdom.Action{ID: shared.ID(id), Kind: rdom.KindIsolateHost, Target: "host-1", BlastRadius: sp.Radius,
		Argv: []string{"synapse-agent-response", "isolate-host", "host-1"}, Reversal: sp.Reversal}
}

// target matches the action's Target ("host-1") — Apply binds the admitted scope target to the executed
// action target, so they must be the same asset.
func target() engagement.Target {
	return engagement.Target{Kind: engagement.TargetIP, Value: "host-1"}
}

// ---- tests ------------------------------------------------------------------------------------------

// TestApplyRoutesThroughAdmissionBeforeExecuting is the #425 admission-bypass guarantee: nothing executes
// unless the gate admitted it. When admission refuses, the executor is never called.
func TestApplyRoutesThroughAdmissionBeforeExecuting(t *testing.T) {
	h := newHarness(t)
	h.admit.err = shared.ErrForbidden // gate refuses
	_, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), "alice")
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("a refused admission must fail, got %v", err)
	}
	if len(h.admit.calls) != 1 {
		t.Fatalf("Apply must route through the admission gate, admit calls=%v", h.admit.calls)
	}
	if h.exec.count() != 0 {
		t.Fatal("nothing may execute when admission is refused (no bypass)")
	}
}

// TestApplyRefusesModelApprover: a machine identity can never approve a response action.
func TestApplyRefusesModelApprover(t *testing.T) {
	h := newHarness(t)
	for _, who := range []string{"llm:gpt-5", "agent:planner", "system:auto", ""} {
		if _, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), who); !errors.Is(err, shared.ErrForbidden) {
			t.Fatalf("approver %q must be refused, got %v", who, err)
		}
	}
	if len(h.admit.calls) != 0 {
		t.Fatal("a machine approver must be refused BEFORE admission")
	}
	if h.exec.count() != 0 {
		t.Fatal("nothing may execute for a machine approver")
	}
}

// TestApplyHappyPathExecutesAndAudits: an admitted, human-approved action executes argv-only and is
// recorded applied.
func TestApplyHappyPathExecutesAndAudits(t *testing.T) {
	h := newHarness(t)
	rec, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), "alice")
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if rec.State != StateApplied {
		t.Fatalf("want applied, got %s", rec.State)
	}
	if h.exec.count() != 1 {
		t.Fatalf("the action must execute exactly once, got %d", h.exec.count())
	}
	// Argv-only, no shell, ever.
	if run := h.exec.runs[0]; len(run.Argv) == 0 || run.Argv[0] != "synapse-agent-response" {
		t.Fatalf("execution must be argv-only, got %v", run.Argv)
	}
	if !h.audit.has("response.applied") {
		t.Error("an applied action must be audited")
	}
}

// TestApplyIsIdempotent: re-issuing an applied action is a no-op reporting the already-applied state.
func TestApplyIsIdempotent(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), "alice"); err != nil {
		t.Fatal(err)
	}
	rec, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), "alice")
	if err != nil {
		t.Fatalf("re-apply must be a no-op, got %v", err)
	}
	if rec.State != StateApplied {
		t.Fatalf("re-apply must report applied, got %s", rec.State)
	}
	if h.exec.count() != 1 {
		t.Fatalf("re-issuing must not execute twice, got %d executions", h.exec.count())
	}
}

// TestApplyHaltsOnBlastRadiusViolation: an effect broader than declared halts the action as a violation.
func TestApplyHaltsOnBlastRadiusViolation(t *testing.T) {
	h := newHarness(t)
	h.exec.observed = offensivepolicy.RadiusStateChanging
	a := act("a1")
	a.BlastRadius = offensivepolicy.RadiusReadOnly // declared read-only, but the effect changes state
	rec, err := h.svc.Apply(tctx(), "eng-1", a, target(), "alice")
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("a blast-radius violation must be refused, got %v", err)
	}
	if rec.State != StateViolation {
		t.Fatalf("want violation state, got %s", rec.State)
	}
	if !h.audit.has("response.blast_radius_violation") {
		t.Error("the violation must be audited")
	}
}

// TestApplyHaltsWhenEffectTouchesMoreThanOneTarget: a state-changing action declares a SINGLE target, so
// an effect touching more than one asset is a blast-radius violation (the meaningful case for the
// binary radius, where every response action is state_changing).
func TestApplyHaltsWhenEffectTouchesMoreThanOneTarget(t *testing.T) {
	h := newHarness(t)
	h.exec.affected = 3 // the executor observed the action touch 3 assets, not the 1 declared
	rec, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), "alice")
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("touching more than the declared target must be refused, got %v", err)
	}
	if rec.State != StateViolation {
		t.Fatalf("want violation, got %s", rec.State)
	}
}

// TestApplyRefusesTargetMismatch: an admission obtained for one asset cannot execute against another.
func TestApplyRefusesTargetMismatch(t *testing.T) {
	h := newHarness(t)
	other := engagement.Target{Kind: engagement.TargetIP, Value: "different-host"}
	if _, err := h.svc.Apply(tctx(), "eng-1", act("a1"), other, "alice"); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("a mismatched admitted/executed target must be refused, got %v", err)
	}
	if len(h.admit.calls) != 0 || h.exec.count() != 0 {
		t.Fatal("a target mismatch must be refused before admission and execution")
	}
}

// TestDryRunExecutesNothing: a dry run enumerates the action and its reversal and runs nothing.
func TestDryRunExecutesNothing(t *testing.T) {
	h := newHarness(t)
	steps, err := h.svc.DryRun(act("a1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 2 {
		t.Fatalf("dry run must enumerate apply + reversal, got %d steps", len(steps))
	}
	if h.exec.count() != 0 || len(h.admit.calls) != 0 {
		t.Fatal("dry run must execute nothing and admit nothing")
	}
}

// TestRevertIsAdmittedAndAudited: a reversal is itself admitted (through the gate) and audited.
func TestRevertIsAdmittedAndAudited(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), "alice"); err != nil {
		t.Fatal(err)
	}
	admBefore := len(h.admit.calls)
	rec, err := h.svc.Revert(tctx(), "a1", target(), "alice")
	if err != nil {
		t.Fatalf("revert: %v", err)
	}
	if rec.State != StateReverted {
		t.Fatalf("want reverted, got %s", rec.State)
	}
	if len(h.admit.calls) != admBefore+1 {
		t.Error("the reversal must itself pass through admission")
	}
	if !h.audit.has("response.reverted") {
		t.Error("the reversal must be audited")
	}
	// The reversal executed argv-only, flagged as a reversal.
	last := h.exec.runs[len(h.exec.runs)-1]
	if !last.IsReversal || len(last.Argv) == 0 {
		t.Errorf("reversal must be an argv-only, reversal-flagged execution: %+v", last)
	}
}

// TestKillSwitchHaltsPending is the #425 kill-switch requirement, measured: a pending (admitted-but-not-
// approved) action is halted.
func TestKillSwitchHaltsPending(t *testing.T) {
	h := newHarness(t)
	h.admit.err = safety.ErrPendingApproval // admission suspends → pending recorded
	if _, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), "alice"); !errors.Is(err, safety.ErrPendingApproval) {
		t.Fatalf("manual admission must suspend, got %v", err)
	}
	if h.exec.count() != 0 {
		t.Fatal("a pending action must not execute")
	}
	start := time.Now()
	n, err := h.svc.HaltResponses(tctx(), "t1", "operator@example.test", "customer requested a stop")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("halt: %v", err)
	}
	if n != 1 {
		t.Fatalf("the pending action must be halted, got %d", n)
	}
	if elapsed > time.Second {
		t.Fatalf("halt took %s, unexpectedly slow", elapsed)
	}
	if !h.audit.has("response.halted") {
		t.Error("the halt must be audited")
	}
	// The halted action is cancelled, and re-applying it is refused-by-admission (still no execution).
	rec, _, _ := h.store.Get(tctx(), "a1")
	if rec.State != StateCancelled {
		t.Fatalf("halted action must be cancelled, got %s", rec.State)
	}
}

// TestFailClosedMissingReversibility: an action with no reversal is refused with nothing executed.
func TestFailClosedMissingReversibility(t *testing.T) {
	h := newHarness(t)
	a := act("a1")
	a.Reversal = rdom.ReversalSpec{} // no reversal
	if _, err := h.svc.Apply(tctx(), "eng-1", a, target(), "alice"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("an action with no reversal must be refused, got %v", err)
	}
	if len(h.admit.calls) != 0 || h.exec.count() != 0 {
		t.Fatal("nothing may be admitted or executed for an unimplementable action")
	}
}

func TestApplyRequiresTenant(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.Apply(context.Background(), "eng-1", act("a1"), target(), "alice"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a missing tenant must be refused, got %v", err)
	}
}

// ---- #638 telemetry-verified post-condition -------------------------------------------------------

type fakeVerifier struct {
	outcome rdom.Verification
	err     error
	calls   int
}

func (f *fakeVerifier) Verify(_ context.Context, _ rdom.Action, _ shared.ID) (rdom.Verification, error) {
	f.calls++
	return f.outcome, f.err
}

// TestApplyVerifiesEffectPostCondition is the #638 guarantee: CommandApplied ≠ VerifiedSucceeded. When a
// verifier is wired, an applied action's EFFECT is confirmed against telemetry — a kill whose process is
// still observed alive verifies as Failed (not a success), insufficient coverage is Unknown, and a
// verifier error is never a silent success. The command still counts as applied; verification is a
// separate axis carried on the record + a distinct audit line, and it is persisted.
func TestApplyVerifiesEffectPostCondition(t *testing.T) {
	cases := []struct {
		name    string
		outcome rdom.Verification
		err     error
		want    rdom.Verification
		audit   string
	}{
		{"succeeded", VerificationSucceeded, nil, VerificationSucceeded, "response.verified"},
		{"failed_effect_not_present", VerificationFailed, nil, VerificationFailed, "response.verification_failed"},
		{"unknown_coverage", VerificationUnknown, nil, VerificationUnknown, "response.verification_unknown"},
		{"verifier_error_is_not_success", VerificationPending, errors.New("telemetry down"), VerificationUnknown, "response.verification_unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			vf := &fakeVerifier{outcome: tc.outcome, err: tc.err}
			h.svc.SetEffectVerifier(vf)
			rec, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), "alice")
			if err != nil {
				t.Fatalf("apply: %v", err)
			}
			if rec.State != StateApplied {
				t.Fatalf("the command must still be applied, got state %s", rec.State)
			}
			if vf.calls != 1 {
				t.Fatalf("verifier must run exactly once, got %d", vf.calls)
			}
			if rec.Verification != tc.want {
				t.Fatalf("verification = %q, want %q", rec.Verification, tc.want)
			}
			if !h.audit.has(tc.audit) {
				t.Errorf("expected audit %q", tc.audit)
			}
			got, found, _ := h.store.Get(tctx(), "a1")
			if !found || got.Verification != tc.want {
				t.Fatalf("persisted verification = %q (found=%v), want %q", got.Verification, found, tc.want)
			}
		})
	}
}

// TestApplyWithoutVerifierLeavesVerificationPending: with no verifier wired the behaviour is unchanged —
// the effect is simply not verified (Pending), never a false claim of success.
func TestApplyWithoutVerifierLeavesVerificationPending(t *testing.T) {
	h := newHarness(t)
	rec, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), "alice")
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if rec.Verification != VerificationPending {
		t.Fatalf("no verifier ⇒ verification pending, got %q", rec.Verification)
	}
}
