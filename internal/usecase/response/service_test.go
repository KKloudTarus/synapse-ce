package response

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
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
	mu            sync.Mutex
	calls         []string // proposed action ids admitted, in order
	err           error    // when set, Admit refuses (nothing must execute)
	reauthErr     error
	started       chan struct{}
	release       chan struct{}
	reauthStarted chan struct{}
	reauthRelease chan struct{}
	decidedBy     string
}

func (f *fakeAdmitter) Admit(_ context.Context, p agent.ProposedAction, _ string) (admission, error) {
	f.mu.Lock()
	f.calls = append(f.calls, p.ID.String())
	started, release, err := f.started, f.release, f.err
	f.mu.Unlock()
	if started != nil {
		close(started)
	}
	if release != nil {
		<-release
	}
	decidedBy := f.decidedBy
	if decidedBy == "" {
		decidedBy = "human-reviewer"
	}
	return admission{action: p, decidedBy: decidedBy, evidenceID: "evidence-1"}, err
}

func (f *fakeAdmitter) Reauthorize(ctx context.Context, _ admission) error {
	f.mu.Lock()
	started, release, err := f.reauthStarted, f.reauthRelease, f.reauthErr
	f.mu.Unlock()
	if started != nil {
		close(started)
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return err
}

type fakeExec struct {
	mu             sync.Mutex
	runs           []ExecRequest
	observed       offensivepolicy.Radius
	affected       int
	already        bool
	before         func(ExecRequest)
	err            error
	haltErr        error
	haltCalls      int
	haltGeneration map[shared.ID]int64
	wrongFence     bool
	supported      *bool
}

type blockingExec struct {
	started        chan struct{}
	release        chan struct{}
	runs           int
	effects        int
	mu             sync.Mutex
	haltGeneration map[shared.ID]int64
	halt           chan struct{}
	activeDone     chan struct{}
}

type blockingVerifier struct {
	started chan struct{}
}

func (*blockingVerifier) Identity() string { return "agent:response-verifier" }

func (v *blockingVerifier) Verify(ctx context.Context, _ VerificationRequest) (VerificationReceipt, error) {
	close(v.started)
	<-ctx.Done()
	return VerificationReceipt{Outcome: VerificationUnknown, EvidenceID: "verification-evidence-1"}, ctx.Err()
}

func (*blockingExec) Identity() string        { return "agent:response-executor" }
func (*blockingExec) Supports(rdom.Kind) bool { return true }
func (*blockingExec) ResolveAgent(context.Context, shared.ID, responsesaga.TargetFingerprint) (shared.ID, error) {
	return "response-executor", nil
}

func (e *blockingExec) Execute(ctx context.Context, req ExecRequest) (ExecOutcome, error) {
	e.mu.Lock()
	if req.HaltGeneration < e.haltGeneration[req.TenantID] {
		e.mu.Unlock()
		return ExecOutcome{}, responsesaga.ErrStaleHaltGeneration
	}
	e.runs++
	if e.runs == 1 {
		close(e.started)
	}
	e.halt = make(chan struct{})
	e.activeDone = make(chan struct{})
	halt, done := e.halt, e.activeDone
	e.mu.Unlock()
	defer close(done)
	select {
	case <-ctx.Done():
		return ExecOutcome{}, ctx.Err()
	case <-halt:
		return ExecOutcome{}, responsesaga.ErrStaleHaltGeneration
	case <-e.release:
		e.mu.Lock()
		e.effects++
		e.mu.Unlock()
		return ExecOutcome{
			ObservedRadius: offensivepolicy.RadiusStateChanging, AffectedCount: 1,
			EnforcedHaltGeneration: req.HaltGeneration,
		}, nil
	}
}

func (e *blockingExec) Halt(ctx context.Context, tenantID shared.ID, generation int64) error {
	e.mu.Lock()
	if e.haltGeneration == nil {
		e.haltGeneration = make(map[shared.ID]int64)
	}
	if generation > e.haltGeneration[tenantID] {
		e.haltGeneration[tenantID] = generation
	}
	halt, done := e.halt, e.activeDone
	if halt != nil {
		close(halt)
		e.halt = nil
	}
	e.mu.Unlock()
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *blockingExec) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.runs
}

func (e *blockingExec) effectCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.effects
}

func (e *fakeExec) Execute(_ context.Context, req ExecRequest) (ExecOutcome, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if req.HaltGeneration < e.haltGeneration[req.TenantID] {
		return ExecOutcome{}, responsesaga.ErrStaleHaltGeneration
	}
	if e.before != nil {
		e.before(req)
	}
	e.runs = append(e.runs, req)
	if e.err != nil {
		return ExecOutcome{}, e.err
	}
	obs := req.Declared
	if e.observed != "" {
		obs = e.observed
	}
	affected := 1
	if e.affected != 0 {
		affected = e.affected
	}
	enforced := req.HaltGeneration
	if e.wrongFence {
		enforced++
	}
	return ExecOutcome{
		ObservedRadius: obs, AffectedCount: affected, AlreadyApplied: e.already,
		EnforcedHaltGeneration: enforced,
	}, nil
}
func (*fakeExec) Identity() string { return "agent:response-executor" }
func (e *fakeExec) Supports(rdom.Kind) bool {
	return e.supported == nil || *e.supported
}
func (*fakeExec) ResolveAgent(context.Context, shared.ID, responsesaga.TargetFingerprint) (shared.ID, error) {
	return "response-executor", nil
}
func (e *fakeExec) Halt(_ context.Context, tenantID shared.ID, generation int64) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.haltCalls++
	if e.haltGeneration == nil {
		e.haltGeneration = make(map[shared.ID]int64)
	}
	if generation > e.haltGeneration[tenantID] {
		e.haltGeneration[tenantID] = generation
	}
	return e.haltErr
}
func (e *fakeExec) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.runs)
}

type fakeAudit struct {
	mu      sync.Mutex
	actions []string
	fail    string
	once    map[string]ports.AuditEntry
}

func (a *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if e.Action == a.fail {
		return errors.New("audit unavailable")
	}
	a.actions = append(a.actions, e.Action)
	return nil
}
func (a *fakeAudit) RecordOnce(ctx context.Context, e ports.AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if e.Action == a.fail {
		return errors.New("audit unavailable")
	}
	key := e.Metadata["idempotency_key"]
	if key == "" {
		return errors.New("idempotent audit entry has no idempotency key")
	}
	if a.once == nil {
		a.once = make(map[string]ports.AuditEntry)
	}
	if existing, ok := a.once[key]; ok {
		if !reflect.DeepEqual(existing, e) {
			return errors.New("idempotency key reused for a different audit entry")
		}
		return nil
	}
	a.once[key] = e
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

type fakeReceiptValidator struct {
	err   error
	calls int
	reqs  []VerificationRequest
}

type fakeApprovalDecider struct {
	proposal  agent.ProposedAction
	decision  agent.ApprovalDecision
	getErr    error
	decideErr error
	calls     int
	reviewer  string
	approve   bool
	reason    string
}

func (f *fakeApprovalDecider) Get(context.Context, shared.ID) (agent.ProposedAction, agent.ApprovalDecision, error) {
	return f.proposal, f.decision, f.getErr
}

func (f *fakeApprovalDecider) Decide(_ context.Context, reviewer string, actionID shared.ID, approve bool, reason string) (agent.ApprovalDecision, error) {
	f.calls++
	f.reviewer, f.approve, f.reason = reviewer, approve, reason
	if f.decideErr != nil {
		return agent.ApprovalDecision{}, f.decideErr
	}
	state := agent.ApprovalDenied
	if approve {
		state = agent.ApprovalApproved
	}
	f.decision = agent.ApprovalDecision{ActionID: actionID, State: state, DecidedBy: reviewer, Reason: reason, DecidedAt: time.Unix(1000, 0)}
	return f.decision, nil
}

func (v *fakeReceiptValidator) Validate(_ context.Context, req VerificationRequest, _ VerificationReceipt, _ string) error {
	v.calls++
	v.reqs = append(v.reqs, req)
	return v.err
}

type harness struct {
	svc   *Service
	admit *fakeAdmitter
	exec  *fakeExec
	audit *fakeAudit
	store ports.ResponseAuditStore
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	admit := &fakeAdmitter{}
	exec := &fakeExec{}
	audit := &fakeAudit{}
	store := memory.NewResponseStore()
	svc, err := newService(admit, exec, store, audit, fixedClock{t: time.Unix(1000, 0)})
	if err != nil {
		t.Fatal(err)
	}
	svc.receipts = &fakeReceiptValidator{}
	return &harness{svc: svc, admit: admit, exec: exec, audit: audit, store: store}
}

func tctx() context.Context { return shared.WithTenant(context.Background(), "t1") }

func act(id string) rdom.Action {
	sp, _ := rdom.SpecFor(rdom.KindIsolateHost)
	return rdom.Action{ID: shared.ID(id), Kind: rdom.KindIsolateHost, Target: "host-1", BlastRadius: sp.Radius, Reversibility: sp.Reversibility,
		Argv: []string{"synapse-agent-response", "isolate-host", "host-1"}, Reversal: sp.Reversal}
}

// target matches the action's Target ("host-1") — Apply binds the admitted scope target to the executed
// action target, so they must be the same asset.
func target() engagement.Target {
	return engagement.Target{Kind: engagement.TargetIP, Value: "host-1"}
}

func fingerprint() responsesaga.TargetFingerprint {
	return responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintHost, HostID: "host-1", NetpolGeneration: 1}
}

func pendingApprovalRecord(action rdom.Action, submitter string) (Record, agent.ProposedAction) {
	authorizationTarget := engagement.Target{Kind: engagement.TargetDomain, Value: action.Target.String()}
	rec := Record{
		ID: action.ID, TenantID: "t1", EngagementID: "eng-1", Action: action,
		AuthorizationTarget: authorizationTarget, TargetFingerprint: fingerprint(),
		SubmittedBy: submitter, State: StatePending, ApprovedBy: submitter, UpdatedAt: time.Unix(1000, 0),
	}
	proposal := agent.ProposedAction{
		ID: action.ID, SessionID: shared.ID("response:" + action.ID.String()), EngagementID: rec.EngagementID,
		Tool: "response." + string(action.Kind), Action: "response." + string(action.Kind),
		Target: authorizationTarget, Argv: action.Argv, Risk: agent.RiskIntrusive,
		Rationale: "defensive response: " + string(action.Kind), ProposedAt: time.Unix(1000, 0),
	}
	return rec, proposal
}

// ---- tests ------------------------------------------------------------------------------------------

func TestDecideApprovalResumesExactPendingAction(t *testing.T) {
	h := newHarness(t)
	pending, proposal := pendingApprovalRecord(act("a1"), "alice")
	if err := h.store.Put(tctx(), pending); err != nil {
		t.Fatal(err)
	}
	approvals := &fakeApprovalDecider{
		proposal: proposal,
		decision: agent.ApprovalDecision{ActionID: pending.ID, State: agent.ApprovalPending},
	}
	h.svc.SetApprovalDecider(approvals)
	h.admit.decidedBy = "bob"
	rec, err := h.svc.Decide(tctx(), pending.ID, "bob", true, "scope confirmed")
	if err != nil {
		t.Fatal(err)
	}
	if approvals.calls != 1 || approvals.reviewer != "bob" || !approvals.approve || approvals.reason != "scope confirmed" {
		t.Fatalf("approval call = calls=%d reviewer=%q approve=%v reason=%q", approvals.calls, approvals.reviewer, approvals.approve, approvals.reason)
	}
	if rec.ID != pending.ID || rec.State != StateApplied || rec.ApprovedBy != "bob" || h.exec.count() != 1 {
		t.Fatalf("resumed record=%+v executions=%d", rec, h.exec.count())
	}
	run := h.exec.runs[0]
	if run.ActionID != pending.ID || run.AuthorizationTarget != pending.AuthorizationTarget || run.Fingerprint != pending.TargetFingerprint {
		t.Fatalf("execution was not bound to persisted input: %+v", run)
	}
}

func TestDecideApprovalRejectsSubmitterAndMismatchedProposal(t *testing.T) {
	for _, tc := range []struct {
		name     string
		reviewer string
		mutate   func(*agent.ProposedAction)
		want     error
	}{
		{name: "same submitter", reviewer: "alice", want: shared.ErrForbidden},
		{name: "altered proposal", reviewer: "bob", mutate: func(p *agent.ProposedAction) { p.Argv = []string{"changed"} }, want: shared.ErrForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			pending, proposal := pendingApprovalRecord(act("a1"), "alice")
			if tc.mutate != nil {
				tc.mutate(&proposal)
			}
			if err := h.store.Put(tctx(), pending); err != nil {
				t.Fatal(err)
			}
			approvals := &fakeApprovalDecider{proposal: proposal, decision: agent.ApprovalDecision{ActionID: pending.ID, State: agent.ApprovalPending}}
			h.svc.SetApprovalDecider(approvals)
			if _, err := h.svc.Decide(tctx(), pending.ID, tc.reviewer, true, "reviewed"); !errors.Is(err, tc.want) {
				t.Fatalf("Decide() error = %v, want %v", err, tc.want)
			}
			if approvals.calls != 0 || h.exec.count() != 0 {
				t.Fatalf("refused decision reached approval/execution: decisions=%d executions=%d", approvals.calls, h.exec.count())
			}
		})
	}
}

func TestDecideDenialCancelsPendingAction(t *testing.T) {
	h := newHarness(t)
	pending, proposal := pendingApprovalRecord(act("a1"), "alice")
	if err := h.store.Put(tctx(), pending); err != nil {
		t.Fatal(err)
	}
	approvals := &fakeApprovalDecider{proposal: proposal, decision: agent.ApprovalDecision{ActionID: pending.ID, State: agent.ApprovalPending}}
	h.svc.SetApprovalDecider(approvals)
	rec, err := h.svc.Decide(tctx(), pending.ID, "bob", false, "target not authorized")
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != StateCancelled || rec.ApprovedBy != "bob" || h.exec.count() != 0 {
		t.Fatalf("denied record=%+v executions=%d", rec, h.exec.count())
	}
	if !h.audit.has("response.approval_denied") {
		t.Fatal("denial must be delivered to the response audit chain")
	}
}

func TestDecideApprovalResumesExactPendingReversal(t *testing.T) {
	h := newHarness(t)
	h.svc.verify = &fakeVerifier{outcome: VerificationSucceeded}
	authorizationTarget := engagement.Target{Kind: engagement.TargetDomain, Value: "host-1"}
	applied, err := h.svc.Apply(tctx(), "eng-1", act("a1"), authorizationTarget, fingerprint(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	h.admit.err = safety.ErrPendingApproval
	pending, err := h.svc.Revert(tctx(), applied.ID, authorizationTarget, fingerprint(), "carol")
	if !errors.Is(err, safety.ErrPendingApproval) {
		t.Fatalf("Revert() error = %v, want pending approval", err)
	}
	if pending.State != StateApplied || pending.ReversalRequestedBy != "carol" {
		t.Fatalf("pending reversal was not persisted: %+v", pending)
	}
	reversalID := shared.ID("revert:" + applied.ID.String())
	proposal := agent.ProposedAction{
		ID: reversalID, SessionID: shared.ID("response:" + applied.ID.String()), EngagementID: applied.EngagementID,
		Tool: "response." + string(applied.Action.Reversal.Kind), Action: "response." + string(applied.Action.Reversal.Kind),
		Target: authorizationTarget, Argv: applied.Action.Reversal.Argv, Risk: agent.RiskIntrusive,
		Rationale: "reverse response: " + applied.Action.Reversal.Description, ProposedAt: time.Unix(1000, 0),
	}
	approvals := &fakeApprovalDecider{proposal: proposal, decision: agent.ApprovalDecision{ActionID: reversalID, State: agent.ApprovalPending}}
	h.svc.SetApprovalDecider(approvals)
	h.admit.err = nil
	h.admit.decidedBy = "bob"
	if _, err := h.svc.Decide(tctx(), applied.ID, "carol", true, "self approval"); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("reversal submitter approval error = %v, want forbidden", err)
	}
	reverted, err := h.svc.Decide(tctx(), applied.ID, "bob", true, "rollback checked")
	if err != nil {
		t.Fatal(err)
	}
	if approvals.decision.ActionID != reversalID || reverted.State != StateReverted || h.exec.count() != 2 {
		t.Fatalf("reversal decision=%+v record=%+v executions=%d", approvals.decision, reverted, h.exec.count())
	}
	if run := h.exec.runs[1]; !run.IsReversal || run.ActionID != applied.ID || run.AuthorizationTarget != authorizationTarget || run.Fingerprint != fingerprint() {
		t.Fatalf("reversal was not bound to persisted input: %+v", run)
	}
}

func TestDecideReversalDenialKeepsAppliedAction(t *testing.T) {
	h := newHarness(t)
	h.svc.verify = &fakeVerifier{outcome: VerificationSucceeded}
	authorizationTarget := engagement.Target{Kind: engagement.TargetDomain, Value: "host-1"}
	applied, err := h.svc.Apply(tctx(), "eng-1", act("a1"), authorizationTarget, fingerprint(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	h.admit.err = safety.ErrPendingApproval
	if _, err := h.svc.Revert(tctx(), applied.ID, authorizationTarget, fingerprint(), "carol"); !errors.Is(err, safety.ErrPendingApproval) {
		t.Fatalf("Revert() error = %v, want pending approval", err)
	}
	reversalID := shared.ID("revert:" + applied.ID.String())
	proposal := agent.ProposedAction{
		ID: reversalID, SessionID: shared.ID("response:" + applied.ID.String()), EngagementID: applied.EngagementID,
		Tool: "response." + string(applied.Action.Reversal.Kind), Action: "response." + string(applied.Action.Reversal.Kind),
		Target: authorizationTarget, Argv: applied.Action.Reversal.Argv, Risk: agent.RiskIntrusive,
		Rationale: "reverse response: " + applied.Action.Reversal.Description, ProposedAt: time.Unix(1000, 0),
	}
	approvals := &fakeApprovalDecider{proposal: proposal, decision: agent.ApprovalDecision{ActionID: reversalID, State: agent.ApprovalPending}}
	h.svc.SetApprovalDecider(approvals)
	rec, err := h.svc.Decide(tctx(), applied.ID, "bob", false, "rollback not justified")
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != StateApplied || h.exec.count() != 1 {
		t.Fatalf("denied reversal changed the applied effect: record=%+v executions=%d", rec, h.exec.count())
	}
}

// TestApplyRoutesThroughAdmissionBeforeExecuting is the #425 admission-bypass guarantee: nothing executes
// unless the gate admitted it. When admission refuses, the executor is never called.
func TestApplyRejectsUnsupportedExecutorKindBeforeAdmissionOrPersistence(t *testing.T) {
	h := newHarness(t)
	supported := false
	h.exec.supported = &supported

	action := act("a1")
	if _, err := h.svc.PrepareIncidentResponse(tctx(), "eng-1", action, target(), fingerprint(), "alice"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unsupported preparation error = %v, want validation", err)
	}
	_, err := h.svc.Apply(tctx(), "eng-1", action, target(), fingerprint(), "alice")
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unsupported executor kind error = %v, want validation", err)
	}
	if len(h.admit.calls) != 0 || h.exec.count() != 0 {
		t.Fatalf("unsupported action crossed admission/execution: admissions=%d executions=%d", len(h.admit.calls), h.exec.count())
	}
	if _, found, getErr := h.store.Get(tctx(), "a1"); getErr != nil || found {
		t.Fatalf("unsupported action persisted: found=%t err=%v", found, getErr)
	}
}

func TestApplyRoutesThroughAdmissionBeforeExecuting(t *testing.T) {
	h := newHarness(t)
	h.admit.err = shared.ErrForbidden // gate refuses
	_, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice")
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
		if _, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), who); !errors.Is(err, shared.ErrForbidden) {
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
	h.exec.before = func(req ExecRequest) {
		attempt, found, err := h.store.GetAttempt(tctx(), req.IdempotencyKey)
		if err != nil || !found {
			t.Fatalf("attempt must be durable before executor starts: found=%v err=%v", found, err)
		}
		if attempt.State != responsesaga.StateExecuting || attempt.Target != fingerprint() {
			t.Fatalf("executor observed invalid pre-side-effect journal: %+v", attempt)
		}
		if !h.audit.has("response.execution_intent") {
			t.Fatal("idempotent audit intent must be durable before executor starts")
		}
	}
	rec, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice")
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
	run := h.exec.runs[0]
	attempt, found, err := h.store.GetAttempt(tctx(), run.IdempotencyKey)
	if err != nil || !found || attempt.State != responsesaga.StateCommandApplied {
		t.Fatalf("command outcome must be durable after execution: attempt=%+v found=%v err=%v", attempt, found, err)
	}
	if !validVerificationChallenge(attempt.VerificationChallenge) {
		t.Fatalf("command outcome must carry a post-command verification challenge: %+v", attempt)
	}
}

func TestApplyPersistsConfiguredAttemptDeadline(t *testing.T) {
	h := newHarness(t)
	if err := h.svc.SetVerificationTimeout(45 * time.Second); err != nil {
		t.Fatal(err)
	}
	if err := h.svc.SetVerificationTimeout(0); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("nonpositive verification timeout error=%v, want validation", err)
	}
	if _, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice"); err != nil {
		t.Fatal(err)
	}
	attempt, found, err := h.store.GetAttempt(tctx(), responseAttemptKey(act("a1"), false))
	if err != nil || !found {
		t.Fatalf("load bounded attempt: found=%v err=%v", found, err)
	}
	want := time.Unix(1045, 0).UTC()
	if !attempt.DeadlineAt.Equal(want) {
		t.Fatalf("attempt deadline=%s, want %s", attempt.DeadlineAt, want)
	}
}

func TestReconcileExpiredAttemptsConvergeWithoutReexecution(t *testing.T) {
	tests := []struct {
		name             string
		state            responsesaga.SagaState
		reversal         bool
		wantAttemptState responsesaga.SagaState
		wantRecordState  State
		wantVerification Verification
	}{
		{name: "issued", state: responsesaga.StateIssued, wantAttemptState: responsesaga.StateCommandFailed, wantRecordState: StateCancelled},
		{name: "claimed", state: responsesaga.StateClaimed, wantAttemptState: responsesaga.StateManualIntervention, wantRecordState: StateViolation, wantVerification: VerificationUnknown},
		{name: "executing", state: responsesaga.StateExecuting, wantAttemptState: responsesaga.StateManualIntervention, wantRecordState: StateViolation, wantVerification: VerificationUnknown},
		{name: "command applied", state: responsesaga.StateCommandApplied, wantAttemptState: responsesaga.StateTimedOut, wantRecordState: StateApplied, wantVerification: VerificationUnknown},
		{name: "outcome unknown", state: responsesaga.StateOutcomeUnknown, wantAttemptState: responsesaga.StateManualIntervention, wantRecordState: StateViolation, wantVerification: VerificationUnknown},
		{name: "verifying", state: responsesaga.StateVerifying, wantAttemptState: responsesaga.StateTimedOut, wantRecordState: StateApplied, wantVerification: VerificationUnknown},
		{name: "governed rollback not started", state: responsesaga.StateRollbackRequested, wantAttemptState: responsesaga.StateManualIntervention, wantRecordState: StateViolation, wantVerification: VerificationUnknown},
		{name: "reversal requested", state: responsesaga.StateRollbackRequested, reversal: true, wantAttemptState: responsesaga.StateRollbackFailed, wantRecordState: StateViolation},
		{name: "reversal executing", state: responsesaga.StateRollingBack, reversal: true, wantAttemptState: responsesaga.StateRollbackFailed, wantRecordState: StateViolation},
		{name: "reversal outcome unknown", state: responsesaga.StateRollbackUnknown, reversal: true, wantAttemptState: responsesaga.StateRollbackFailed, wantRecordState: StateViolation},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			attempt := seedAttemptState(t, h, tc.state, tc.reversal)
			h.svc.clock = fixedClock{t: attempt.DeadlineAt.Add(time.Second)}
			if err := h.svc.ReconcileVerifications(tctx()); err != nil {
				t.Fatalf("reconcile expired attempt: %v", err)
			}
			stored, found, err := h.store.GetAttempt(tctx(), attempt.IdempotencyKey)
			if err != nil || !found {
				t.Fatalf("load terminal attempt: found=%v err=%v", found, err)
			}
			if stored.State != tc.wantAttemptState || stored.TerminalReason == "" || !stored.DeadlineAt.Equal(attempt.DeadlineAt) {
				t.Fatalf("terminal attempt=%+v, want state=%s with unchanged deadline and reason", stored, tc.wantAttemptState)
			}
			rec, found, err := h.store.Get(tctx(), attempt.ActionID)
			if err != nil || !found || rec.State != tc.wantRecordState || rec.Verification != tc.wantVerification {
				t.Fatalf("terminal response=%+v found=%v err=%v, want state=%s verification=%s", rec, found, err, tc.wantRecordState, tc.wantVerification)
			}
			if h.exec.count() != 0 {
				t.Fatalf("expired ambiguous attempt was reexecuted %d time(s)", h.exec.count())
			}
			if !h.audit.has("response.attempt_terminal") {
				t.Fatal("terminal transition was not audited")
			}
		})
	}
}

func TestApplyRetryCannotClaimExpiredIssuedAttempt(t *testing.T) {
	h := newHarness(t)
	attempt := seedAttemptState(t, h, responsesaga.StateIssued, false)
	h.admit.decidedBy = attempt.DecidedBy
	h.svc.clock = fixedClock{t: attempt.DeadlineAt.Add(time.Second)}
	rec, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), attempt.DecidedBy)
	if !errors.Is(err, ErrAttemptDeadlineExceeded) {
		t.Fatalf("expired apply retry error=%v, want deadline exceeded", err)
	}
	if rec.State != StateCancelled || h.exec.count() != 0 {
		t.Fatalf("expired apply retry record=%+v executions=%d", rec, h.exec.count())
	}
}

func TestRevertRetryCannotClaimExpiredAttempt(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice"); err != nil {
		t.Fatal(err)
	}
	h.svc.verify = &fakeVerifier{outcome: VerificationSucceeded}
	attempt := h.svc.newAttempt(act("a1"), fingerprint(), true, responsesaga.StateRollbackRequested, 0, "bob", time.Unix(1000, 0).UTC())
	attempt.ExecutorID = h.exec.Identity()
	attempt.ExecutorAgentID = "response-executor"
	if err := setVerificationChallenge(&attempt); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.store.StartAttempt(tctx(), attempt); err != nil {
		t.Fatal(err)
	}
	h.svc.clock = fixedClock{t: attempt.DeadlineAt.Add(time.Second)}
	rec, err := h.svc.Revert(tctx(), "a1", target(), fingerprint(), "bob")
	if !errors.Is(err, ErrAttemptDeadlineExceeded) {
		t.Fatalf("expired reversal retry error=%v, want deadline exceeded", err)
	}
	if rec.State != StateViolation || h.exec.count() != 1 {
		t.Fatalf("expired reversal retry record=%+v executions=%d", rec, h.exec.count())
	}
}

func TestReconcileDoesNotResurrectRevertedResponse(t *testing.T) {
	h := newHarness(t)
	h.svc.verify = &fakeVerifier{outcome: VerificationSucceeded}
	if _, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Revert(tctx(), "a1", target(), fingerprint(), "alice"); err != nil {
		t.Fatal(err)
	}
	if err := h.svc.ReconcileVerifications(tctx()); err != nil {
		t.Fatal(err)
	}
	rec, found, err := h.store.Get(tctx(), "a1")
	if err != nil || !found || rec.State != StateReverted || h.exec.count() != 2 {
		t.Fatalf("reconciled reverted response=%+v found=%v err=%v executions=%d", rec, found, err, h.exec.count())
	}
}

func TestReconcileReportsOperationalVerifierFailure(t *testing.T) {
	h := newHarness(t)
	want := errors.New("telemetry store unavailable")
	h.svc.verify = &fakeVerifier{outcome: VerificationPending, err: want}
	if _, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice"); !errors.Is(err, ErrVerificationPending) {
		t.Fatalf("initial pending verification error=%v", err)
	}
	if err := h.svc.ReconcileVerifications(tctx()); !errors.Is(err, want) {
		t.Fatalf("reconciliation error=%v, want operational verifier failure", err)
	}
}

func seedAttemptState(t *testing.T, h *harness, state responsesaga.SagaState, reversal bool) responsesaga.ResponseAttempt {
	t.Helper()
	action := act("a1")
	recordState := StatePending
	if reversal {
		recordState = StateApplied
	}
	rec := h.svc.record("t1", "eng-1", action, target(), fingerprint(), "alice", recordState, "bob", "approval-evidence")
	if err := h.store.Put(tctx(), rec); err != nil {
		t.Fatal(err)
	}
	initial := responsesaga.StateIssued
	if reversal {
		initial = responsesaga.StateRollbackRequested
	}
	attempt := h.svc.newAttempt(action, fingerprint(), reversal, initial, 0, "bob", time.Unix(1000, 0).UTC())
	attempt.ExecutorID = h.exec.Identity()
	attempt.ExecutorAgentID = "response-executor"
	if err := setVerificationChallenge(&attempt); err != nil {
		t.Fatal(err)
	}
	stored, _, err := h.store.StartAttempt(tctx(), attempt)
	if err != nil {
		t.Fatal(err)
	}
	attempt = stored
	if reversal {
		if state == responsesaga.StateRollbackRequested {
			return attempt
		}
		attempt, _, err = h.store.ClaimAttempt(tctx(), attempt.IdempotencyKey, responsesaga.StateRollbackRequested, responsesaga.StateRollingBack, time.Unix(1000, 0).UTC())
		if err != nil {
			t.Fatal(err)
		}
		if state == responsesaga.StateRollingBack {
			return attempt
		}
		attempt.CommandOutcome = "rollback_acknowledgement_lost"
		attempt, err = h.svc.transitionAttempt(tctx(), attempt, responsesaga.StateRollingBack, responsesaga.StateRollbackUnknown)
		if err != nil {
			t.Fatal(err)
		}
		return attempt
	}
	if state == responsesaga.StateIssued {
		return attempt
	}
	if state == responsesaga.StateClaimed {
		attempt, _, err = h.store.ClaimAttempt(tctx(), attempt.IdempotencyKey, responsesaga.StateIssued, responsesaga.StateClaimed, time.Unix(1000, 0).UTC())
		if err != nil {
			t.Fatal(err)
		}
		return attempt
	}
	attempt, _, err = h.store.ClaimAttempt(tctx(), attempt.IdempotencyKey, responsesaga.StateIssued, responsesaga.StateExecuting, time.Unix(1000, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if state == responsesaga.StateExecuting {
		return attempt
	}
	if state == responsesaga.StateOutcomeUnknown || state == responsesaga.StateRollbackRequested {
		attempt.CommandOutcome = "executor_acknowledgement_lost"
		attempt, err = h.svc.transitionAttempt(tctx(), attempt, responsesaga.StateExecuting, responsesaga.StateOutcomeUnknown)
		if err != nil {
			t.Fatal(err)
		}
		if state == responsesaga.StateRollbackRequested {
			attempt.VerificationOutcome = responsesaga.VerificationSucceeded
			attempt, err = h.svc.transitionAttempt(tctx(), attempt, responsesaga.StateOutcomeUnknown, responsesaga.StateRollbackRequested)
			if err != nil {
				t.Fatal(err)
			}
		}
		return attempt
	}
	attempt.CommandOutcome = "applied"
	attempt.ObservedRadius = offensivepolicy.RadiusStateChanging
	attempt.AffectedCount = 1
	attempt, err = h.svc.transitionAttempt(tctx(), attempt, responsesaga.StateExecuting, responsesaga.StateCommandApplied)
	if err != nil {
		t.Fatal(err)
	}
	if state == responsesaga.StateCommandApplied {
		return attempt
	}
	attempt, err = h.svc.transitionAttempt(tctx(), attempt, responsesaga.StateCommandApplied, responsesaga.StateVerifying)
	if err != nil {
		t.Fatal(err)
	}
	return attempt
}

func TestApplyRejectsExecutorWithoutExactHaltFenceAcknowledgement(t *testing.T) {
	h := newHarness(t)
	h.exec.wrongFence = true
	if _, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice"); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("unfenced executor outcome must fail closed, got %v", err)
	}
	attempt, found, err := h.store.GetAttempt(tctx(), newAttempt(act("a1"), fingerprint(), false, responsesaga.StateIssued, 0, "", time.Time{}).IdempotencyKey)
	if err != nil || !found || attempt.State != responsesaga.StateOutcomeUnknown {
		t.Fatalf("unfenced executor attempt = %+v found=%v err=%v", attempt, found, err)
	}
	if !validVerificationChallenge(attempt.VerificationChallenge) {
		t.Fatal("ambiguous command outcome must retain a post-command verification challenge")
	}
}

type failingAttemptStore struct {
	ports.ResponseAuditStore
	err error
}

func (s failingAttemptStore) StartAttempt(context.Context, responsesaga.ResponseAttempt) (responsesaga.ResponseAttempt, bool, error) {
	return responsesaga.ResponseAttempt{}, false, s.err
}

func TestApplyFailsClosedBeforeExecutionWhenJournalOrAuditFails(t *testing.T) {
	t.Run("journal", func(t *testing.T) {
		h := newHarness(t)
		store := failingAttemptStore{ResponseAuditStore: h.store, err: errors.New("journal unavailable")}
		svc, err := newService(h.admit, h.exec, store, h.audit, fixedClock{t: time.Unix(1000, 0)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice"); err == nil {
			t.Fatal("journal failure must fail the operation")
		}
		if h.exec.count() != 0 {
			t.Fatal("journal failure must prevent the side effect")
		}
	})

	t.Run("audit_intent", func(t *testing.T) {
		h := newHarness(t)
		h.audit.fail = "response.execution_intent"
		if _, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice"); err == nil {
			t.Fatal("audit intent failure must fail the operation")
		}
		if h.exec.count() != 0 {
			t.Fatal("audit intent failure must prevent the side effect")
		}
	})
}

func TestApplyRecoversCommittedAttemptWithoutReexecuting(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice"); err != nil {
		t.Fatal(err)
	}
	rec, found, err := h.store.Get(tctx(), "a1")
	if err != nil || !found {
		t.Fatalf("get applied record: found=%v err=%v", found, err)
	}
	// Simulate a crash window where the command-attempt commit survived but the action projection did not.
	rec.State = StatePending
	rec.AppliedAt = time.Time{}
	if transitioned, err := h.store.Transition(tctx(), rec, StateApplied); err != nil || !transitioned {
		t.Fatalf("simulate stale pending projection: transitioned=%v err=%v", transitioned, err)
	}
	got, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice")
	if err != nil {
		t.Fatalf("recover committed attempt: %v", err)
	}
	if got.State != StateApplied || h.exec.count() != 1 {
		t.Fatalf("recovery must repair projection without reexecution: state=%s executions=%d", got.State, h.exec.count())
	}
	if !h.audit.has("response.applied") {
		t.Fatal("recovered projection must reconcile the durable outcome audit")
	}
}

func TestApplyRejectsUnjournaledAppliedRecord(t *testing.T) {
	h := newHarness(t)
	action := act("a1")
	legacy := Record{
		ID: action.ID, TenantID: "t1", EngagementID: "eng-1", Action: action,
		State: StateApplied, ApprovedBy: "alice", UpdatedAt: time.Unix(900, 0).UTC(),
	}
	if err := h.store.Put(tctx(), legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Apply(tctx(), "eng-1", action, target(), fingerprint(), "alice"); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("unjournaled applied record must not be trusted, got %v", err)
	}
	if h.exec.count() != 0 {
		t.Fatal("unjournaled applied record was executed again")
	}
}

func TestApplySurfacesAndReconcilesPostEffectAuditFailure(t *testing.T) {
	h := newHarness(t)
	h.audit.fail = "response.applied"
	if _, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice"); err == nil {
		t.Fatal("post-effect audit failure must be returned to the caller")
	}
	if h.exec.count() != 1 {
		t.Fatalf("initial command executions=%d, want 1", h.exec.count())
	}
	h.audit.fail = ""
	rec, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice")
	if err != nil {
		t.Fatalf("retry must reconcile committed command and audit: %v", err)
	}
	if rec.State != StateApplied || h.exec.count() != 1 || !h.audit.has("response.applied") {
		t.Fatalf("reconciliation state=%s executions=%d audit=%v", rec.State, h.exec.count(), h.audit.actions)
	}
}

func TestVerifiedOutcomeCommitsAuditIntentBeforeDelivery(t *testing.T) {
	h := newHarness(t)
	h.svc.verify = &fakeVerifier{outcome: VerificationSucceeded}
	h.audit.fail = "response.verified"
	if _, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice"); err == nil {
		t.Fatal("verification audit delivery failure must be returned")
	}
	attempt, found, err := h.store.GetAttempt(tctx(), responseAttemptKey(act("a1"), false))
	if err != nil || !found || attempt.State != responsesaga.StateVerifiedSucceeded {
		t.Fatalf("verified attempt was not committed before audit delivery: attempt=%+v found=%v err=%v", attempt, found, err)
	}
	pending, err := h.store.ListPendingResponseAudits(tctx())
	if err != nil || len(pending) == 0 {
		t.Fatalf("verification audit obligation was not durable: pending=%+v err=%v", pending, err)
	}
	h.audit.fail = ""
	if err := h.svc.ReconcilePending(tctx()); err != nil {
		t.Fatalf("reconcile verification audit: %v", err)
	}
	if !h.audit.has("response.verified") {
		t.Fatal("reconciler did not deliver the committed verification audit")
	}
}

func TestConcurrentApplyHasSingleExecutionClaim(t *testing.T) {
	h := newHarness(t)
	exec := &blockingExec{started: make(chan struct{}), release: make(chan struct{})}
	svc, err := newService(h.admit, exec, h.store, h.audit, fixedClock{t: time.Unix(1000, 0)})
	if err != nil {
		t.Fatal(err)
	}
	firstDone := make(chan error, 1)
	go func() {
		_, err := svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice")
		firstDone <- err
	}()
	<-exec.started
	if _, err := svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice"); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("a concurrent redelivery must not receive an execution claim, got %v", err)
	}
	close(exec.release)
	if err := <-firstDone; err != nil {
		t.Fatalf("claimed execution failed: %v", err)
	}
	if exec.count() != 1 {
		t.Fatalf("concurrent delivery executed %d times, want exactly one", exec.count())
	}
}

func TestHaltCancelsRegisteredInFlightExecution(t *testing.T) {
	h := newHarness(t)
	exec := &blockingExec{started: make(chan struct{}), release: make(chan struct{})}
	svc, err := newService(h.admit, exec, h.store, h.audit, fixedClock{t: time.Unix(1000, 0)})
	if err != nil {
		t.Fatal(err)
	}
	applyDone := make(chan error, 1)
	go func() {
		_, err := svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice")
		applyDone <- err
	}()
	<-exec.started
	halted, err := svc.HaltResponses(tctx(), "t1", "operator@example.test", "kill switch")
	if !errors.Is(err, shared.ErrSaturated) {
		t.Fatalf("an executing command cannot be reported as cleanly halted, got %v", err)
	}
	if halted != 1 {
		t.Fatalf("halted=%d, want 1", halted)
	}
	if err := <-applyDone; err == nil {
		t.Fatal("the cancelled executor must not report apply success")
	}
	rec, found, err := h.store.Get(tctx(), "a1")
	if err != nil || !found || rec.State != StateCancelled {
		t.Fatalf("halted record = %+v found=%v err=%v", rec, found, err)
	}
	if exec.count() != 1 {
		t.Fatalf("executor calls=%d, want one cancelled call", exec.count())
	}
	if exec.effectCount() != 0 {
		t.Fatal("executor-side halt fence allowed an in-flight host effect")
	}
	gen, _ := h.store.CurrentHaltGeneration(tctx())
	attempt, found, err := h.store.GetAttempt(tctx(), newAttempt(act("a1"), fingerprint(), false, responsesaga.StateIssued, gen, "", time.Time{}).IdempotencyKey)
	if err != nil || !found || attempt.State != responsesaga.StateOutcomeUnknown {
		t.Fatalf("cancelled executing outcome = %+v found=%v err=%v", attempt, found, err)
	}
	if !h.audit.has("response.halt_failed") {
		t.Fatal("ambiguous executing cancellation must be audited as halt_failed")
	}
}

func TestHaltStillCancelsWhenIntentAuditFails(t *testing.T) {
	h := newHarness(t)
	h.audit.fail = "response.halt_intent"
	exec := &blockingExec{started: make(chan struct{}), release: make(chan struct{})}
	svc, err := newService(h.admit, exec, h.store, h.audit, fixedClock{t: time.Unix(1000, 0)})
	if err != nil {
		t.Fatal(err)
	}
	applyDone := make(chan error, 1)
	go func() {
		_, err := svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice")
		applyDone <- err
	}()
	<-exec.started
	if _, err := svc.HaltResponses(tctx(), "t1", "operator@example.test", "kill switch"); !errors.Is(err, shared.ErrSaturated) {
		t.Fatalf("audit-degraded halt must return partial failure, got %v", err)
	}
	if err := <-applyDone; err == nil {
		t.Fatal("audit failure allowed in-flight response to report success")
	}
	rec, found, err := h.store.Get(tctx(), "a1")
	if err != nil || !found || rec.State != StateCancelled {
		t.Fatalf("audit-degraded halt record = %+v found=%v err=%v", rec, found, err)
	}
	pending, err := h.store.ListPendingResponseAudits(tctx())
	if err != nil || len(pending) != 1 || pending[0].Entry.Action != "response.halt_intent" {
		t.Fatalf("durable audit obligations = %+v err=%v", pending, err)
	}
	h.audit.fail = ""
	if err := h.svc.ReconcileAudits(tctx()); err != nil {
		t.Fatalf("reconcile response audits: %v", err)
	}
	pending, err = h.store.ListPendingResponseAudits(tctx())
	if err != nil || len(pending) != 0 || !h.audit.has("response.halt_intent") {
		t.Fatalf("reconciled audit obligations = %+v err=%v", pending, err)
	}
}

func TestHaltSurfacesExecutorFenceFailure(t *testing.T) {
	h := newHarness(t)
	h.exec.haltErr = errors.New("remote fence unavailable")
	if halted, err := h.svc.HaltResponses(tctx(), "t1", "operator@example.test", "kill switch"); halted != 0 || !errors.Is(err, shared.ErrSaturated) {
		t.Fatalf("executor fence failure must fail closed: halted=%d err=%v", halted, err)
	}
	if !h.audit.has("response.halt_failed") {
		t.Fatal("executor fence failure was not audited")
	}
}

func TestHaltFailureLeavesDurableDispatchForReplay(t *testing.T) {
	h := newHarness(t)
	h.exec.haltErr = errors.New("remote fence unavailable")
	if _, err := h.svc.HaltResponses(tctx(), "t1", "operator@example.test", "kill switch"); !errors.Is(err, shared.ErrSaturated) {
		t.Fatalf("initial halt error = %v, want saturated", err)
	}
	pending, err := h.store.ListPendingResponseHaltDispatches(tctx())
	if err != nil || len(pending) != 1 || pending[0].Generation != 1 {
		t.Fatalf("durable halt dispatches=%+v err=%v", pending, err)
	}

	h.exec.haltErr = nil
	if err := h.svc.ReconcileHaltDispatches(tctx()); err != nil {
		t.Fatalf("reconcile halt dispatch: %v", err)
	}
	pending, err = h.store.ListPendingResponseHaltDispatches(tctx())
	if err != nil || len(pending) != 1 || pending[0].Generation != 1 {
		t.Fatalf("immutable halt dispatch history after replay=%+v err=%v", pending, err)
	}
	if h.exec.haltCalls != 2 || h.exec.haltGeneration["t1"] != 1 {
		t.Fatalf("executor replay calls=%d generation=%d, want calls=2 generation=1", h.exec.haltCalls, h.exec.haltGeneration["t1"])
	}
}

func TestReconcileHaltDispatchesRepairsCrashWindow(t *testing.T) {
	h := newHarness(t)
	intent := responseAuditIntent(
		"response-halt:v1:t1:1:intent", "operator@example.test", "response.halt_intent", "t1",
		time.Unix(1000, 0).UTC(), map[string]string{"reason": "kill switch", "generation": "1"},
	)
	generation, _, dispatch, err := h.store.AdvanceHaltGenerationWithAudit(tctx(), 0, intent)
	if err != nil {
		t.Fatalf("commit halt before simulated crash: %v", err)
	}
	if generation != 1 || dispatch.Generation != 1 || h.exec.haltCalls != 0 {
		t.Fatalf("pre-recovery generation=%d dispatch=%+v executor calls=%d", generation, dispatch, h.exec.haltCalls)
	}

	if err := h.svc.ReconcileHaltDispatches(tctx()); err != nil {
		t.Fatalf("reconcile crash-window halt: %v", err)
	}
	if h.exec.haltCalls != 1 || h.exec.haltGeneration["t1"] != 1 {
		t.Fatalf("replayed executor calls=%d generation=%d, want 1/1", h.exec.haltCalls, h.exec.haltGeneration["t1"])
	}
	if err := h.svc.ReconcileHaltDispatches(tctx()); err != nil {
		t.Fatalf("repeat reconciliation: %v", err)
	}
	if h.exec.haltCalls != 2 || h.exec.haltGeneration["t1"] != 1 {
		t.Fatalf("immutable replay calls=%d generation=%d, want 2/1", h.exec.haltCalls, h.exec.haltGeneration["t1"])
	}
}

func TestHaltFencesExecutionClaimedByAnotherService(t *testing.T) {
	h := newHarness(t)
	exec := &blockingExec{started: make(chan struct{}), release: make(chan struct{})}
	worker, err := newService(h.admit, exec, h.store, h.audit, fixedClock{t: time.Unix(1000, 0)})
	if err != nil {
		t.Fatal(err)
	}
	halter, err := newService(h.admit, exec, h.store, h.audit, fixedClock{t: time.Unix(1000, 0)})
	if err != nil {
		t.Fatal(err)
	}
	applyDone := make(chan error, 1)
	go func() {
		_, err := worker.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice")
		applyDone <- err
	}()
	<-exec.started

	halted, err := halter.HaltResponses(tctx(), "t1", "operator@example.test", "kill switch")
	if halted != 1 || !errors.Is(err, shared.ErrSaturated) {
		t.Fatalf("cross-service halt must fail closed: halted=%d err=%v", halted, err)
	}
	close(exec.release)
	if err := <-applyDone; err == nil {
		t.Fatal("a remotely fenced execution must not commit an applied projection")
	}
	if exec.effectCount() != 0 {
		t.Fatal("remote executor-side halt fence allowed the host effect")
	}
	rec, found, err := h.store.Get(tctx(), "a1")
	if err != nil || !found || rec.State != StateCancelled {
		t.Fatalf("durably fenced record = %+v found=%v err=%v", rec, found, err)
	}
}

func TestHaltGenerationFencesOperationBlockedInAdmission(t *testing.T) {
	h := newHarness(t)
	h.admit.started = make(chan struct{})
	h.admit.release = make(chan struct{})
	applyDone := make(chan error, 1)
	go func() {
		_, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice")
		applyDone <- err
	}()
	<-h.admit.started
	if halted, err := h.svc.HaltResponses(tctx(), "t1", "operator@example.test", "kill switch"); err != nil || halted != 0 {
		t.Fatalf("halt blocked admission: halted=%d err=%v", halted, err)
	}
	close(h.admit.release)
	if err := <-applyDone; !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale admission generation must be fenced, got %v", err)
	}
	if h.exec.count() != 0 {
		t.Fatal("an operation admitted against a stale halt generation executed")
	}
	rec, found, err := h.store.Get(tctx(), "a1")
	if err != nil || !found || rec.State != StateCancelled {
		t.Fatalf("stale admitted response = %+v found=%v err=%v", rec, found, err)
	}
	h.admit.started = nil
	h.admit.release = nil
	a2 := act("a2")
	if _, err := h.svc.Apply(tctx(), "eng-1", a2, target(), fingerprint(), "alice"); !errors.Is(err, responsesaga.ErrHaltLatched) {
		t.Fatalf("latched halt must reject new-generation dispatch, got %v", err)
	}
	if h.exec.count() != 0 {
		t.Fatal("new work executed while response halt was latched")
	}
}

func TestHaltGenerationFencesOperationBlockedInReauthorization(t *testing.T) {
	h := newHarness(t)
	h.admit.reauthStarted = make(chan struct{})
	h.admit.reauthRelease = make(chan struct{})
	worker, err := newService(h.admit, h.exec, h.store, h.audit, fixedClock{t: time.Unix(1000, 0)})
	if err != nil {
		t.Fatal(err)
	}
	halter, err := newService(&fakeAdmitter{}, h.exec, h.store, h.audit, fixedClock{t: time.Unix(1000, 0)})
	if err != nil {
		t.Fatal(err)
	}
	applyDone := make(chan error, 1)
	go func() {
		_, err := worker.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice")
		applyDone <- err
	}()
	<-h.admit.reauthStarted
	if halted, err := halter.HaltResponses(tctx(), "t1", "operator@example.test", "kill switch"); halted != 1 || !errors.Is(err, shared.ErrSaturated) {
		t.Fatalf("halt during remote reauthorization must fail closed: halted=%d err=%v", halted, err)
	}
	close(h.admit.reauthRelease)
	if err := <-applyDone; err == nil {
		t.Fatal("operation admitted against the pre-halt generation executed after reauthorization")
	}
	if h.exec.count() != 0 {
		t.Fatal("response executed after its halt generation became stale during reauthorization")
	}
}

func TestApplyExecutesImmutableSnapshot(t *testing.T) {
	h := newHarness(t)
	h.admit.started = make(chan struct{})
	h.admit.release = make(chan struct{})
	action := act("a1")
	applyDone := make(chan error, 1)
	go func() {
		_, err := h.svc.Apply(tctx(), "eng-1", action, target(), fingerprint(), "alice")
		applyDone <- err
	}()
	<-h.admit.started
	action.Argv[0] = "poisoned"
	action.Reversal.Argv[0] = "also-poisoned"
	close(h.admit.release)
	if err := <-applyDone; err != nil {
		t.Fatalf("apply immutable snapshot: %v", err)
	}
	if got := h.exec.runs[0].Argv[0]; got != "synapse-agent-response" {
		t.Fatalf("executed caller-mutated argv %q", got)
	}
}

func TestApplyReauthorizesImmediatelyBeforeDispatch(t *testing.T) {
	h := newHarness(t)
	h.admit.reauthErr = shared.ErrForbidden
	if _, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice"); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("dispatch reauthorization must fail closed, got %v", err)
	}
	if h.exec.count() != 0 {
		t.Fatal("response executed after dispatch reauthorization failed")
	}
}

func TestHaltFencesRollbackClaimedByAnotherService(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice"); err != nil {
		t.Fatal(err)
	}
	exec := &blockingExec{started: make(chan struct{}), release: make(chan struct{})}
	worker, err := newService(h.admit, exec, h.store, h.audit, fixedClock{t: time.Unix(1000, 0)})
	if err != nil {
		t.Fatal(err)
	}
	worker.verify = &fakeVerifier{outcome: VerificationSucceeded}
	halter, err := newService(h.admit, exec, h.store, h.audit, fixedClock{t: time.Unix(1000, 0)})
	if err != nil {
		t.Fatal(err)
	}
	revertDone := make(chan error, 1)
	go func() {
		_, err := worker.Revert(tctx(), "a1", target(), fingerprint(), "alice")
		revertDone <- err
	}()
	<-exec.started

	halted, err := halter.HaltResponses(tctx(), "t1", "operator@example.test", "kill switch")
	if halted != 1 || !errors.Is(err, shared.ErrSaturated) {
		t.Fatalf("cross-service rollback halt must fail closed: halted=%d err=%v", halted, err)
	}
	close(exec.release)
	if err := <-revertDone; err == nil {
		t.Fatal("a remotely fenced rollback must not commit a reverted projection")
	}
	if exec.effectCount() != 0 {
		t.Fatal("remote executor-side halt fence allowed the rollback effect")
	}
	rec, found, err := h.store.Get(tctx(), "a1")
	if err != nil || !found || rec.State != StateApplied {
		t.Fatalf("rollback-fenced record = %+v found=%v err=%v", rec, found, err)
	}
}

func TestHaltDuringRollbackVerificationNeverReportsCleanCancellation(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice"); err != nil {
		t.Fatal(err)
	}
	verifier := &blockingVerifier{started: make(chan struct{})}
	h.svc.verify = verifier
	revertDone := make(chan error, 1)
	go func() {
		_, err := h.svc.Revert(tctx(), "a1", target(), fingerprint(), "alice")
		revertDone <- err
	}()
	<-verifier.started
	halted, err := h.svc.HaltResponses(tctx(), "t1", "operator@example.test", "kill switch")
	if halted != 1 || !errors.Is(err, shared.ErrSaturated) {
		t.Fatalf("halt during rollback verification must fail closed: halted=%d err=%v", halted, err)
	}
	if err := <-revertDone; err == nil {
		t.Fatal("interrupted rollback verification must not report success")
	}
	rec, found, err := h.store.Get(tctx(), "a1")
	if err != nil || !found || rec.State != StateApplied {
		t.Fatalf("interrupted rollback projection = %+v found=%v err=%v", rec, found, err)
	}
	h.svc.verify = &fakeVerifier{outcome: VerificationSucceeded}
	rec, err = h.svc.Revert(tctx(), "a1", target(), fingerprint(), "alice")
	if err != nil || rec.State != StateReverted {
		t.Fatalf("reconcile old-generation rollback under halt latch: state=%s err=%v", rec.State, err)
	}
}

func TestHaltDuringApplyVerificationCancelsVerifier(t *testing.T) {
	h := newHarness(t)
	verifier := &blockingVerifier{started: make(chan struct{})}
	h.svc.verify = verifier
	applyDone := make(chan error, 1)
	go func() {
		_, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice")
		applyDone <- err
	}()
	<-verifier.started
	halted, err := h.svc.HaltResponses(tctx(), "t1", "operator@example.test", "kill switch")
	if halted != 1 || !errors.Is(err, shared.ErrSaturated) {
		t.Fatalf("halt during apply verification must fail closed: halted=%d err=%v", halted, err)
	}
	if err := <-applyDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("interrupted apply verification must retain cancellation, got %v", err)
	}
	rec, found, err := h.store.Get(tctx(), "a1")
	if err != nil || !found || rec.State != StateApplied || rec.Verification != VerificationPending {
		t.Fatalf("interrupted apply verification projection = %+v found=%v err=%v", rec, found, err)
	}
}

func TestRemoteHaltSeesApplyVerificationInProgress(t *testing.T) {
	h := newHarness(t)
	verifier := &blockingVerifier{started: make(chan struct{})}
	worker, err := newService(h.admit, h.exec, h.store, h.audit, fixedClock{t: time.Unix(1000, 0)})
	if err != nil {
		t.Fatal(err)
	}
	worker.verify = verifier
	halter, err := newService(&fakeAdmitter{}, h.exec, h.store, h.audit, fixedClock{t: time.Unix(1000, 0)})
	if err != nil {
		t.Fatal(err)
	}
	applyCtx, cancelApply := context.WithCancel(tctx())
	defer cancelApply()
	applyDone := make(chan error, 1)
	go func() {
		_, err := worker.Apply(applyCtx, "eng-1", act("a1"), target(), fingerprint(), "alice")
		applyDone <- err
	}()
	<-verifier.started
	halted, err := halter.HaltResponses(tctx(), "t1", "operator@example.test", "kill switch")
	if halted != 1 || !errors.Is(err, shared.ErrSaturated) {
		t.Fatalf("remote halt must report in-progress apply verification: halted=%d err=%v", halted, err)
	}
	cancelApply()
	if err := <-applyDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled remote apply verification returned %v", err)
	}
}

func TestApplyRefusesUnboundStableFingerprint(t *testing.T) {
	h := newHarness(t)
	wrong := fingerprint()
	wrong.HostID = "host-2"
	if _, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), wrong, "alice"); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("unbound target fingerprint must be forbidden, got %v", err)
	}
	if len(h.admit.calls) != 0 || h.exec.count() != 0 {
		t.Fatal("invalid target fingerprint must fail before admission and execution")
	}
}

func TestRevertRequiresOriginalStableFingerprint(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice"); err != nil {
		t.Fatal(err)
	}
	h.svc.verify = &fakeVerifier{outcome: VerificationSucceeded}
	newGeneration := fingerprint()
	newGeneration.NetpolGeneration++
	if _, err := h.svc.Revert(tctx(), "a1", target(), newGeneration, "alice"); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("rollback target generation change must conflict, got %v", err)
	}
	if h.exec.count() != 1 {
		t.Fatalf("rollback executed against a rebound target; executions=%d", h.exec.count())
	}
}

func TestApplyRetryCannotChangeStableFingerprint(t *testing.T) {
	h := newHarness(t)
	h.exec.err = errors.New("executor acknowledgement lost")
	if _, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice"); err == nil {
		t.Fatal("ambiguous apply must return an error")
	}
	h.exec.err = nil
	changed := fingerprint()
	changed.NetpolGeneration++
	if _, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), changed, "alice"); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("retry with changed fingerprint must conflict, got %v", err)
	}
	if h.exec.count() != 1 {
		t.Fatalf("changed fingerprint caused a second execution; executions=%d", h.exec.count())
	}
	rec, found, err := h.store.Get(tctx(), "a1")
	if err != nil || !found || rec.State != StatePending {
		t.Fatalf("identity conflict changed parent projection: rec=%+v found=%v err=%v", rec, found, err)
	}
}

// TestApplyIsIdempotent: re-issuing an applied action is a no-op reporting the already-applied state.
func TestApplyIsIdempotent(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice"); err != nil {
		t.Fatal(err)
	}
	rec, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice")
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

func TestApplyRejectsCatalogueRadiusMismatchBeforeExecution(t *testing.T) {
	h := newHarness(t)
	h.exec.observed = offensivepolicy.RadiusStateChanging
	a := act("a1")
	a.BlastRadius = offensivepolicy.RadiusReadOnly
	if _, err := h.svc.Apply(tctx(), "eng-1", a, target(), fingerprint(), "alice"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a catalogue radius mismatch must be refused, got %v", err)
	}
	if h.exec.count() != 0 {
		t.Fatal("a catalogue radius mismatch must fail before execution")
	}
}

func TestRadiusExceeded(t *testing.T) {
	if !radiusExceeded(offensivepolicy.RadiusReadOnly, offensivepolicy.RadiusStateChanging) {
		t.Fatal("state-changing observation must exceed a read-only declaration")
	}
	if radiusExceeded(offensivepolicy.RadiusStateChanging, offensivepolicy.RadiusStateChanging) {
		t.Fatal("matching state-changing radius must not exceed its declaration")
	}
}

// TestApplyHaltsWhenEffectTouchesMoreThanOneTarget: a state-changing action declares a SINGLE target, so
// an effect touching more than one asset is a blast-radius violation (the meaningful case for the
// binary radius, where every response action is state_changing).
func TestApplyHaltsWhenEffectTouchesMoreThanOneTarget(t *testing.T) {
	h := newHarness(t)
	h.exec.affected = 3 // the executor observed the action touch 3 assets, not the 1 declared
	rec, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice")
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
	if _, err := h.svc.Apply(tctx(), "eng-1", act("a1"), other, fingerprint(), "alice"); !errors.Is(err, shared.ErrForbidden) {
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
	h.svc.verify = &fakeVerifier{outcome: VerificationSucceeded}
	if _, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice"); err != nil {
		t.Fatal(err)
	}
	admBefore := len(h.admit.calls)
	rec, err := h.svc.Revert(tctx(), "a1", target(), fingerprint(), "alice")
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

// TestRevertEnforcesTheBlastRadius is the same guarantee as apply, on the reversal: a reversal whose
// executed effect exceeds its declared single-target radius is a violation, halted and audited, never a
// clean revert. Without it a reversal could escape the blast-radius rule apply enforces.
func TestRevertEnforcesTheBlastRadius(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice"); err != nil {
		t.Fatal(err)
	}
	// The next execution (the reversal) reports touching two entities: a blast-radius violation.
	h.exec.affected = 2
	h.svc.verify = &fakeVerifier{outcome: VerificationSucceeded}
	rec, err := h.svc.Revert(tctx(), "a1", target(), fingerprint(), "alice")
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("a reversal exceeding its radius must be forbidden, got %v", err)
	}
	if rec.State != StateViolation {
		t.Fatalf("want violation, got %s", rec.State)
	}
	if !h.audit.has("response.reversal_blast_radius_violation") {
		t.Error("the reversal violation must be audited")
	}
	stored, _, _ := h.store.Get(tctx(), "a1")
	if stored.State != StateViolation {
		t.Fatalf("the violation must be persisted, got %s", stored.State)
	}
	attempt, found, attemptErr := h.store.GetAttempt(tctx(), responseAttemptKey(act("a1"), true))
	if attemptErr != nil || !found || attempt.State != responsesaga.StateRollbackUnknown {
		t.Fatalf("reversal violation attempt = %+v found=%v err=%v, want durable rollback-unknown", attempt, found, attemptErr)
	}
}

// TestApplyPendingReturnsTheRecordSoItCanBeReferenced: a pending admission records the action under its
// server-minted id and hands that record back (with the pending error), so the operator learns the id
// to find it in the list and the kill switch can cancel it.
func TestApplyPendingReturnsTheRecordSoItCanBeReferenced(t *testing.T) {
	h := newHarness(t)
	h.admit.err = safety.ErrPendingApproval
	rec, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice")
	if !errors.Is(err, safety.ErrPendingApproval) {
		t.Fatalf("want pending, got %v", err)
	}
	if rec.Action.ID != "a1" || rec.State != StatePending {
		t.Fatalf("pending record = %+v, want the server-minted id in pending state", rec)
	}
	stored, found, _ := h.store.Get(tctx(), "a1")
	if !found || stored.State != StatePending {
		t.Fatalf("the pending action must be durably stored, got found=%v state=%s", found, stored.State)
	}
}

func TestRevertRequiresTelemetryVerifier(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Revert(tctx(), "a1", target(), fingerprint(), "alice"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("rollback without telemetry must fail closed, got %v", err)
	}
	if h.exec.count() != 1 {
		t.Fatalf("rollback executed without a verifier; executions=%d", h.exec.count())
	}
}

func TestRevertCanRecoverTelemetryConfirmedAmbiguousApply(t *testing.T) {
	h := newHarness(t)
	h.exec.err = errors.New("executor acknowledgement lost")
	if _, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice"); err == nil {
		t.Fatal("ambiguous apply must return an error")
	}
	h.exec.err = nil
	h.svc.verify = &fakeVerifier{outcome: VerificationSucceeded}
	rec, err := h.svc.Revert(tctx(), "a1", target(), fingerprint(), "alice")
	if err != nil {
		t.Fatalf("governed rollback of telemetry-confirmed ambiguous effect: %v", err)
	}
	if rec.State != StateReverted || h.exec.count() != 2 {
		t.Fatalf("ambiguous effect recovery state=%s executions=%d", rec.State, h.exec.count())
	}
}

func TestRevertRequiresVerifiedRestoration(t *testing.T) {
	for _, outcome := range []Verification{VerificationFailed, VerificationUnknown} {
		t.Run(string(outcome), func(t *testing.T) {
			h := newHarness(t)
			if _, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice"); err != nil {
				t.Fatal(err)
			}
			h.svc.verify = &fakeVerifier{outcome: outcome}
			if _, err := h.svc.Revert(tctx(), "a1", target(), fingerprint(), "alice"); !errors.Is(err, shared.ErrForbidden) {
				t.Fatalf("unverified rollback must fail closed, got %v", err)
			}
			rec, _, _ := h.store.Get(tctx(), "a1")
			if rec.State != StateViolation {
				t.Fatalf("unverified rollback projection=%s, want violation requiring intervention", rec.State)
			}
		})
	}
}

// TestKillSwitchHaltsPending is the #425 kill-switch requirement, measured: a pending (admitted-but-not-
// approved) action is halted.
func TestKillSwitchHaltsPending(t *testing.T) {
	h := newHarness(t)
	h.admit.err = safety.ErrPendingApproval // admission suspends → pending recorded
	if _, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice"); !errors.Is(err, safety.ErrPendingApproval) {
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
	if _, err := h.svc.Apply(tctx(), "eng-1", a, target(), fingerprint(), "alice"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("an action with no reversal must be refused, got %v", err)
	}
	if len(h.admit.calls) != 0 || h.exec.count() != 0 {
		t.Fatal("nothing may be admitted or executed for an unimplementable action")
	}
}

func TestApplyRequiresTenant(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.Apply(context.Background(), "eng-1", act("a1"), target(), fingerprint(), "alice"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a missing tenant must be refused, got %v", err)
	}
}

// ---- #638 telemetry-verified post-condition -------------------------------------------------------

type fakeVerifier struct {
	outcome    rdom.Verification
	err        error
	calls      int
	identity   string
	evidenceID shared.ID
}

func (f *fakeVerifier) Identity() string {
	if f.identity != "" {
		return f.identity
	}
	return "agent:response-verifier"
}

func (f *fakeVerifier) Verify(_ context.Context, _ VerificationRequest) (VerificationReceipt, error) {
	f.calls++
	evidenceID := f.evidenceID
	if evidenceID.IsZero() {
		evidenceID = "verification-evidence-1"
	}
	return VerificationReceipt{Outcome: f.outcome, EvidenceID: evidenceID}, f.err
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
		wantErr bool
	}{
		{"succeeded", VerificationSucceeded, nil, VerificationSucceeded, "response.verified", false},
		{"failed_effect_not_present", VerificationFailed, nil, VerificationFailed, "response.verification_failed", true},
		{"unknown_coverage", VerificationUnknown, nil, VerificationUnknown, "response.verification_unknown", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			vf := &fakeVerifier{outcome: tc.outcome, err: tc.err}
			h.svc.verify = vf
			rec, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice")
			if tc.wantErr && !errors.Is(err, shared.ErrConflict) {
				t.Fatalf("unverified apply must return conflict, got %v", err)
			}
			if !tc.wantErr && err != nil {
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

func TestApplyKeepsMissingObservationPendingUntilReconciled(t *testing.T) {
	h := newHarness(t)
	verifier := &fakeVerifier{outcome: VerificationPending, err: errors.New("telemetry store unavailable")}
	h.svc.verify = verifier
	action := act("pending-observation")

	rec, err := h.svc.Apply(tctx(), "eng-1", action, target(), fingerprint(), "alice")
	if !errors.Is(err, ErrVerificationPending) {
		t.Fatalf("missing observation must remain retryable, got %v", err)
	}
	if rec.State != StateApplied || rec.Verification != VerificationPending || h.audit.has("response.verification_unknown") {
		t.Fatalf("missing observation was terminalized: record=%+v", rec)
	}
	attempt, found, err := h.store.GetAttempt(tctx(), responseAttemptKey(action, false))
	if err != nil || !found || attempt.State != responsesaga.StateVerifying {
		t.Fatalf("pending attempt state=%s found=%t err=%v", attempt.State, found, err)
	}

	verifier.err = nil
	verifier.outcome = VerificationSucceeded
	if err := h.svc.ReconcilePending(tctx()); err != nil {
		t.Fatalf("reconcile late observation: %v", err)
	}
	rec, found, err = h.store.Get(tctx(), action.ID)
	if err != nil || !found || rec.Verification != VerificationSucceeded {
		t.Fatalf("late observation did not verify response: record=%+v found=%t err=%v", rec, found, err)
	}
}

// TestApplyWithoutVerifierLeavesVerificationPending: with no verifier wired the behaviour is unchanged —
// the effect is simply not verified (Pending), never a false claim of success.
func TestApplyWithoutVerifierLeavesVerificationPending(t *testing.T) {
	h := newHarness(t)
	rec, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice")
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if rec.Verification != VerificationPending {
		t.Fatalf("no verifier ⇒ verification pending, got %q", rec.Verification)
	}
}

func TestApplyRejectsSelfVerification(t *testing.T) {
	h := newHarness(t)
	h.svc.verify = &fakeVerifier{outcome: VerificationSucceeded, identity: h.exec.Identity()}
	rec, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice")
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("executor self-verification must return non-success, got %v", err)
	}
	if rec.Verification != VerificationUnknown {
		t.Fatalf("self-verification recorded %q, want unknown", rec.Verification)
	}
}

func TestApplyRejectsUntrustedVerificationReceipt(t *testing.T) {
	h := newHarness(t)
	h.svc.verify = &fakeVerifier{outcome: VerificationSucceeded}
	h.svc.receipts = &fakeReceiptValidator{err: shared.ErrForbidden}
	rec, err := h.svc.Apply(tctx(), "eng-1", act("a1"), target(), fingerprint(), "alice")
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("untrusted verification receipt must return non-success, got %v", err)
	}
	if rec.Verification != VerificationUnknown {
		t.Fatalf("untrusted verification receipt recorded %q, want unknown", rec.Verification)
	}
}

func TestApplyRecoveryRevalidatesPersistedReceipt(t *testing.T) {
	h := newHarness(t)
	verifier := &fakeVerifier{outcome: VerificationSucceeded}
	h.svc.verify = verifier
	validator := h.svc.receipts.(*fakeReceiptValidator)
	action := act("receipt-recovery-apply")

	if _, err := h.svc.Apply(tctx(), "eng-1", action, target(), fingerprint(), "alice"); err != nil {
		t.Fatalf("initial apply: %v", err)
	}
	if validator.calls != 1 || verifier.calls != 1 {
		t.Fatalf("initial verification calls = validator:%d verifier:%d, want 1 each", validator.calls, verifier.calls)
	}
	if _, err := h.svc.Apply(tctx(), "eng-1", action, target(), fingerprint(), "alice"); err != nil {
		t.Fatalf("recover valid applied response: %v", err)
	}
	if validator.calls != 2 || verifier.calls != 1 {
		t.Fatalf("recovery calls = validator:%d verifier:%d, want validator=2 verifier=1", validator.calls, verifier.calls)
	}
	if validator.reqs[1].Reversal {
		t.Fatal("apply recovery revalidated a rollback receipt")
	}

	validator.err = shared.ErrForbidden
	if _, err := h.svc.Apply(tctx(), "eng-1", action, target(), fingerprint(), "alice"); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("untrusted persisted apply receipt error = %v, want forbidden", err)
	}
	if verifier.calls != 1 {
		t.Fatalf("recovery re-ran telemetry verifier %d times, want the persisted receipt checked instead", verifier.calls)
	}
}

func TestRollbackRecoveryRevalidatesPersistedReceipt(t *testing.T) {
	h := newHarness(t)
	verifier := &fakeVerifier{outcome: VerificationSucceeded}
	h.svc.verify = verifier
	validator := h.svc.receipts.(*fakeReceiptValidator)
	action := act("receipt-recovery-rollback")

	if _, err := h.svc.Apply(tctx(), "eng-1", action, target(), fingerprint(), "alice"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, err := h.svc.Revert(tctx(), action.ID, target(), fingerprint(), "bob"); err != nil {
		t.Fatalf("initial rollback: %v", err)
	}
	if validator.calls != 2 || verifier.calls != 2 {
		t.Fatalf("initial receipt calls = validator:%d verifier:%d, want 2 each", validator.calls, verifier.calls)
	}
	if _, err := h.svc.Revert(tctx(), action.ID, target(), fingerprint(), "bob"); err != nil {
		t.Fatalf("recover valid rollback: %v", err)
	}
	if validator.calls != 3 || verifier.calls != 2 {
		t.Fatalf("rollback recovery calls = validator:%d verifier:%d, want validator=3 verifier=2", validator.calls, verifier.calls)
	}
	if !validator.reqs[2].Reversal {
		t.Fatal("rollback recovery revalidated an apply receipt")
	}

	validator.err = shared.ErrForbidden
	if _, err := h.svc.Revert(tctx(), action.ID, target(), fingerprint(), "bob"); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("untrusted persisted rollback receipt error = %v, want forbidden", err)
	}
	if verifier.calls != 2 {
		t.Fatalf("rollback recovery re-ran telemetry verifier %d times, want persisted receipt validation", verifier.calls)
	}
}
