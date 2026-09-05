// Package response applies governed defensive response actions (issue #425): isolate a host, quarantine
// a file, stop a process. It adds no new trust model — every action goes through the SAME admission gate
// (internal/usecase/safety) as a DAST probe and an exploitation step, is approved by a human (never a
// model) with the approval sealed as evidence, is argv-only, is reversible, and is halted by the #418
// kill switch. Apply is reachable only after admission plus a recorded human approval.
package response

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/safety"
)

// machinePrefixes are the non-human identity families. A machine may propose, never approve — automatic
// response on a model's opinion is prohibited by construction (#425 req 2). Mirrors offensivepolicy.
var machinePrefixes = []string{"agent:", "llm:", "mcp:", "system:", "machine:", "bot:", "service:"}

// admitter is the admission gate every action is routed through — the SAME gate the DAST probe and the
// exploitation step use (*safety.Gate satisfies it). A response action is not a privileged side path: it
// cannot execute without an AdmittedAction, which only the gate can mint (its fields are unexported).
type admitter interface {
	Admit(ctx context.Context, p agent.ProposedAction, actor string) (safety.AdmittedAction, error)
}

// The production admitter IS the shared safety gate — a compile-time proof that a response action is
// admitted through the same gate as a DAST probe and an exploitation step, not a privileged side path.
var _ admitter = (*safety.Gate)(nil)

// Executor runs an argv-only response command on the host, scoped to the target, and reports the OBSERVED
// blast radius so an effect exceeding the declared radius is caught. No shell, ever, including reversals.
type Executor interface {
	Execute(ctx context.Context, req ExecRequest) (ExecOutcome, error)
}

// ExecRequest is an argv-only command to run against a target.
type ExecRequest struct {
	Argv       []string
	Target     shared.ID
	Declared   offensivepolicy.Radius
	IsReversal bool
}

// ExecOutcome reports what the host actually did. AlreadyApplied lets the executor signal idempotency
// (the host is already isolated / the file already quarantined), so a re-issue is a no-op. AffectedCount
// is how many distinct entities the action actually touched: an action declares a SINGLE target, so an
// effect touching more than one is a blast-radius violation the binary read_only/state_changing radius
// cannot express on its own.
type ExecOutcome struct {
	ObservedRadius offensivepolicy.Radius
	AffectedCount  int
	AlreadyApplied bool
}

// EffectVerifier confirms, against telemetry, whether an applied action's intended EFFECT actually took
// hold on the target (#638). It is READ-ONLY — it observes, it never executes anything on the host — so
// wiring it crosses no execution boundary. `CommandApplied ≠ VerifiedSucceeded`: a kill whose syscall
// returned but whose process is still observed alive verifies as Failed; a target with no covering
// telemetry verifies as Unknown, never silently a success. Optional (nil ⇒ verification is not run).
type EffectVerifier interface {
	Verify(ctx context.Context, action rdom.Action, target shared.ID) (rdom.Verification, error)
}

// Record and State are the domain types (domain/response); re-exported as aliases so callers of this
// usecase package need not import both.
type (
	Record       = rdom.Record
	State        = rdom.State
	Verification = rdom.Verification
)

const (
	StatePending   = rdom.StatePending
	StateApplied   = rdom.StateApplied
	StateReverted  = rdom.StateReverted
	StateCancelled = rdom.StateCancelled
	StateViolation = rdom.StateViolation

	VerificationPending   = rdom.VerificationPending
	VerificationSucceeded = rdom.VerificationSucceeded
	VerificationFailed    = rdom.VerificationFailed
	VerificationUnknown   = rdom.VerificationUnknown
)

// Service applies response actions under the shared governance.
type Service struct {
	admit  admitter
	exec   Executor
	store  ports.ResponseStore
	audit  ports.AuditLogger
	clock  ports.Clock
	verify EffectVerifier // optional (#638): confirms an applied effect via telemetry; nil ⇒ not run
}

// NewService validates dependencies.
func NewService(admit admitter, exec Executor, store ports.ResponseStore, audit ports.AuditLogger, clock ports.Clock) (*Service, error) {
	if admit == nil || exec == nil || store == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: response service is missing a dependency", shared.ErrValidation)
	}
	return &Service{admit: admit, exec: exec, store: store, audit: audit, clock: clock}, nil
}

// SetEffectVerifier wires the telemetry-verified post-condition (#638). Optional and read-only: when set,
// an applied action is verified against telemetry and the outcome is recorded on the record + audited;
// nil leaves Verification as Pending. It never executes anything on the host.
func (s *Service) SetEffectVerifier(v EffectVerifier) { s.verify = v }

// verified runs the post-condition check on an APPLIED record (when a verifier is wired) and records the
// outcome on the record + a distinct audit line. `CommandApplied ≠ VerifiedSucceeded`: a Failed outcome
// means the command ran but the effect is not confirmed — a loud signal the operator must act on. A
// verifier error is NEVER a silent success: it records Unknown. Read-only; no host side effect.
func (s *Service) verified(ctx context.Context, rec Record, approver string) Record {
	if s.verify == nil || rec.State != StateApplied {
		return rec
	}
	v, err := s.verify.Verify(ctx, rec.Action, rec.Action.Target)
	if err != nil {
		rec.Verification = VerificationUnknown
		s.recordAudit(ctx, "response.verification_unknown", approver, rec.Action, map[string]string{"reason": "verifier error"})
		return rec
	}
	// A verifier that RAN must yield a definite outcome: an invalid value, or Pending ("" = "not
	// verified"), is coerced to Unknown so a verifier that ran is never recorded as un-run and is always
	// audited. Fail-closed — never a silent success.
	if !v.Valid() || v == VerificationPending {
		v = VerificationUnknown
	}
	rec.Verification = v
	switch v {
	case VerificationSucceeded:
		s.recordAudit(ctx, "response.verified", approver, rec.Action, nil)
	case VerificationFailed:
		s.recordAudit(ctx, "response.verification_failed", approver, rec.Action, nil)
	case VerificationUnknown:
		s.recordAudit(ctx, "response.verification_unknown", approver, rec.Action, map[string]string{"reason": "insufficient coverage"})
	}
	return rec
}

// PlanStep is one line of a dry run: the action or reversal that WOULD run, and its argv.
type PlanStep struct {
	Label       string
	Argv        []string
	BlastRadius offensivepolicy.Radius
}

// DryRun enumerates exactly what an action would do — the action and its reversal — and executes NOTHING.
// Same contract as the offensive-policy dry run.
func (s *Service) DryRun(action rdom.Action) ([]PlanStep, error) {
	if err := action.Validate(); err != nil {
		return nil, err
	}
	return []PlanStep{
		{Label: "apply " + string(action.Kind), Argv: action.Argv, BlastRadius: action.BlastRadius},
		{Label: "reverse via " + string(action.Reversal.Kind), Argv: action.Reversal.Argv, BlastRadius: action.BlastRadius},
	}, nil
}

// Apply executes a response action after: (1) it validates (fail-closed on missing reversal/argv/
// radius/scope), (2) the approver is a HUMAN (a machine identity is refused — no model verdict can
// approve), (3) the admission gate admits it (scope guard + recorded human approval, sealed as evidence),
// and (4) the executed effect stays within the declared blast radius. Re-issuing an applied action is a
// no-op reporting the already-applied state.
func (s *Service) Apply(ctx context.Context, engagementID shared.ID, action rdom.Action, target engagement.Target, approver string) (Record, error) {
	if err := action.Validate(); err != nil {
		return Record{}, err
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return Record{}, fmt.Errorf("%w: response apply requires a tenant in context", shared.ErrValidation)
	}
	if isMachine(approver) {
		return Record{}, fmt.Errorf("%w: a response action requires a human approver; %q is a machine identity", shared.ErrForbidden, approver)
	}

	// Idempotency: an already-applied action is a no-op reporting its state.
	if existing, found, err := s.store.Get(ctx, action.ID); err != nil {
		return Record{}, err
	} else if found && existing.State == StateApplied {
		return existing, nil
	}

	// Bind the ADMITTED target to the EXECUTED target: admission scope-checks the engagement.Target, but
	// execution acts on action.Target — decoupling them would let a caller get an in-scope admission for
	// one asset while hitting another. They must be the same asset.
	if target.Value != action.Target.String() {
		return Record{}, fmt.Errorf("%w: admitted target %q does not match the action target %q", shared.ErrForbidden, target.Value, action.Target)
	}

	// Admission: the SAME gate as exploitation. Fail-closed — out-of-scope → ErrForbidden, no approval →
	// ErrPendingApproval; nothing executes in either case.
	p := agent.ProposedAction{
		ID: action.ID, SessionID: shared.ID("response:" + action.ID.String()), EngagementID: engagementID,
		Tool: "response." + string(action.Kind), Action: "response." + string(action.Kind),
		Target: target, Argv: action.Argv, Risk: agent.RiskActive, ProposedAt: s.clock.Now().UTC(),
		Rationale: "defensive response: " + string(action.Kind),
	}
	adm, err := s.admit.Admit(ctx, p, approver)
	if err != nil {
		// Record the pending/refused state so the kill switch can see an in-flight action.
		if isPending(err) {
			_ = s.put(ctx, Record{ID: action.ID, TenantID: tenantID, EngagementID: engagementID, Action: action, State: StatePending, ApprovedBy: approver, UpdatedAt: s.clock.Now().UTC()})
		}
		return Record{}, err
	}

	// Execute argv-only. The executed argv is exactly the admitted payload: p.Argv above is action.Argv,
	// so what the gate cleared and what runs are the same slice — admission is not on a different command.
	out, err := s.exec.Execute(ctx, ExecRequest{Argv: action.Argv, Target: action.Target, Declared: action.BlastRadius})
	if err != nil {
		return Record{}, fmt.Errorf("execute response %s: %w", action.ID, err)
	}
	if out.AlreadyApplied {
		rec := s.record(tenantID, engagementID, action, StateApplied, approver, adm.EvidenceID())
		s.recordAudit(ctx, "response.already_applied", approver, action, nil)
		rec = s.verified(ctx, rec, approver) // re-verify the effect still holds on an idempotent re-issue
		if err := s.put(ctx, rec); err != nil {
			return Record{}, err
		}
		return rec, nil
	}
	// Blast radius at EXECUTION: a broader-than-declared radius OR an effect touching more than the single
	// declared target is a violation — halted and recorded, mirroring the exploitation rule.
	if radiusExceeded(action.BlastRadius, out.ObservedRadius) || out.AffectedCount > 1 {
		rec := s.record(tenantID, engagementID, action, StateViolation, approver, adm.EvidenceID())
		_ = s.put(ctx, rec)
		s.recordAudit(ctx, "response.blast_radius_violation", approver, action, map[string]string{
			"declared": string(action.BlastRadius), "observed": string(out.ObservedRadius), "affected": fmt.Sprint(out.AffectedCount),
		})
		return rec, fmt.Errorf("%w: response %s effect exceeded its declared single-target radius (observed=%s affected=%d)", shared.ErrForbidden, action.ID, out.ObservedRadius, out.AffectedCount)
	}

	rec := s.record(tenantID, engagementID, action, StateApplied, approver, adm.EvidenceID())
	s.recordAudit(ctx, "response.applied", approver, action, map[string]string{"decided_by": adm.DecidedBy()})
	// Telemetry-verified post-condition (#638): the command applied — now confirm the EFFECT actually
	// took hold. CommandApplied ≠ VerifiedSucceeded; the outcome rides on the record + a distinct audit.
	rec = s.verified(ctx, rec, approver)
	if err := s.put(ctx, rec); err != nil {
		return Record{}, err
	}
	return rec, nil
}

// Revert applies an action's reversal. The reversal is itself ADMITTED (through the same gate) and
// AUDITED — a reversal is a first-class governed action, not an unchecked undo.
func (s *Service) Revert(ctx context.Context, actionID shared.ID, target engagement.Target, approver string) (Record, error) {
	rec, found, err := s.store.Get(ctx, actionID)
	if err != nil {
		return Record{}, err
	}
	if !found {
		return Record{}, fmt.Errorf("%w: no response action %s to revert", shared.ErrNotFound, actionID)
	}
	if rec.State != StateApplied {
		return Record{}, fmt.Errorf("%w: response %s is %s, only an applied action can be reverted", shared.ErrValidation, actionID, rec.State)
	}
	if isMachine(approver) {
		return Record{}, fmt.Errorf("%w: a reversal requires a human approver; %q is a machine identity", shared.ErrForbidden, approver)
	}
	if target.Value != rec.Action.Target.String() {
		return Record{}, fmt.Errorf("%w: reversal target %q does not match the action target %q", shared.ErrForbidden, target.Value, rec.Action.Target)
	}
	// Re-validate the stored action (and thus its reversal's argv-only / no-shell guard) before acting on
	// bytes read back from storage — defense in depth against a tampered row.
	if err := rec.Action.Validate(); err != nil {
		return Record{}, fmt.Errorf("stored response action %s is invalid: %w", actionID, err)
	}
	rev := rec.Action.Reversal
	p := agent.ProposedAction{
		ID: shared.ID("revert:" + actionID.String()), SessionID: shared.ID("response:" + actionID.String()), EngagementID: rec.EngagementID,
		Tool: "response." + string(rev.Kind), Action: "response." + string(rev.Kind),
		Target: target, Argv: rev.Argv, Risk: agent.RiskActive, ProposedAt: s.clock.Now().UTC(),
		Rationale: "reverse response: " + rev.Description,
	}
	if _, err := s.admit.Admit(ctx, p, approver); err != nil {
		return Record{}, err
	}
	// The executed reversal argv is exactly the admitted payload (p.Argv above is rev.Argv).
	if _, err := s.exec.Execute(ctx, ExecRequest{Argv: rev.Argv, Target: rec.Action.Target, Declared: rec.Action.BlastRadius, IsReversal: true}); err != nil {
		return Record{}, fmt.Errorf("execute reversal %s: %w", actionID, err)
	}
	rec.State = StateReverted
	rec.UpdatedAt = s.clock.Now().UTC()
	if err := s.put(ctx, rec); err != nil {
		return Record{}, err
	}
	s.recordAudit(ctx, "response.reverted", approver, rec.Action, map[string]string{"reversal": string(rev.Kind)})
	return rec, nil
}

// ListByState returns the tenant's response actions in a state (from ctx tenant), for the operator's
// view of what is admitted-but-not-applied — the same set the kill switch cancels.
func (s *Service) ListByState(ctx context.Context, state State) ([]Record, error) {
	return s.store.ListByState(ctx, state)
}

// HaltResponses cancels every pending (admitted-but-not-yet-applied) response action for the tenant,
// exactly as the kill switch halts offensive work. It is the ResponseHalter the #418 kill switch drives,
// so its signature matches that seam. A single operator action, audited with the operator + reason.
func (s *Service) HaltResponses(ctx context.Context, tenantID shared.ID, actor, reason string) (int, error) {
	if strings.TrimSpace(actor) == "" || strings.TrimSpace(reason) == "" {
		return 0, fmt.Errorf("%w: a halt must name the operator and a reason", shared.ErrValidation)
	}
	ctx = shared.WithTenant(ctx, tenantID) // scope the halt to the tenant the kill switch named
	pending, err := s.store.ListByState(ctx, StatePending)
	if err != nil {
		return 0, err
	}
	halted, failed := 0, 0
	for _, rec := range pending {
		rec.State = StateCancelled
		rec.UpdatedAt = s.clock.Now().UTC()
		if err := s.store.Put(ctx, rec); err != nil {
			// A pending, production-changing action that could NOT be cancelled must not vanish from the
			// count and read as a clean halt — it is a hard failure the operator must see.
			failed++
			continue
		}
		halted++
		s.recordAudit(ctx, "response.halted", actor, rec.Action, map[string]string{"reason": reason})
	}
	if failed > 0 {
		return halted, fmt.Errorf("%w: %d pending response action(s) could not be halted", shared.ErrSaturated, failed)
	}
	return halted, nil
}

func (s *Service) record(tenant, eng shared.ID, action rdom.Action, state State, approver string, evID shared.ID) Record {
	now := s.clock.Now().UTC()
	r := Record{ID: action.ID, TenantID: tenant, EngagementID: eng, Action: action, State: state,
		ApprovedBy: approver, ApprovalEvidenceID: evID, UpdatedAt: now}
	if state == StateApplied {
		r.AppliedAt = now // only a genuinely applied action carries an apply time
	}
	return r
}

func (s *Service) put(ctx context.Context, r Record) error { return s.store.Put(ctx, r) }

func (s *Service) recordAudit(ctx context.Context, action, actor string, a rdom.Action, meta map[string]string) {
	if meta == nil {
		meta = map[string]string{}
	}
	meta["kind"] = string(a.Kind)
	meta["target"] = a.Target.String()
	_ = s.audit.Record(ctx, ports.AuditEntry{Actor: actor, Action: action, Target: a.ID.String(), At: s.clock.Now().UTC(), Metadata: meta})
}

// radiusExceeded reports whether the observed effect is broader than declared (state_changing beyond a
// declared read_only). Mirrors the exploitation rule.
func radiusExceeded(declared, observed offensivepolicy.Radius) bool {
	return declared == offensivepolicy.RadiusReadOnly && observed == offensivepolicy.RadiusStateChanging
}

// isMachine reports whether an approver identity is non-human. It normalises (trim + lower-case) before
// matching the machine-prefix families so a leading space or a capitalised "Agent:" cannot slip a
// machine identity past the "a model can never approve" check. (The stronger guard — requiring a
// resolved human Principal — lands with the HTTP layer; this is the domain-side backstop.)
func isMachine(actor string) bool {
	a := strings.ToLower(strings.TrimSpace(actor))
	if a == "" {
		return true
	}
	for _, p := range machinePrefixes {
		if strings.HasPrefix(a, p) {
			return true
		}
	}
	return false
}

func isPending(err error) bool { return errors.Is(err, safety.ErrPendingApproval) }
