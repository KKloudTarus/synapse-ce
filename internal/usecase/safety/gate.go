// Package safety is the single admission gate for AI-proposed actions and
// the structural embodiment of the rule that AI orchestration is a typed Go state machine,
// not prompt-driven control flow. It produces an AdmittedAction – a type whose
// fields are UNEXPORTED, so it can be constructed ONLY here, by Gate.Admit, and only after
// (1) the engagement execution guard (scope + authorization window + RoE) AND (2) the HITL
// approval both pass. Because the orchestrator's executor accepts an AdmittedAction (not a
// raw spec), there is no compile path to run a tool that skipped scope + approval: the
// invariant is enforced by the Go type system, not by a checklist.
package safety

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/approval"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/execution"
)

// ErrPendingApproval means the action is enqueued for a human and not yet decided – the
// orchestrator suspends the session (status awaiting_approval) and resumes on the decision.
var ErrPendingApproval = errors.New("action awaiting human approval")

// AdmittedAction is a proposed action that has PASSED scope + approval. Its fields are
// unexported: no package other than safety can construct one, so possessing an
// AdmittedAction is proof the action was authorized + approved. The orchestrator reads it
// through the accessors to dispatch the run.
type AdmittedAction struct {
	action       agent.ProposedAction
	decidedBy    string
	authorizedAt time.Time
}

// Action is the underlying proposed action (target/argv/tool) cleared to run.
func (a AdmittedAction) Action() agent.ProposedAction { return a.action }

// DecidedBy is the human who approved it ("auto" when the mode auto-approved it).
func (a AdmittedAction) DecidedBy() string { return a.decidedBy }

// AuthorizedAt is the time the execution guard authorized it.
func (a AdmittedAction) AuthorizedAt() time.Time { return a.authorizedAt }

// Gate admits actions through the engagement guard + the HITL approval, sealing the
// admission into the evidence chain.
type Gate struct {
	guard     *execution.Guard
	approvals *approval.Service
	evidence  *evidence.Service
}

// NewGate validates its deps. All three are required: the guard (scope/window/RoE), the
// approval service (HITL), and the evidence vault (the admission MUST be sealed – if it
// cannot be recorded, the action is not admitted).
func NewGate(guard *execution.Guard, approvals *approval.Service, ev *evidence.Service) (*Gate, error) {
	if guard == nil || approvals == nil || ev == nil {
		return nil, fmt.Errorf("%w: safety gate is missing a dependency", shared.ErrValidation)
	}
	return &Gate{guard: guard, approvals: approvals, evidence: ev}, nil
}

// sealedAdmission is the evidence payload recorded when an action is admitted.
type sealedAdmission struct {
	ActionID  string   `json:"action_id"`
	SessionID string   `json:"session_id"`
	Tool      string   `json:"tool"`
	Action    string   `json:"action"`
	Target    string   `json:"target"`
	Argv      []string `json:"argv"`
	Risk      string   `json:"risk"`
	DecidedBy string   `json:"decided_by"`
}

// Admit runs the proposed action through the guard then the HITL gate. On success it seals
// the admission as evidence and returns an AdmittedAction. Returns ErrForbidden (scope/
// window/RoE failure – already audited by the guard, or a deny/timeout), or ErrPendingApproval
// (awaiting a human). actor is the human who owns the agent session (attribution).
func (g *Gate) Admit(ctx context.Context, p agent.ProposedAction, actor string) (AdmittedAction, error) {
	// 1) Scope + authorization window + RoE – the SAME server-side chokepoint recon/SCA use.
	// A failure here is ErrForbidden and is already audited (agent.<tool>.denied).
	at, err := g.guard.Authorize(ctx, execution.Request{
		Actor:        actor,
		EngagementID: p.EngagementID,
		Action:       p.Action,
		Target:       p.Target,
		Metadata:     map[string]string{"agent_action_id": p.ID.String(), "agent_session": p.SessionID.String()},
	})
	if err != nil {
		return AdmittedAction{}, err
	}
	// 2) Human-in-the-loop approval (per mode/risk; manual ⇒ pending).
	dec, err := g.approvals.Request(ctx, p)
	if err != nil {
		return AdmittedAction{}, fmt.Errorf("approval: %w", err)
	}
	switch dec.State {
	case agent.ApprovalApproved:
		// 3) Seal the admission into the evidence chain – fail CLOSED if it cannot be
		// recorded (custody must capture every authorized AI action into the hash-chained,
		// append-only record).
		payload, _ := json.Marshal(sealedAdmission{
			ActionID: p.ID.String(), SessionID: p.SessionID.String(), Tool: p.Tool, Action: p.Action,
			Target: p.Target.Value, Argv: p.Argv, Risk: string(p.Risk), DecidedBy: dec.DecidedBy,
		})
		if _, err := g.evidence.Seal(ctx, p.EngagementID, "agent_admission", payload, actor); err != nil {
			return AdmittedAction{}, fmt.Errorf("seal admission: %w", err)
		}
		return AdmittedAction{action: p, decidedBy: dec.DecidedBy, authorizedAt: at}, nil
	case agent.ApprovalPending:
		return AdmittedAction{}, ErrPendingApproval
	default: // denied | timeout
		return AdmittedAction{}, fmt.Errorf("%w: action %s %s", shared.ErrForbidden, p.ID, dec.State)
	}
}
