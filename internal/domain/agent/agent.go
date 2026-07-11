package agent

import (
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// State is the orchestrator's typed control flow: the loop advances
// through these, the LLM only fills the "plan" (propose) slot. Control flow is Go, not
// model output.
type State string

const (
	StatePlan     State = "plan"     // ask the LLM for the next proposed tool-call
	StateValidate State = "validate" // unmarshal to typed args + scope-check (execution.Guard)
	StateApprove  State = "approve"  // HITL gate (auto/filter/manual)
	StateExecute  State = "execute"  // run the AdmittedAction via the sandboxed use-cases
	StateObserve  State = "observe"  // parse + REDACT the result before it re-enters the transcript
	StateRecord   State = "record"   // seal the step into the evidence chain
	StateReflect  State = "reflect"  // append observation; check budgets/termination; loop or finish
	StateDone     State = "done"     // terminal: goal reached / model stopped
	StateFailed   State = "failed"   // terminal: error / budget exhausted / denied-terminal
)

// validTransitions is the allowed state graph. A transition not listed here is a bug – the
// orchestrator asserts against it so the control flow can never be steered off-graph by an
// observation or a model response.
var validTransitions = map[State]map[State]bool{
	StatePlan:     {StateValidate: true, StateDone: true, StateFailed: true},
	StateValidate: {StateApprove: true, StateReflect: true, StateFailed: true}, // reflect = rejected-in-Go, fed back
	StateApprove:  {StateExecute: true, StateReflect: true, StateFailed: true}, // reflect = denied, fed back
	StateExecute:  {StateObserve: true, StateFailed: true},
	StateObserve:  {StateRecord: true, StateFailed: true},
	StateRecord:   {StateReflect: true, StateFailed: true},
	StateReflect:  {StatePlan: true, StateDone: true, StateFailed: true},
}

// CanTransition reports whether from→to is a legal orchestrator transition.
func CanTransition(from, to State) bool { return validTransitions[from][to] }

// Terminal reports whether the state ends the run.
func (s State) Terminal() bool { return s == StateDone || s == StateFailed }

// Status is the session lifecycle as persisted/queryable (distinct from the per-step State).
type Status string

const (
	StatusRunning          Status = "running"
	StatusAwaitingApproval Status = "awaiting_approval" // suspended on a manual HITL decision (survives restart)
	StatusSucceeded        Status = "succeeded"
	StatusFailed           Status = "failed"
	StatusCancelled        Status = "cancelled"
)

// Terminal reports whether the session has finished.
func (s Status) Terminal() bool {
	return s == StatusSucceeded || s == StatusFailed || s == StatusCancelled
}

// RiskClass tiers a proposed action for the HITL policy. Read is passive (subfinder/httpx/
// SBOM); Active touches live hosts (naabu); Intrusive is exploitation/credential-use/
// state-changing. ModeFilter auto-approves Read; Intrusive is ALWAYS manual regardless of
// mode (the gate enforces that – this is just the classification).
type RiskClass string

const (
	RiskRead      RiskClass = "read"
	RiskActive    RiskClass = "active"
	RiskIntrusive RiskClass = "intrusive"
)

// Session is one agent run against an engagement, initiated by a human. The transcript +
// steps are persisted (AgentSessionStore) so a run is resumable across a HITL pause/restart
// and replayable for audit. ProviderBase + Model + PromptHash pin WHAT reasoned about it.
type Session struct {
	ID             shared.ID
	EngagementID   shared.ID
	InitiatedBy    string // the human actor who started it (attribution; never an agent id)
	Goal           string
	Model          string
	ProviderBase   string // the LLM base URL (e.g. the gateway endpoint); never the API key
	PromptHash     string // sha256 of (system prompt + tool contract) – pins the reasoning context
	Status         Status
	Steps          int
	TokensUsed     int
	TokenBudgetMax int // hard cap snapshotted at creation; the orchestrator stops when TokensUsed reaches it
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// BudgetExhausted reports whether the session has spent its token budget (0 = unbounded).
func (s Session) BudgetExhausted() bool {
	return s.TokenBudgetMax > 0 && s.TokensUsed >= s.TokenBudgetMax
}

// AgentActor formats the audit/evidence attribution for an agent's own actions, kept
// distinct from a human actor (every action must be attributable to a human OR an
// agent id). Human approvals are recorded under the human's id, not this.
func (s Session) AgentActor() string { return "agent:" + s.ID.String() }

// NewSession validates + builds a session in the running state.
func NewSession(id, engagementID shared.ID, initiatedBy, goal, model, providerBase, promptHash string, now time.Time, tokenBudget int) (Session, error) {
	if id == "" || engagementID == "" {
		return Session{}, fmt.Errorf("%w: agent session needs an id + engagement", shared.ErrValidation)
	}
	if initiatedBy == "" {
		return Session{}, fmt.Errorf("%w: agent session must be initiated by a human actor (attribution)", shared.ErrValidation)
	}
	if goal == "" {
		return Session{}, fmt.Errorf("%w: agent session needs a goal", shared.ErrValidation)
	}
	return Session{
		ID: id, EngagementID: engagementID, InitiatedBy: initiatedBy, Goal: goal,
		Model: model, ProviderBase: providerBase, PromptHash: promptHash,
		Status: StatusRunning, TokenBudgetMax: tokenBudget, CreatedAt: now, UpdatedAt: now,
	}, nil
}

// ProposedAction is a single tool-call the LLM proposed, decoded into typed, scope-relevant
// fields. Argv + Target + EgressPreview ARE the diff-before-run payload shown to a human
// approver – the EXACT command and the scope it would run under. It is just a proposal: it
// has NOT been scope-validated or approved here (that yields a safety.AdmittedAction).
type ProposedAction struct {
	ID            shared.ID
	SessionID     shared.ID
	EngagementID  shared.ID
	Tool          string            // catalog tool name, e.g. "start_recon"
	Action        string            // audit verb, e.g. "recon.naabu"
	Target        engagement.Target // the typed target the call resolves to
	Argv          []string          // the exact argv that would run (diff-before-run)
	EgressPreview []string          // in-scope destinations the run would be allowed to reach
	Risk          RiskClass         // tier for the HITL policy
	Rationale     string            // the model's one-line justification (shown to the approver)
	ProposedAt    time.Time
}

// ApprovalMode is the per-engagement HITL policy. ModeManual = a human approves every
// action (the safe default); ModeFilter = auto-approve passive Read, manual for the rest;
// ModeAuto = auto Read + Active, but Intrusive is ALWAYS manual regardless of mode.
type ApprovalMode string

const (
	ModeManual ApprovalMode = "manual"
	ModeFilter ApprovalMode = "filter"
	ModeAuto   ApprovalMode = "auto"
)

// AutoApproves reports whether an action of the given risk may skip the human queue under
// this mode. Intrusive is never auto-approved (defense against confused-deputy + approval
// fatigue on the highest-risk tier).
func (m ApprovalMode) AutoApproves(risk RiskClass) bool {
	if risk == RiskIntrusive {
		return false
	}
	switch m {
	case ModeAuto:
		return true // Read + Active
	case ModeFilter:
		return risk == RiskRead
	default: // ModeManual (and any unknown mode → fail safe to manual)
		return false
	}
}

// ApprovalState is the terminal disposition of a HITL decision.
type ApprovalState string

const (
	ApprovalPending  ApprovalState = "pending"
	ApprovalApproved ApprovalState = "approved"
	ApprovalDenied   ApprovalState = "denied"
	ApprovalTimeout  ApprovalState = "timeout" // undecided within the window → fail-closed deny
)

// Admitted reports whether the decision permits execution (only an explicit human approval).
func (s ApprovalState) Admitted() bool { return s == ApprovalApproved }

// ApprovalDecision records who decided a proposed action and how. DecidedBy is the human
// actor (empty for a timeout – the system denied it). It is sealed + audited.
type ApprovalDecision struct {
	ActionID  shared.ID
	State     ApprovalState
	DecidedBy string // human actor; empty on timeout
	Reason    string
	DecidedAt time.Time
}
