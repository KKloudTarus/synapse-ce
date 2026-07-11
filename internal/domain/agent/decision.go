package agent

import (
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// AgentDecision is the STRUCTURED, queryable record of one orchestrator decision (for
// explainability). It makes a run answerable from stored data –
// why a tool was chosen (Reason.WhyTool), why a target (Reason.WhyTarget), and why the run
// stopped (StopReason) – WITHOUT parsing prose or the (untrusted) LLM transcript. It is a
// projection ALONGSIDE the authoritative evidence chain, not a replacement: Refs link each
// decision to the chain by hash only (no content, no secrets), so a decision can always be
// tied back to the sealed `agent_step`/`agent_admission` it describes.
//
// Pure domain: imports only shared + stdlib.

// DecisionKind separates a per-step decision from the single terminal stop decision.
type DecisionKind string

const (
	DecisionStep DecisionKind = "step" // one proposed tool call resolved (executed/denied/read/error)
	DecisionStop DecisionKind = "stop" // the run terminated (exactly one per finished session)
)

// StepOutcome is how a single step resolved. It mirrors the orchestrator's internal outcome
// but is a stable, queryable, closed vocabulary.
type StepOutcome string

const (
	OutcomeExecuted StepOutcome = "executed" // admitted + ran + sealed
	OutcomeDenied   StepOutcome = "denied"   // gate denied (scope/window/RoE/human-deny); not run
	OutcomeRead     StepOutcome = "read"     // a read tool returned data
	OutcomeError    StepOutcome = "error"    // dispatch/validation error fed back
)

func (o StepOutcome) valid() bool {
	switch o {
	case OutcomeExecuted, OutcomeDenied, OutcomeRead, OutcomeError:
		return true
	default:
		return false
	}
}

// StopReason is the CLOSED set of run-termination reasons (so "why did it stop?" is always a
// known, queryable value – never free prose).
type StopReason string

const (
	StopGoalReached StopReason = "goal_reached" // the model produced a final answer (no tool call)
	StopMaxSteps    StopReason = "max_steps"    // hard step cap hit
	StopBudget      StopReason = "budget"       // token budget exhausted
	StopWallClock   StopReason = "wall_clock"   // MaxDuration / context cancelled
	StopError       StopReason = "error"        // an orchestration error failed the run
	StopPlanSettled StopReason = "plan_settled" // a plan finished (complete or failed) and was summarized
)

func (r StopReason) valid() bool {
	switch r {
	case StopGoalReached, StopMaxSteps, StopBudget, StopWallClock, StopError, StopPlanSettled:
		return true
	default:
		return false
	}
}

// AgentReason is the structured rationale for a step. WhyTool/WhyTarget come from the model's
// proposal rationale (redacted by the caller); Summary is the (redacted, capped) observation
// summary for an executed step. No raw observation bytes, no secrets.
type AgentReason struct {
	WhyTool   string `json:"why_tool,omitempty"`
	WhyTarget string `json:"why_target,omitempty"`
	Summary   string `json:"summary,omitempty"`
}

// AgentEvidenceRefs ties a decision to the custody chain by HASH ONLY (never content). An
// operator can resolve these against the evidence ledger to inspect the sealed step.
type AgentEvidenceRefs struct {
	StepHash      string `json:"step_hash,omitempty"`      // the agent_step link
	AdmissionHash string `json:"admission_hash,omitempty"` // the gate's agent_admission link
	IntentHash    string `json:"intent_hash,omitempty"`    // the pre-execution agent_intent link
}

// AgentDecision is one row in the decision log.
type AgentDecision struct {
	SessionID    shared.ID         `json:"session_id"`
	EngagementID shared.ID         `json:"engagement_id"`
	Seq          int               `json:"seq"` // monotonic per session (store-assigned)
	Kind         DecisionKind      `json:"kind"`
	Outcome      StepOutcome       `json:"outcome,omitempty"`     // step only
	ActionID     shared.ID         `json:"action_id,omitempty"`   // step only (the proposed action)
	Tool         string            `json:"tool,omitempty"`        // step only
	Action       string            `json:"action,omitempty"`      // step only (audit verb)
	Target       string            `json:"target,omitempty"`      // step only (redacted)
	Risk         RiskClass         `json:"risk,omitempty"`        // step only
	DecidedBy    string            `json:"decided_by,omitempty"`  // step only (auto / human id)
	StopReason   StopReason        `json:"stop_reason,omitempty"` // stop only
	Reason       AgentReason       `json:"reason"`
	Refs         AgentEvidenceRefs `json:"refs"`
	CreatedBy    string            `json:"created_by"` // the agent actor (agent:<sid>)
	CreatedAt    time.Time         `json:"created_at"`
}

// NewStepDecision validates + builds a per-step decision. target/reason fields must already be
// redacted by the caller (they may derive from tool output).
func NewStepDecision(sessionID, engagementID shared.ID, outcome StepOutcome, actionID shared.ID, tool, action, target string, risk RiskClass, decidedBy string, reason AgentReason, refs AgentEvidenceRefs, createdBy string, now time.Time) (AgentDecision, error) {
	if sessionID == "" || engagementID == "" {
		return AgentDecision{}, fmt.Errorf("%w: decision needs session + engagement", shared.ErrValidation)
	}
	if !outcome.valid() {
		return AgentDecision{}, fmt.Errorf("%w: unknown step outcome %q", shared.ErrValidation, outcome)
	}
	if createdBy == "" {
		return AgentDecision{}, fmt.Errorf("%w: decision needs a created_by actor", shared.ErrValidation)
	}
	return AgentDecision{
		SessionID: sessionID, EngagementID: engagementID, Kind: DecisionStep, Outcome: outcome,
		ActionID: actionID, Tool: tool, Action: action, Target: target, Risk: risk, DecidedBy: decidedBy,
		Reason: reason, Refs: refs, CreatedBy: createdBy, CreatedAt: now,
	}, nil
}

// NewStopDecision validates + builds the terminal stop decision (one per session). The
// StopReason must be a known, closed value.
func NewStopDecision(sessionID, engagementID shared.ID, reason StopReason, summary, createdBy string, now time.Time) (AgentDecision, error) {
	if sessionID == "" || engagementID == "" {
		return AgentDecision{}, fmt.Errorf("%w: decision needs session + engagement", shared.ErrValidation)
	}
	if !reason.valid() {
		return AgentDecision{}, fmt.Errorf("%w: unknown stop reason %q", shared.ErrValidation, reason)
	}
	if createdBy == "" {
		return AgentDecision{}, fmt.Errorf("%w: decision needs a created_by actor", shared.ErrValidation)
	}
	return AgentDecision{
		SessionID: sessionID, EngagementID: engagementID, Kind: DecisionStop, StopReason: reason,
		Reason: AgentReason{Summary: summary}, CreatedBy: createdBy, CreatedAt: now,
	}, nil
}
