package orchestrator

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/platform/redact"
)

// This file is the structured decision-log projection. Every recorder is a
// no-op when no DecisionStore is wired (legacy), and a recording failure is AUDITED but never
// fails the run – the evidence chain (fail-closed) is the authoritative custody record; the
// decision log is a queryable projection on top of it.

// appendDecision persists a built decision, swallowing+auditing a store error (non-fatal).
func (o *Orchestrator) appendDecision(ctx context.Context, sess agent.Session, d agent.AgentDecision, buildErr error) {
	if o.decisions == nil {
		return
	}
	if buildErr != nil {
		o.auditSessionMeta(ctx, sess, "agent.decision.build_failed", map[string]string{"error": buildErr.Error()})
		return
	}
	if err := o.decisions.AppendDecision(ctx, d); err != nil {
		o.auditSessionMeta(ctx, sess, "agent.decision.record_failed", map[string]string{"error": err.Error()})
	}
}

func (o *Orchestrator) recordExecutedDecision(ctx context.Context, sess agent.Session, prop agent.ProposedAction, decidedBy, summary string, refs agent.AgentEvidenceRefs) {
	if o.decisions == nil {
		return
	}
	reason := agent.AgentReason{WhyTool: prop.Rationale, Summary: summary} // prop.Rationale is already redacted at the catalog
	d, err := agent.NewStepDecision(sess.ID, sess.EngagementID, agent.OutcomeExecuted, prop.ID, prop.Tool, prop.Action, redact.String(prop.Target.Value, nil), prop.Risk, decidedBy, reason, refs, sess.AgentActor(), o.clock.Now())
	o.appendDecision(ctx, sess, d, err)
}

func (o *Orchestrator) recordDeniedDecision(ctx context.Context, sess agent.Session, prop agent.ProposedAction) {
	if o.decisions == nil {
		return
	}
	reason := agent.AgentReason{WhyTool: prop.Rationale, Summary: "denied by scope/authorization/approval; not executed"}
	d, err := agent.NewStepDecision(sess.ID, sess.EngagementID, agent.OutcomeDenied, prop.ID, prop.Tool, prop.Action, redact.String(prop.Target.Value, nil), prop.Risk, "", reason, agent.AgentEvidenceRefs{}, sess.AgentActor(), o.clock.Now())
	o.appendDecision(ctx, sess, d, err)
}

func (o *Orchestrator) recordReadDecision(ctx context.Context, sess agent.Session, tool string) {
	if o.decisions == nil {
		return
	}
	d, err := agent.NewStepDecision(sess.ID, sess.EngagementID, agent.OutcomeRead, "", tool, "", "", "", "", agent.AgentReason{}, agent.AgentEvidenceRefs{}, sess.AgentActor(), o.clock.Now())
	o.appendDecision(ctx, sess, d, err)
}

func (o *Orchestrator) recordErrorDecision(ctx context.Context, sess agent.Session, tool, errMsg string) {
	if o.decisions == nil {
		return
	}
	reason := agent.AgentReason{Summary: truncate(redact.String(errMsg, nil), 200)}
	d, err := agent.NewStepDecision(sess.ID, sess.EngagementID, agent.OutcomeError, "", tool, "", "", "", "", reason, agent.AgentEvidenceRefs{}, sess.AgentActor(), o.clock.Now())
	o.appendDecision(ctx, sess, d, err)
}

func (o *Orchestrator) recordStopDecision(ctx context.Context, sess agent.Session, reason agent.StopReason, summary string) {
	if o.decisions == nil {
		return
	}
	d, err := agent.NewStopDecision(sess.ID, sess.EngagementID, reason, summary, sess.AgentActor(), o.clock.Now())
	o.appendDecision(ctx, sess, d, err)
}

// admissionHash resolves the agent_admission chain link for an action by matching the sealed
// admission payload's action id, returning its hash (empty if not found / chain unreadable).
// This lets a decision reference the gate's admission without the safety package exposing it.
func (o *Orchestrator) admissionHash(ctx context.Context, engagementID, actionID shared.ID) string {
	if o.decisions == nil { // only needed for the decision projection
		return ""
	}
	items, err := o.evidence.List(ctx, engagementID)
	if err != nil {
		return ""
	}
	want := actionID.String()
	// Scan newest-first so a re-admission's latest link wins.
	for i := len(items) - 1; i >= 0; i-- {
		if items[i].Kind != "agent_admission" {
			continue
		}
		var a struct {
			ActionID string `json:"action_id"`
		}
		if json.Unmarshal(items[i].Content, &a) == nil && a.ActionID == want {
			return items[i].Hash
		}
	}
	return ""
}

// stopReasonFor maps a terminal status + the orchestrator's own (trusted) final text to a
// closed StopReason. The text prefixes are produced by overBudget / the loops, never by the
// model, so this is a safe classification (not parsing untrusted data).
func stopReasonFor(status agent.Status, finalText string) agent.StopReason {
	if status == agent.StatusSucceeded {
		return agent.StopGoalReached
	}
	switch {
	case strings.Contains(finalText, "step limit"):
		return agent.StopMaxSteps
	case strings.Contains(finalText, "token budget"):
		return agent.StopBudget
	case strings.Contains(finalText, "wall-clock"), strings.Contains(finalText, "context"):
		return agent.StopWallClock
	default:
		return agent.StopError
	}
}
