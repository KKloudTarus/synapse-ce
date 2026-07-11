package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// AgentSessionStore persists agent sessions + their transcripts so a run is
// resumable across a HITL pause/restart and replayable for audit. Messages are appended by
// monotonic seq; the store rejects a duplicate (sessionID, seq) so a redelivery cannot fork
// a transcript (mirrors the evidence chain's fork-guard). A Postgres + an in-memory adapter
// implement it; the migration adds agent_sessions + agent_messages.
type AgentSessionStore interface {
	SaveSession(ctx context.Context, s agent.Session) error // upsert (status/steps/tokens advance)
	GetSession(ctx context.Context, id shared.ID) (agent.Session, error)
	ListByEngagement(ctx context.Context, engagementID shared.ID) ([]agent.Session, error)
	AppendMessage(ctx context.Context, sessionID shared.ID, seq int, m agent.Message) error
	Messages(ctx context.Context, sessionID shared.ID) ([]agent.Message, error)
	// ListResumable returns non-terminal sessions (running / awaiting_approval) not updated
	// since now-staleFor, oldest first, capped at limit – the startup reconciler's input for
	// re-driving sessions a crash stranded.
	ListResumable(ctx context.Context, staleFor time.Duration, now time.Time, limit int) ([]agent.Session, error)
}

// ApprovalStore is the durable HITL approval queue. A proposed action is Enqueued
// (pending); a human Decide()s it; a background timeout flips an undecided action to a
// fail-closed denied (timeout). Decide is idempotent – the first decision wins, a second
// returns ErrConflict – so a double-click / race cannot re-open an admitted action.
type ApprovalStore interface {
	Enqueue(ctx context.Context, a agent.ProposedAction) error
	Pending(ctx context.Context, engagementID shared.ID) ([]agent.ProposedAction, error)
	// Get returns the proposed action and its current decision (state ApprovalPending until decided).
	Get(ctx context.Context, actionID shared.ID) (agent.ProposedAction, agent.ApprovalDecision, error)
	Decide(ctx context.Context, d agent.ApprovalDecision) error
	// EngagementsWithPending lists the engagements that have at least one pending approval –
	// so the prod timeout sweeper can fan out across them without a global scan.
	EngagementsWithPending(ctx context.Context) ([]shared.ID, error)
}

// PlanStore persists an agent session's execution plan.
// One plan per session (CreatePlan enforces uniqueness so a redelivered Drive cannot fork a
// second plan). SavePlan is an optimistic-concurrency UPDATE: it applies only if the stored
// revision still equals the plan's revision (lost-update guard), and a stale revision returns
// shared.ErrConflict. That CAS is the durable idempotency authority for a node claim – a
// redelivered or concurrent driver that loses the CAS cannot double-run a node. A Postgres + an
// in-memory adapter implement it; migration 0031 adds agent_plans.
type PlanStore interface {
	CreatePlan(ctx context.Context, p agent.Plan) error
	// GetBySession returns the session's plan; found=false (nil error) when none exists.
	GetBySession(ctx context.Context, sessionID shared.ID) (agent.Plan, bool, error)
	// SavePlan persists node/status changes iff the stored revision still matches p.Revision,
	// then bumps the stored revision. On a mismatch it returns shared.ErrConflict (the caller
	// reloads + reapplies). On success the caller increments its in-memory p.Revision to match.
	SavePlan(ctx context.Context, p agent.Plan) error
}

// DecisionStore persists the structured agent decision log:
// one row per orchestrator step (executed/denied/read/error) plus one terminal stop row. It is
// a queryable projection ALONGSIDE the authoritative evidence chain – a decision's Refs link to
// the chain by hash only. AppendDecision assigns a monotonic per-session seq and is idempotent
// (a re-recorded step keyed on (session_id, action_id), and a single stop per session) so a
// redelivered drive cannot fork the log. A Postgres + an in-memory adapter implement it;
// migration 0032 adds agent_decisions.
type DecisionStore interface {
	AppendDecision(ctx context.Context, d agent.AgentDecision) error
	ListBySession(ctx context.Context, sessionID shared.ID) ([]agent.AgentDecision, error)
}
