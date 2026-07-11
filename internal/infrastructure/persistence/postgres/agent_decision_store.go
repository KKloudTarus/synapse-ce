package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// AgentDecisionStore is the durable ports.DecisionStore on PostgreSQL (migration 0032).
// seq is a monotonic per-session counter (MAX+1). Idempotency is enforced by
// partial unique indexes – one row per (session_id, action_id) for steps and one stop per
// session – so a redelivered drive that re-records a decision is a no-op (ON CONFLICT DO
// NOTHING), never a forked log. Decisions are written by a single driver under the session run
// lock, so the MAX+1 read/insert pair is race-free.
type AgentDecisionStore struct {
	pool *pgxpool.Pool
}

// NewAgentDecisionStore returns a Postgres-backed decision store.
func NewAgentDecisionStore(pool *pgxpool.Pool) *AgentDecisionStore {
	return &AgentDecisionStore{pool: pool}
}

var _ ports.DecisionStore = (*AgentDecisionStore)(nil)

func (s *AgentDecisionStore) AppendDecision(ctx context.Context, d agent.AgentDecision) error {
	reason, err := json.Marshal(d.Reason)
	if err != nil {
		return fmt.Errorf("marshal decision reason: %w", err)
	}
	refs, err := json.Marshal(d.Refs)
	if err != nil {
		return fmt.Errorf("marshal decision refs: %w", err)
	}
	// seq is allocated as MAX+1 then inserted. Under a parallel batch, several drivers in
	// the same session can read the same MAX+1 and collide on the (session_id, seq) PK – that is
	// NOT an idempotent re-record and must RETRY with a fresh seq (else the projection silently
	// drops a row). A collision on the partial unique indexes (same action for a step, or a
	// second stop) IS a genuine idempotent re-record → success, no retry. We distinguish by the
	// violated constraint name so a seq collision never masquerades as a dedup.
	for attempt := 0; attempt < 16; attempt++ {
		var seq int
		if err := s.pool.QueryRow(ctx,
			`SELECT COALESCE(MAX(seq), -1) + 1 FROM agent_decisions WHERE session_id=$1`, d.SessionID.String()).Scan(&seq); err != nil {
			return fmt.Errorf("next decision seq: %w", err)
		}
		_, err = s.pool.Exec(ctx,
			`INSERT INTO agent_decisions
			   (session_id, seq, engagement_id, kind, outcome, action_id, tool, action, target, risk, decided_by, stop_reason, reason, refs, created_by, created_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
			d.SessionID.String(), seq, d.EngagementID.String(), string(d.Kind), string(d.Outcome), d.ActionID.String(),
			d.Tool, d.Action, d.Target, string(d.Risk), d.DecidedBy, string(d.StopReason), reason, refs, d.CreatedBy, d.CreatedAt)
		if err == nil {
			return nil
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			switch pgErr.ConstraintName {
			case "idx_agent_decisions_step_action", "idx_agent_decisions_one_stop":
				return nil // genuine idempotent re-record (same action / second stop) – no-op
			default: // (session_id, seq) PK collision under concurrency – retry with a fresh seq
				continue
			}
		}
		return fmt.Errorf("append agent decision: %w", err)
	}
	return fmt.Errorf("append agent decision: %w: seq contention exceeded retries", shared.ErrConflict)
}

func (s *AgentDecisionStore) ListBySession(ctx context.Context, sessionID shared.ID) ([]agent.AgentDecision, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT session_id, seq, engagement_id, kind, outcome, action_id, tool, action, target, risk, decided_by, stop_reason, reason, refs, created_by, created_at
		 FROM agent_decisions WHERE session_id=$1 ORDER BY seq`, sessionID.String())
	if err != nil {
		return nil, fmt.Errorf("list agent decisions: %w", err)
	}
	defer rows.Close()
	var out []agent.AgentDecision
	for rows.Next() {
		var (
			d                         agent.AgentDecision
			kind, outcome, stopReason string
			reason, refs              []byte
		)
		if err := rows.Scan(&d.SessionID, &d.Seq, &d.EngagementID, &kind, &outcome, &d.ActionID, &d.Tool, &d.Action, &d.Target, &d.Risk, &d.DecidedBy, &stopReason, &reason, &refs, &d.CreatedBy, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan agent decision: %w", err)
		}
		d.Kind = agent.DecisionKind(kind)
		d.Outcome = agent.StepOutcome(outcome)
		d.StopReason = agent.StopReason(stopReason)
		if len(reason) > 0 {
			_ = json.Unmarshal(reason, &d.Reason)
		}
		if len(refs) > 0 {
			_ = json.Unmarshal(refs, &d.Refs)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
