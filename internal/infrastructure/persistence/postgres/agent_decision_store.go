package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// AgentDecisionStore persists the structured agent decision log in tenant-bound
// transactions. A durable redelivery cannot write or read another tenant's log.
type AgentDecisionStore struct{ pool *pgxpool.Pool }

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
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return fmt.Errorf("append agent decision: %w", shared.ErrValidation)
	}
	return WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		for range 16 {
			var seq int
			if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(seq), -1) + 1 FROM agent_decisions WHERE session_id=$1`, d.SessionID.String()).Scan(&seq); err != nil {
				return fmt.Errorf("next decision seq: %w", err)
			}
			_, err = tx.Exec(ctx, `INSERT INTO agent_decisions (tenant_id, session_id, seq, engagement_id, kind, outcome, action_id, tool, action, target, risk, decided_by, stop_reason, reason, refs, created_by, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`, tenantID.String(), d.SessionID.String(), seq, d.EngagementID.String(), string(d.Kind), string(d.Outcome), d.ActionID.String(), d.Tool, d.Action, d.Target, string(d.Risk), d.DecidedBy, string(d.StopReason), reason, refs, d.CreatedBy, d.CreatedAt)
			if err == nil {
				return nil
			}
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				switch pgErr.ConstraintName {
				case "idx_agent_decisions_step_action", "idx_agent_decisions_one_stop":
					return nil
				default:
					continue
				}
			}
			return fmt.Errorf("append agent decision: %w", err)
		}
		return fmt.Errorf("append agent decision: %w: seq contention exceeded retries", shared.ErrConflict)
	})
}

func (s *AgentDecisionStore) ListBySession(ctx context.Context, sessionID shared.ID) ([]agent.AgentDecision, error) {
	var out []agent.AgentDecision
	err := WithContextTenantTx(ctx, s.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT session_id, seq, engagement_id, kind, outcome, action_id, tool, action, target, risk, decided_by, stop_reason, reason, refs, created_by, created_at FROM agent_decisions WHERE session_id=$1 ORDER BY seq`, sessionID.String())
		if err != nil {
			return fmt.Errorf("list agent decisions: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var d agent.AgentDecision
			var kind, outcome, stopReason string
			var reason, refs []byte
			if err := rows.Scan(&d.SessionID, &d.Seq, &d.EngagementID, &kind, &outcome, &d.ActionID, &d.Tool, &d.Action, &d.Target, &d.Risk, &d.DecidedBy, &stopReason, &reason, &refs, &d.CreatedBy, &d.CreatedAt); err != nil {
				return fmt.Errorf("scan agent decision: %w", err)
			}
			d.Kind, d.Outcome, d.StopReason = agent.DecisionKind(kind), agent.StepOutcome(outcome), agent.StopReason(stopReason)
			if len(reason) > 0 {
				_ = json.Unmarshal(reason, &d.Reason)
			}
			if len(refs) > 0 {
				_ = json.Unmarshal(refs, &d.Refs)
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
