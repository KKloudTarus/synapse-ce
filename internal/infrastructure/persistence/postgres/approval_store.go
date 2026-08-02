package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ApprovalStore is the durable ports.ApprovalStore on PostgreSQL: the HITL
// approval queue (migration 0028). Decide is a guarded UPDATE (… WHERE decision_state=
// 'pending') so the first decision wins; a second hits 0 rows and returns ErrConflict.
type ApprovalStore struct {
	pool *pgxpool.Pool
}

// NewApprovalStore returns a Postgres-backed approval store.
func NewApprovalStore(pool *pgxpool.Pool) *ApprovalStore { return &ApprovalStore{pool: pool} }

var _ ports.ApprovalStore = (*ApprovalStore)(nil)

func (s *ApprovalStore) Enqueue(ctx context.Context, a agent.ProposedAction) error {
	argv, _ := json.Marshal(a.Argv)
	egress, _ := json.Marshal(a.EgressPreview)
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return fmt.Errorf("enqueue approval: %w", shared.ErrValidation)
	}
	return WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO agent_approvals
			   (action_id, tenant_id, session_id, engagement_id, tool, action, target_kind, target_value, argv, egress_preview, risk, rationale, proposed_at, decision_state)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'pending')
			 ON CONFLICT (action_id) DO NOTHING`,
			a.ID.String(), tenantID.String(), a.SessionID.String(), a.EngagementID.String(), a.Tool, a.Action,
			string(a.Target.Kind), a.Target.Value, argv, egress, string(a.Risk), a.Rationale, a.ProposedAt)
		if err != nil {
			return fmt.Errorf("enqueue approval: %w", err)
		}
		return nil
	})
}

func (s *ApprovalStore) Pending(ctx context.Context, engagementID shared.ID) ([]agent.ProposedAction, error) {
	var out []agent.ProposedAction
	err := WithContextTenantTx(ctx, s.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT action_id, session_id, engagement_id, tool, action, target_kind, target_value, argv, egress_preview, risk, rationale, proposed_at
			 FROM agent_approvals WHERE engagement_id=$1 AND decision_state='pending' ORDER BY proposed_at`, engagementID.String())
		if err != nil {
			return fmt.Errorf("list pending approvals: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			a, err := scanProposed(rows)
			if err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *ApprovalStore) EngagementsWithPending(ctx context.Context) ([]shared.ID, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT DISTINCT engagement_id FROM agent_approvals WHERE decision_state='pending' ORDER BY engagement_id`)
	if err != nil {
		return nil, fmt.Errorf("list engagements with pending approvals: %w", err)
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan engagement id: %w", err)
		}
		out = append(out, shared.ID(id))
	}
	return out, rows.Err()
}

func (s *ApprovalStore) Get(ctx context.Context, actionID shared.ID) (agent.ProposedAction, agent.ApprovalDecision, error) {
	var a agent.ProposedAction
	d := agent.ApprovalDecision{ActionID: actionID}
	err := WithContextTenantTx(ctx, s.pool, func(tx pgx.Tx) error {
		var tkind, tval string
		var argv, egress []byte
		var risk, state, by, reason string
		err := tx.QueryRow(ctx,
			`SELECT action_id, session_id, engagement_id, tool, action, target_kind, target_value, argv, egress_preview, risk, rationale, proposed_at,
			        decision_state, decided_by, decision_reason, COALESCE(decided_at, to_timestamp(0))
			 FROM agent_approvals WHERE action_id=$1`, actionID.String()).
			Scan(&a.ID, &a.SessionID, &a.EngagementID, &a.Tool, &a.Action, &tkind, &tval, &argv, &egress, &risk, &a.Rationale, &a.ProposedAt,
				&state, &by, &reason, &d.DecidedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("approval %s: %w", actionID, shared.ErrNotFound)
		}
		if err != nil {
			return fmt.Errorf("get approval: %w", err)
		}
		a.Target = engagement.Target{Kind: engagement.TargetKind(tkind), Value: tval}
		a.Risk = agent.RiskClass(risk)
		_ = json.Unmarshal(argv, &a.Argv)
		_ = json.Unmarshal(egress, &a.EgressPreview)
		d.State, d.DecidedBy, d.Reason = agent.ApprovalState(state), by, reason
		return nil
	})
	if err != nil {
		return agent.ProposedAction{}, agent.ApprovalDecision{}, err
	}
	return a, d, nil
}

func (s *ApprovalStore) Decide(ctx context.Context, d agent.ApprovalDecision) error {
	return WithContextTenantTx(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE agent_approvals SET decision_state=$2, decided_by=$3, decision_reason=$4, decided_at=$5
			 WHERE action_id=$1 AND decision_state='pending'`,
			d.ActionID.String(), string(d.State), d.DecidedBy, d.Reason, d.DecidedAt)
		if err != nil {
			return fmt.Errorf("decide approval: %w", err)
		}
		if tag.RowsAffected() != 0 {
			return nil
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent_approvals WHERE action_id=$1)`, d.ActionID.String()).Scan(&exists); err != nil {
			return fmt.Errorf("check approval: %w", err)
		}
		if exists {
			return fmt.Errorf("approval %s already decided: %w", d.ActionID, shared.ErrConflict)
		}
		return fmt.Errorf("approval %s: %w", d.ActionID, shared.ErrNotFound)
	})
}

func scanProposed(rows pgx.Rows) (agent.ProposedAction, error) {
	var (
		a            agent.ProposedAction
		tkind, tval  string
		argv, egress []byte
		risk         string
	)
	if err := rows.Scan(&a.ID, &a.SessionID, &a.EngagementID, &a.Tool, &a.Action, &tkind, &tval, &argv, &egress, &risk, &a.Rationale, &a.ProposedAt); err != nil {
		return agent.ProposedAction{}, fmt.Errorf("scan approval: %w", err)
	}
	a.Target = engagement.Target{Kind: engagement.TargetKind(tkind), Value: tval}
	a.Risk = agent.RiskClass(risk)
	_ = json.Unmarshal(argv, &a.Argv)
	_ = json.Unmarshal(egress, &a.EgressPreview)
	return a, nil
}
