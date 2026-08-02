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

// AgentPlanStore is the durable ports.PlanStore on PostgreSQL. Every operation
// binds the authenticated or durable-job tenant for eventual RLS enforcement.
type AgentPlanStore struct{ pool *pgxpool.Pool }

func NewAgentPlanStore(pool *pgxpool.Pool) *AgentPlanStore { return &AgentPlanStore{pool: pool} }

var _ ports.PlanStore = (*AgentPlanStore)(nil)

func (s *AgentPlanStore) CreatePlan(ctx context.Context, p agent.Plan) error {
	nodes, err := json.Marshal(p.Nodes)
	if err != nil {
		return fmt.Errorf("marshal plan nodes: %w", err)
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return fmt.Errorf("create agent plan: %w", shared.ErrValidation)
	}
	return WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO agent_plans (id, tenant_id, session_id, engagement_id, goal, status, revision, nodes, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, p.ID.String(), tenantID.String(), p.SessionID.String(), p.EngagementID.String(), p.Goal, string(p.Status), p.Revision, nodes, p.CreatedAt, p.UpdatedAt)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return fmt.Errorf("plan for session %s already exists: %w", p.SessionID, shared.ErrConflict)
			}
			return fmt.Errorf("create agent plan: %w", err)
		}
		return nil
	})
}

func (s *AgentPlanStore) GetBySession(ctx context.Context, sessionID shared.ID) (agent.Plan, bool, error) {
	var out agent.Plan
	found := false
	err := WithContextTenantTx(ctx, s.pool, func(tx pgx.Tx) error {
		var status string
		var nodes []byte
		err := tx.QueryRow(ctx, `SELECT id, session_id, engagement_id, goal, status, revision, nodes, created_at, updated_at FROM agent_plans WHERE session_id=$1`, sessionID.String()).Scan(&out.ID, &out.SessionID, &out.EngagementID, &out.Goal, &status, &out.Revision, &nodes, &out.CreatedAt, &out.UpdatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("get agent plan: %w", err)
		}
		out.Status, found = agent.PlanStatus(status), true
		if len(nodes) > 0 {
			if err := json.Unmarshal(nodes, &out.Nodes); err != nil {
				return fmt.Errorf("unmarshal plan nodes: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return agent.Plan{}, false, err
	}
	return out, found, nil
}

func (s *AgentPlanStore) SavePlan(ctx context.Context, p agent.Plan) error {
	nodes, err := json.Marshal(p.Nodes)
	if err != nil {
		return fmt.Errorf("marshal plan nodes: %w", err)
	}
	return WithContextTenantTx(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE agent_plans SET status=$1, revision=revision+1, nodes=$2, updated_at=now() WHERE session_id=$3 AND revision=$4`, string(p.Status), nodes, p.SessionID.String(), p.Revision)
		if err != nil {
			return fmt.Errorf("save agent plan: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("plan for session %s revision %d is stale: %w", p.SessionID, p.Revision, shared.ErrConflict)
		}
		return nil
	})
}
