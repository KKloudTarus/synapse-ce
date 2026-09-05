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

// AgentPlanStore is the durable ports.PlanStore on PostgreSQL (migration 0031).
// One plan per session (session_id UNIQUE → CreatePlan on a redelivery hits a
// unique violation → ErrConflict, preventing a forked second plan). SavePlan is a guarded
// UPDATE (… WHERE revision=$expected) that bumps the revision, so a node claim is an atomic
// compare-and-swap; a lost CAS (0 rows) returns ErrConflict.
//
// agent_plans is RLS-protected (migration 0129). agent.Plan carries no tenant of its own, so every
// statement runs under the ambient tenant bound to ctx and keys on (tenant_id, session_id): a
// context without a tenant is a validation error, and a plan cannot be read or CAS-advanced from
// another tenant.
type AgentPlanStore struct {
	pool *pgxpool.Pool
}

// NewAgentPlanStore returns a Postgres-backed plan store.
func NewAgentPlanStore(pool *pgxpool.Pool) *AgentPlanStore { return &AgentPlanStore{pool: pool} }

var _ ports.PlanStore = (*AgentPlanStore)(nil)

func (s *AgentPlanStore) CreatePlan(ctx context.Context, p agent.Plan) error {
	tenantID, err := planTenant(ctx)
	if err != nil {
		return err
	}
	nodes, err := json.Marshal(p.Nodes)
	if err != nil {
		return fmt.Errorf("marshal plan nodes: %w", err)
	}
	return requireTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		// The session subselect binds the plan to a session this tenant owns, so a forged
		// session id cannot attach a plan to another tenant's run.
		tag, err := tx.Exec(ctx,
			`INSERT INTO agent_plans (id, tenant_id, session_id, engagement_id, goal, status, revision, nodes, created_at, updated_at)
			 SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10
			 WHERE EXISTS (SELECT 1 FROM agent_sessions WHERE id=$3 AND tenant_id=$2)`,
			p.ID.String(), tenantID.String(), p.SessionID.String(), p.EngagementID.String(), p.Goal, string(p.Status), p.Revision, nodes, p.CreatedAt, p.UpdatedAt)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" { // session_id UNIQUE - fork guard
				return fmt.Errorf("plan for session %s already exists: %w", p.SessionID, shared.ErrConflict)
			}
			return fmt.Errorf("create agent plan: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("agent session %s: %w", p.SessionID, shared.ErrNotFound)
		}
		return nil
	})
}

// planTenant reads the ambient tenant the RLS-protected agent_plans statements run under.
func planTenant(ctx context.Context) (shared.ID, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() {
		return "", fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	return tenantID, nil
}

func (s *AgentPlanStore) GetBySession(ctx context.Context, sessionID shared.ID) (agent.Plan, bool, error) {
	tenantID, err := planTenant(ctx)
	if err != nil {
		return agent.Plan{}, false, err
	}
	var (
		p     agent.Plan
		found bool
	)
	err = requireTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		var (
			status string
			nodes  []byte
		)
		err := tx.QueryRow(ctx,
			`SELECT id, session_id, engagement_id, goal, status, revision, nodes, created_at, updated_at
			 FROM agent_plans WHERE tenant_id=$1 AND session_id=$2`, tenantID.String(), sessionID.String()).
			Scan(&p.ID, &p.SessionID, &p.EngagementID, &p.Goal, &status, &p.Revision, &nodes, &p.CreatedAt, &p.UpdatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("get agent plan: %w", err)
		}
		p.Status = agent.PlanStatus(status)
		if len(nodes) > 0 {
			if err := json.Unmarshal(nodes, &p.Nodes); err != nil {
				return fmt.Errorf("unmarshal plan nodes: %w", err)
			}
		}
		found = true
		return nil
	})
	if err != nil {
		return agent.Plan{}, false, err
	}
	if !found {
		return agent.Plan{}, false, nil
	}
	return p, true, nil
}

func (s *AgentPlanStore) SavePlan(ctx context.Context, p agent.Plan) error {
	tenantID, err := planTenant(ctx)
	if err != nil {
		return err
	}
	nodes, err := json.Marshal(p.Nodes)
	if err != nil {
		return fmt.Errorf("marshal plan nodes: %w", err)
	}
	return requireTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE agent_plans SET status=$1, revision=revision+1, nodes=$2, updated_at=now()
			 WHERE tenant_id=$3 AND session_id=$4 AND revision=$5`,
			string(p.Status), nodes, tenantID.String(), p.SessionID.String(), p.Revision)
		if err != nil {
			return fmt.Errorf("save agent plan: %w", err)
		}
		if tag.RowsAffected() == 0 {
			// Either the row is gone, it belongs to another tenant, or another driver advanced the
			// revision first - all mean this driver's view is stale and must reload
			// (lost-update guard / node-claim CAS).
			return fmt.Errorf("plan for session %s revision %d is stale: %w", p.SessionID, p.Revision, shared.ErrConflict)
		}
		return nil
	})
}
