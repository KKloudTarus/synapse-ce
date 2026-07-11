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
type AgentPlanStore struct {
	pool *pgxpool.Pool
}

// NewAgentPlanStore returns a Postgres-backed plan store.
func NewAgentPlanStore(pool *pgxpool.Pool) *AgentPlanStore { return &AgentPlanStore{pool: pool} }

var _ ports.PlanStore = (*AgentPlanStore)(nil)

func (s *AgentPlanStore) CreatePlan(ctx context.Context, p agent.Plan) error {
	nodes, err := json.Marshal(p.Nodes)
	if err != nil {
		return fmt.Errorf("marshal plan nodes: %w", err)
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO agent_plans (id, session_id, engagement_id, goal, status, revision, nodes, created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		p.ID.String(), p.SessionID.String(), p.EngagementID.String(), p.Goal, string(p.Status), p.Revision, nodes, p.CreatedAt, p.UpdatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // session_id UNIQUE – fork guard
			return fmt.Errorf("plan for session %s already exists: %w", p.SessionID, shared.ErrConflict)
		}
		return fmt.Errorf("create agent plan: %w", err)
	}
	return nil
}

func (s *AgentPlanStore) GetBySession(ctx context.Context, sessionID shared.ID) (agent.Plan, bool, error) {
	var (
		p      agent.Plan
		status string
		nodes  []byte
	)
	err := s.pool.QueryRow(ctx,
		`SELECT id, session_id, engagement_id, goal, status, revision, nodes, created_at, updated_at
		 FROM agent_plans WHERE session_id=$1`, sessionID.String()).
		Scan(&p.ID, &p.SessionID, &p.EngagementID, &p.Goal, &status, &p.Revision, &nodes, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return agent.Plan{}, false, nil
	}
	if err != nil {
		return agent.Plan{}, false, fmt.Errorf("get agent plan: %w", err)
	}
	p.Status = agent.PlanStatus(status)
	if len(nodes) > 0 {
		if err := json.Unmarshal(nodes, &p.Nodes); err != nil {
			return agent.Plan{}, false, fmt.Errorf("unmarshal plan nodes: %w", err)
		}
	}
	return p, true, nil
}

func (s *AgentPlanStore) SavePlan(ctx context.Context, p agent.Plan) error {
	nodes, err := json.Marshal(p.Nodes)
	if err != nil {
		return fmt.Errorf("marshal plan nodes: %w", err)
	}
	tag, err := s.pool.Exec(ctx,
		`UPDATE agent_plans SET status=$1, revision=revision+1, nodes=$2, updated_at=now()
		 WHERE session_id=$3 AND revision=$4`,
		string(p.Status), nodes, p.SessionID.String(), p.Revision)
	if err != nil {
		return fmt.Errorf("save agent plan: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Either the row is gone or another driver advanced the revision first – both mean this
		// driver's view is stale and must reload (lost-update guard / node-claim CAS).
		return fmt.Errorf("plan for session %s revision %d is stale: %w", p.SessionID, p.Revision, shared.ErrConflict)
	}
	return nil
}
