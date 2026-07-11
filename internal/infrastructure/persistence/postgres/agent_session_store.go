package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// AgentSessionStore is the durable ports.AgentSessionStore on PostgreSQL:
// agent_sessions + agent_messages (migration 0027). The (session_id, seq) primary key is
// the transcript fork-guard – a duplicate seq is a unique violation → ErrConflict.
type AgentSessionStore struct {
	pool *pgxpool.Pool
}

// NewAgentSessionStore returns a Postgres-backed agent session store.
func NewAgentSessionStore(pool *pgxpool.Pool) *AgentSessionStore {
	return &AgentSessionStore{pool: pool}
}

var _ ports.AgentSessionStore = (*AgentSessionStore)(nil)

func (s *AgentSessionStore) SaveSession(ctx context.Context, e agent.Session) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO agent_sessions
		   (id, engagement_id, initiated_by, goal, model, provider_base, prompt_hash, status, steps, tokens_used, token_budget_max, created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		 ON CONFLICT (id) DO UPDATE SET
		   status=$8, steps=$9, tokens_used=$10, token_budget_max=$11, updated_at=$13`,
		e.ID.String(), e.EngagementID.String(), e.InitiatedBy, e.Goal, e.Model, e.ProviderBase, e.PromptHash,
		string(e.Status), e.Steps, e.TokensUsed, e.TokenBudgetMax, e.CreatedAt, e.UpdatedAt)
	if err != nil {
		return fmt.Errorf("save agent session: %w", err)
	}
	return nil
}

func (s *AgentSessionStore) GetSession(ctx context.Context, id shared.ID) (agent.Session, error) {
	var e agent.Session
	var status string
	err := s.pool.QueryRow(ctx,
		`SELECT id, engagement_id, initiated_by, goal, model, provider_base, prompt_hash, status, steps, tokens_used, token_budget_max, created_at, updated_at
		 FROM agent_sessions WHERE id=$1`, id.String()).
		Scan(&e.ID, &e.EngagementID, &e.InitiatedBy, &e.Goal, &e.Model, &e.ProviderBase, &e.PromptHash, &status, &e.Steps, &e.TokensUsed, &e.TokenBudgetMax, &e.CreatedAt, &e.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return agent.Session{}, fmt.Errorf("agent session %s: %w", id, shared.ErrNotFound)
	}
	if err != nil {
		return agent.Session{}, fmt.Errorf("get agent session: %w", err)
	}
	e.Status = agent.Status(status)
	return e, nil
}

func (s *AgentSessionStore) ListByEngagement(ctx context.Context, engagementID shared.ID) ([]agent.Session, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, engagement_id, initiated_by, goal, model, provider_base, prompt_hash, status, steps, tokens_used, token_budget_max, created_at, updated_at
		 FROM agent_sessions WHERE engagement_id=$1 ORDER BY created_at`, engagementID.String())
	if err != nil {
		return nil, fmt.Errorf("list agent sessions: %w", err)
	}
	defer rows.Close()
	var out []agent.Session
	for rows.Next() {
		var e agent.Session
		var status string
		if err := rows.Scan(&e.ID, &e.EngagementID, &e.InitiatedBy, &e.Goal, &e.Model, &e.ProviderBase, &e.PromptHash, &status, &e.Steps, &e.TokensUsed, &e.TokenBudgetMax, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan agent session: %w", err)
		}
		e.Status = agent.Status(status)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *AgentSessionStore) ListResumable(ctx context.Context, staleFor time.Duration, now time.Time, limit int) ([]agent.Session, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id, engagement_id, initiated_by, goal, model, provider_base, prompt_hash, status, steps, tokens_used, token_budget_max, created_at, updated_at
		 FROM agent_sessions WHERE status IN ('running','awaiting_approval') AND updated_at < $1
		 ORDER BY updated_at LIMIT $2`, now.Add(-staleFor), limit)
	if err != nil {
		return nil, fmt.Errorf("list resumable sessions: %w", err)
	}
	defer rows.Close()
	var out []agent.Session
	for rows.Next() {
		var e agent.Session
		var status string
		if err := rows.Scan(&e.ID, &e.EngagementID, &e.InitiatedBy, &e.Goal, &e.Model, &e.ProviderBase, &e.PromptHash, &status, &e.Steps, &e.TokensUsed, &e.TokenBudgetMax, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan resumable session: %w", err)
		}
		e.Status = agent.Status(status)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *AgentSessionStore) AppendMessage(ctx context.Context, sessionID shared.ID, seq int, m agent.Message) error {
	var toolCalls []byte
	if len(m.ToolCalls) > 0 {
		toolCalls, _ = json.Marshal(m.ToolCalls)
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO agent_messages (session_id, seq, role, content, tool_calls, tool_call_id)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		sessionID.String(), seq, string(m.Role), m.Content, toolCalls, m.ToolCallID)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // (session_id, seq) PK – fork guard
			return fmt.Errorf("agent message (%s, seq %d) already exists: %w", sessionID, seq, shared.ErrConflict)
		}
		return fmt.Errorf("append agent message: %w", err)
	}
	return nil
}

func (s *AgentSessionStore) Messages(ctx context.Context, sessionID shared.ID) ([]agent.Message, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT role, content, tool_calls, tool_call_id FROM agent_messages WHERE session_id=$1 ORDER BY seq`, sessionID.String())
	if err != nil {
		return nil, fmt.Errorf("list agent messages: %w", err)
	}
	defer rows.Close()
	var out []agent.Message
	for rows.Next() {
		var m agent.Message
		var role string
		var toolCalls []byte
		if err := rows.Scan(&role, &m.Content, &toolCalls, &m.ToolCallID); err != nil {
			return nil, fmt.Errorf("scan agent message: %w", err)
		}
		m.Role = agent.Role(role)
		if len(toolCalls) > 0 {
			_ = json.Unmarshal(toolCalls, &m.ToolCalls)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
