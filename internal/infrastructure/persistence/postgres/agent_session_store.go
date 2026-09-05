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
// the transcript fork-guard - a duplicate seq is a unique violation, reported as ErrConflict.
//
// agent_sessions is RLS-protected (migration 0129), so every statement runs inside a WithTenant
// transaction and keeps its explicit tenant_id predicate. agent_messages has no tenant column of
// its own; it is reached only through a join or subselect on agent_sessions, which the policy
// scopes. ListResumable is the one cross-tenant read: it fans out over the tenants table (which
// is not RLS-protected) and runs one tenant-bound query per tenant.
type AgentSessionStore struct {
	pool *pgxpool.Pool
}

// NewAgentSessionStore returns a Postgres-backed agent session store.
func NewAgentSessionStore(pool *pgxpool.Pool) *AgentSessionStore {
	return &AgentSessionStore{pool: pool}
}

var _ ports.AgentSessionStore = (*AgentSessionStore)(nil)

func (s *AgentSessionStore) SaveSession(ctx context.Context, e agent.Session) error {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || e.TenantID != tenantID {
		return fmt.Errorf("%w: agent session tenant context is required and must match", shared.ErrValidation)
	}
	return requireTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`INSERT INTO agent_sessions
			   (id, tenant_id, engagement_id, initiated_by, goal, model, provider_base, prompt_hash, status, steps, tokens_used, token_budget_max, created_at, updated_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
			 ON CONFLICT (id) DO UPDATE SET
			   status=$9, steps=$10, tokens_used=$11, token_budget_max=$12, updated_at=$14
			 WHERE agent_sessions.tenant_id=$2 AND agent_sessions.engagement_id=$3`,
			e.ID.String(), tenantID.String(), e.EngagementID.String(), e.InitiatedBy, e.Goal, e.Model, e.ProviderBase, e.PromptHash,
			string(e.Status), e.Steps, e.TokensUsed, e.TokenBudgetMax, e.CreatedAt, e.UpdatedAt)
		if err != nil {
			return fmt.Errorf("save agent session: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("agent session %s belongs to another tenant or engagement: %w", e.ID, shared.ErrConflict)
		}
		return nil
	})
}

func (s *AgentSessionStore) GetSession(ctx context.Context, id shared.ID) (agent.Session, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return agent.Session{}, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	var e agent.Session
	if err := requireTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		var status string
		err := tx.QueryRow(ctx,
			`SELECT id, tenant_id, engagement_id, initiated_by, goal, model, provider_base, prompt_hash, status, steps, tokens_used, token_budget_max, created_at, updated_at
			 FROM agent_sessions WHERE id=$1 AND tenant_id=$2`, id.String(), tenantID.String()).
			Scan(&e.ID, &e.TenantID, &e.EngagementID, &e.InitiatedBy, &e.Goal, &e.Model, &e.ProviderBase, &e.PromptHash, &status, &e.Steps, &e.TokensUsed, &e.TokenBudgetMax, &e.CreatedAt, &e.UpdatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("agent session %s: %w", id, shared.ErrNotFound)
		}
		if err != nil {
			return fmt.Errorf("get agent session: %w", err)
		}
		e.Status = agent.Status(status)
		return nil
	}); err != nil {
		return agent.Session{}, err
	}
	return e, nil
}

func (s *AgentSessionStore) ListByEngagement(ctx context.Context, engagementID shared.ID) ([]agent.Session, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return nil, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	var out []agent.Session
	if err := requireTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, engagement_id, initiated_by, goal, model, provider_base, prompt_hash, status, steps, tokens_used, token_budget_max, created_at, updated_at
			 FROM agent_sessions WHERE tenant_id=$1 AND engagement_id=$2 ORDER BY created_at`, tenantID.String(), engagementID.String())
		if err != nil {
			return fmt.Errorf("list agent sessions: %w", err)
		}
		defer rows.Close()
		sessions, err := scanAgentSessions(rows)
		if err != nil {
			return err
		}
		out = sessions
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// scanAgentSessions drains a session projection in the column order shared by every session query.
func scanAgentSessions(rows pgx.Rows) ([]agent.Session, error) {
	var out []agent.Session
	for rows.Next() {
		var e agent.Session
		var status string
		if err := rows.Scan(&e.ID, &e.TenantID, &e.EngagementID, &e.InitiatedBy, &e.Goal, &e.Model, &e.ProviderBase, &e.PromptHash, &status, &e.Steps, &e.TokensUsed, &e.TokenBudgetMax, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan agent session: %w", err)
		}
		e.Status = agent.Status(status)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListResumable is the startup reconciler's cross-tenant sweep, so it has no ambient tenant to run
// under. Rather than reading agent_sessions unscoped, it enumerates the tenants table (global
// reference data, not RLS-protected) and runs one tenant-bound query per tenant, exactly as the
// job queue's Claim and the engagement repository's reconciliation scan do. The caller binds each
// returned session's own tenant before acting on it.
func (s *AgentSessionStore) ListResumable(ctx context.Context, staleFor time.Duration, now time.Time, limit int) ([]agent.Session, error) {
	if limit <= 0 {
		limit = 100
	}
	tenantIDs, err := listTenantIDs(ctx, s.pool, "resumable agent sessions")
	if err != nil {
		return nil, err
	}
	var out []agent.Session
	cutoff := now.Add(-staleFor)
	for _, tenantID := range tenantIDs {
		if len(out) >= limit {
			break
		}
		remaining := limit - len(out)
		if err := requireTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx,
				`SELECT id, tenant_id, engagement_id, initiated_by, goal, model, provider_base, prompt_hash, status, steps, tokens_used, token_budget_max, created_at, updated_at
				 FROM agent_sessions WHERE tenant_id=$1 AND status IN ('running','awaiting_approval') AND updated_at < $2
				 ORDER BY updated_at LIMIT $3`, tenantID.String(), cutoff, remaining)
			if err != nil {
				return fmt.Errorf("list resumable sessions: %w", err)
			}
			defer rows.Close()
			sessions, err := scanAgentSessions(rows)
			if err != nil {
				return err
			}
			out = append(out, sessions...)
			return nil
		}); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *AgentSessionStore) AppendMessage(ctx context.Context, sessionID shared.ID, seq int, m agent.Message) error {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	var toolCalls []byte
	if len(m.ToolCalls) > 0 {
		toolCalls, _ = json.Marshal(m.ToolCalls)
	}
	return requireTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`INSERT INTO agent_messages (session_id, seq, role, content, tool_calls, tool_call_id)
			 SELECT $1,$2,$3,$4,$5,$6 FROM agent_sessions WHERE id=$1 AND tenant_id=$7`,
			sessionID.String(), seq, string(m.Role), m.Content, toolCalls, m.ToolCallID, tenantID.String())
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" { // (session_id, seq) PK - fork guard
				return fmt.Errorf("agent message (%s, seq %d) already exists: %w", sessionID, seq, shared.ErrConflict)
			}
			return fmt.Errorf("append agent message: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("agent session %s: %w", sessionID, shared.ErrNotFound)
		}
		return nil
	})
}

func (s *AgentSessionStore) Messages(ctx context.Context, sessionID shared.ID) ([]agent.Message, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return nil, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	var out []agent.Message
	if err := requireTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT m.role, m.content, m.tool_calls, m.tool_call_id
			 FROM agent_messages m JOIN agent_sessions s ON s.id=m.session_id
			 WHERE m.session_id=$1 AND s.tenant_id=$2 ORDER BY m.seq`, sessionID.String(), tenantID.String())
		if err != nil {
			return fmt.Errorf("list agent messages: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var m agent.Message
			var role string
			var toolCalls []byte
			if err := rows.Scan(&role, &m.Content, &toolCalls, &m.ToolCallID); err != nil {
				return fmt.Errorf("scan agent message: %w", err)
			}
			m.Role = agent.Role(role)
			if len(toolCalls) > 0 {
				_ = json.Unmarshal(toolCalls, &m.ToolCalls)
			}
			out = append(out, m)
		}
		return rows.Err()
	}); err != nil {
		return nil, err
	}
	return out, nil
}
