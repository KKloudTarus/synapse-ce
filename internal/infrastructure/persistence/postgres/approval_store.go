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
// approval queue (migration 0028). Decide is a guarded UPDATE (... WHERE decision_state=
// 'pending') so the first decision wins; a second hits 0 rows and returns ErrConflict.
//
// agent_approvals is RLS-protected (migration 0129). agent.ProposedAction carries no tenant of its
// own, so every statement runs under the ambient tenant bound to ctx and keys on
// (tenant_id, action_id). The guarded UPDATEs used to key on action_id alone, which meant a
// decision or a consume could be applied to another tenant's action id; the tenant is now part of
// every guard. EngagementsWithPending is the one cross-tenant read and fans out over the tenants
// table instead of scanning the queue unscoped.
type ApprovalStore struct {
	pool *pgxpool.Pool
}

// NewApprovalStore returns a Postgres-backed approval store.
func NewApprovalStore(pool *pgxpool.Pool) *ApprovalStore { return &ApprovalStore{pool: pool} }

var _ ports.ApprovalStore = (*ApprovalStore)(nil)

// approvalTenant reads the ambient tenant the RLS-protected agent_approvals statements run under.
func approvalTenant(ctx context.Context) (shared.ID, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() {
		return "", fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	return tenantID, nil
}

func (s *ApprovalStore) Enqueue(ctx context.Context, a agent.ProposedAction) error {
	tenantID, err := approvalTenant(ctx)
	if err != nil {
		return err
	}
	argv, _ := json.Marshal(a.Argv)
	egress, _ := json.Marshal(a.EgressPreview)
	return requireTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		// The engagements subselect is itself tenant-scoped by RLS, so an action naming another
		// tenant's engagement enqueues nothing rather than creating an orphan the owner can see.
		tag, err := tx.Exec(ctx,
			`INSERT INTO agent_approvals
			   (action_id, tenant_id, session_id, engagement_id, tool, action, target_kind, target_value, argv, egress_preview, risk, rationale, proposed_at, decision_state)
			 SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'pending'
			 WHERE EXISTS (SELECT 1 FROM engagements WHERE id=$4 AND tenant_id=$2)
			 ON CONFLICT (action_id) DO NOTHING`, // idempotent re-enqueue on resume
			a.ID.String(), tenantID.String(), a.SessionID.String(), a.EngagementID.String(), a.Tool, a.Action,
			string(a.Target.Kind), a.Target.Value, argv, egress, string(a.Risk), a.Rationale, a.ProposedAt)
		if err != nil {
			return fmt.Errorf("enqueue approval: %w", err)
		}
		if tag.RowsAffected() == 0 {
			// Either the action is already queued (the idempotent resume path) or the engagement
			// is not this tenant's. Distinguish them so a cross-tenant enqueue is not silent.
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent_approvals WHERE tenant_id=$1 AND action_id=$2)`, tenantID.String(), a.ID.String()).Scan(&exists); err != nil {
				return fmt.Errorf("enqueue approval: %w", err)
			}
			if !exists {
				return fmt.Errorf("engagement %s: %w", a.EngagementID, shared.ErrNotFound)
			}
		}
		return nil
	})
}

func (s *ApprovalStore) Pending(ctx context.Context, engagementID shared.ID) ([]agent.ProposedAction, error) {
	tenantID, err := approvalTenant(ctx)
	if err != nil {
		return nil, err
	}
	var out []agent.ProposedAction
	if err := requireTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT action_id, session_id, engagement_id, tool, action, target_kind, target_value, argv, egress_preview, risk, rationale, proposed_at
			 FROM agent_approvals WHERE tenant_id=$1 AND engagement_id=$2 AND decision_state='pending' ORDER BY proposed_at`,
			tenantID.String(), engagementID.String())
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
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// EngagementsWithPending is the fail-closed timeout sweeper's fan-out input. It has no ambient
// tenant, so it enumerates the tenants table and asks each tenant's partition for its pending
// engagements under a tenant-bound transaction. Each scope carries the tenant back so the caller
// binds it before sweeping, which is what keeps the rest of the sweep inside one tenant.
func (s *ApprovalStore) EngagementsWithPending(ctx context.Context) ([]ports.ApprovalSweepScope, error) {
	tenantIDs, err := listTenantIDs(ctx, s.pool, "pending approvals")
	if err != nil {
		return nil, err
	}
	var out []ports.ApprovalSweepScope
	for _, tenantID := range tenantIDs {
		if err := requireTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx,
				`SELECT DISTINCT engagement_id FROM agent_approvals WHERE tenant_id=$1 AND decision_state='pending' ORDER BY engagement_id`, tenantID.String())
			if err != nil {
				return fmt.Errorf("list engagements with pending approvals: %w", err)
			}
			defer rows.Close()
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err != nil {
					return fmt.Errorf("scan engagement id: %w", err)
				}
				out = append(out, ports.ApprovalSweepScope{TenantID: tenantID, EngagementID: shared.ID(id)})
			}
			return rows.Err()
		}); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *ApprovalStore) Get(ctx context.Context, actionID shared.ID) (agent.ProposedAction, agent.ApprovalDecision, error) {
	tenantID, err := approvalTenant(ctx)
	if err != nil {
		return agent.ProposedAction{}, agent.ApprovalDecision{}, err
	}
	var a agent.ProposedAction
	d := agent.ApprovalDecision{ActionID: actionID}
	if err := requireTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		var (
			tkind, tval             string
			argv, egress            []byte
			risk, state, by, reason string
		)
		err := tx.QueryRow(ctx,
			`SELECT action_id, session_id, engagement_id, tool, action, target_kind, target_value, argv, egress_preview, risk, rationale, proposed_at,
			        decision_state, decided_by, decision_reason, COALESCE(decided_at, to_timestamp(0))
			 FROM agent_approvals WHERE tenant_id=$1 AND action_id=$2`, tenantID.String(), actionID.String()).
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
	}); err != nil {
		return agent.ProposedAction{}, agent.ApprovalDecision{}, err
	}
	return a, d, nil
}

func (s *ApprovalStore) Decide(ctx context.Context, d agent.ApprovalDecision) error {
	tenantID, err := approvalTenant(ctx)
	if err != nil {
		return err
	}
	return requireTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE agent_approvals SET decision_state=$3, decided_by=$4, decision_reason=$5, decided_at=$6
			 WHERE tenant_id=$1 AND action_id=$2 AND decision_state='pending'`,
			tenantID.String(), d.ActionID.String(), string(d.State), d.DecidedBy, d.Reason, d.DecidedAt)
		if err != nil {
			return fmt.Errorf("decide approval: %w", err)
		}
		if tag.RowsAffected() == 0 {
			// Either it does not exist for this tenant, or it was already decided (the guarded
			// WHERE missed). The existence probe is tenant-scoped too, so another tenant's action
			// id reports not-found rather than leaking that it exists.
			var exists bool
			if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent_approvals WHERE tenant_id=$1 AND action_id=$2)`, tenantID.String(), d.ActionID.String()).Scan(&exists); e == nil && exists {
				return fmt.Errorf("approval %s already decided: %w", d.ActionID, shared.ErrConflict)
			}
			return fmt.Errorf("approval %s: %w", d.ActionID, shared.ErrNotFound)
		}
		return nil
	})
}

func (s *ApprovalStore) Consume(ctx context.Context, actionID shared.ID) error {
	tenantID, err := approvalTenant(ctx)
	if err != nil {
		return err
	}
	return requireTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE agent_approvals SET decision_state='consumed'
			 WHERE tenant_id=$1 AND action_id=$2 AND decision_state='approved'`, tenantID.String(), actionID.String())
		if err != nil {
			return fmt.Errorf("consume approval: %w", err)
		}
		if tag.RowsAffected() == 0 {
			var exists bool
			if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent_approvals WHERE tenant_id=$1 AND action_id=$2)`, tenantID.String(), actionID.String()).Scan(&exists); e == nil && exists {
				return fmt.Errorf("approval %s cannot be consumed: %w", actionID, shared.ErrConflict)
			}
			return fmt.Errorf("approval %s: %w", actionID, shared.ErrNotFound)
		}
		return nil
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
