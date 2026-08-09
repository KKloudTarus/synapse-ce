package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetrollout"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const fleetRolloutCols = `tenant_id, channel, target_version, canary_groups, promoted_to_all, paused, pause_reason, updated_by, created_at, updated_at`

// FleetRolloutRepository persists operator update-rollout plans (migration 0065).
//
// Durability is the point: a plan held only in memory stops offering updates the moment the control
// plane restarts, and says nothing about why. Every method runs through WithTenant, so Row Level
// Security isolates by tenant — one tenant must never be able to read, still less move, another
// tenant's fleet.
type FleetRolloutRepository struct{ pool *pgxpool.Pool }

// NewFleetRolloutRepository constructs the Postgres rollout repository.
func NewFleetRolloutRepository(pool *pgxpool.Pool) *FleetRolloutRepository {
	return &FleetRolloutRepository{pool: pool}
}

var _ ports.FleetRolloutStore = (*FleetRolloutRepository)(nil)

// Get returns the plan for a channel, or shared.ErrNotFound when none is configured.
//
// "No row" is a legitimate resting state, not an error condition: it means no rollout is in progress
// and therefore no agent is offered anything.
func (r *FleetRolloutRepository) Get(ctx context.Context, tenantID shared.ID, channel string) (*fleetrollout.Plan, error) {
	channel = fleetrollout.NormalizeChannel(channel)
	var plan fleetrollout.Plan
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		var tenant, updatedBy string
		row := tx.QueryRow(ctx,
			`SELECT `+fleetRolloutCols+` FROM fleet_rollouts WHERE tenant_id=$1 AND channel=$2`,
			tenantID.String(), channel)
		if scanErr := row.Scan(&tenant, &plan.Channel, &plan.TargetVersion, &plan.CanaryGroups,
			&plan.PromotedToAll, &plan.Paused, &plan.PauseReason, &updatedBy,
			&plan.Audit.CreatedAt, &plan.Audit.UpdatedAt); scanErr != nil {
			return scanErr
		}
		plan.TenantID = shared.ID(tenant)
		plan.UpdatedBy = shared.ID(updatedBy)
		return nil
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("rollout plan for %q: %w", channel, shared.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("get rollout plan: %w", err)
	}
	return &plan, nil
}

// Put upserts the plan for (tenant, channel).
//
// It is an upsert rather than an insert-or-update decision at the call site because a plan is a single
// current STATE, not a history: "the fleet is moving to 1.4.0, canary first" replaces whatever came
// before it. The audit log is what carries the history of who decided what.
//
// created_at is preserved on conflict so the plan keeps the moment the rollout began, while
// updated_at moves with each operator action.
func (r *FleetRolloutRepository) Put(ctx context.Context, plan *fleetrollout.Plan) error {
	if plan == nil {
		return fmt.Errorf("%w: nil rollout plan", shared.ErrValidation)
	}
	if err := plan.Validate(); err != nil {
		return err
	}
	groups := plan.CanaryGroups
	if groups == nil {
		// A nil slice would store SQL NULL against a NOT NULL column; an empty rollout has an empty
		// canary list, not an absent one.
		groups = []string{}
	}
	err := WithTenant(ctx, r.pool, plan.TenantID.String(), func(tx pgx.Tx) error {
		_, execErr := tx.Exec(ctx, `
			INSERT INTO fleet_rollouts (`+fleetRolloutCols+`)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
			ON CONFLICT (tenant_id, channel) DO UPDATE SET
			  target_version  = EXCLUDED.target_version,
			  canary_groups   = EXCLUDED.canary_groups,
			  promoted_to_all = EXCLUDED.promoted_to_all,
			  paused          = EXCLUDED.paused,
			  pause_reason    = EXCLUDED.pause_reason,
			  updated_by      = EXCLUDED.updated_by,
			  updated_at      = EXCLUDED.updated_at`,
			plan.TenantID.String(), fleetrollout.NormalizeChannel(plan.Channel), plan.TargetVersion,
			groups, plan.PromotedToAll, plan.Paused, plan.PauseReason, plan.UpdatedBy.String(),
			plan.Audit.CreatedAt, plan.Audit.UpdatedAt)
		return execErr
	})
	if err != nil {
		return fmt.Errorf("store rollout plan: %w", err)
	}
	return nil
}
