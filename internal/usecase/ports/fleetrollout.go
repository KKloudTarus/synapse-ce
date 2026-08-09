package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetrollout"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// FleetRolloutStore persists one rollout plan per (tenant, channel).
//
// A plan is operator state, not agent state: nothing an agent reports can create or change one. Get
// returns shared.ErrNotFound when no plan exists, which is the normal resting state for a tenant with
// no rollout in progress and means no agent is offered an update.
type FleetRolloutStore interface {
	Get(ctx context.Context, tenantID shared.ID, channel string) (*fleetrollout.Plan, error)
	Put(ctx context.Context, plan *fleetrollout.Plan) error
}
