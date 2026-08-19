package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetdesired"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// FleetDesiredStore persists control-plane-owned desired capability sets for canonical host/cluster
// assets. Implementations are tenant-scoped; List is deterministically ordered by AssetID.
//
// Put is CAS by (PolicyID,Version): version 1 requires absence; later versions require the same
// PolicyID and stored version N-1. Delete requires the lifecycle PolicyID plus expectedVersion. This
// prevents both lost updates and the delete/recreate ABA race. An empty policy is represented by absence.
type FleetDesiredStore interface {
	Get(ctx context.Context, tenantID, assetID shared.ID) (*fleetdesired.State, error)
	Put(ctx context.Context, state *fleetdesired.State) error
	Delete(ctx context.Context, tenantID, assetID, expectedPolicyID shared.ID, expectedVersion int64) error
	List(ctx context.Context, tenantID shared.ID) ([]*fleetdesired.State, error)
}
