package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ResponseStore persists governed response actions (#425): their state (for idempotency and the
// kill-switch halt set) and the approval that authorized them. Tenant-scoped through the chokepoint.
type ResponseStore interface {
	// Get returns the record for an id in the ctx tenant.
	Get(ctx context.Context, id shared.ID) (response.Record, bool, error)
	// Put upserts a record (immutable id) under the authenticated tenant.
	Put(ctx context.Context, r response.Record) error
	// ListByState returns the ctx tenant's records in a state (e.g. pending, for a kill-switch halt).
	ListByState(ctx context.Context, s response.State) ([]response.Record, error)
}
