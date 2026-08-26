package ports

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ProcessSnapshot is the persisted, lightweight projection of a running (or exited) process entity for one
// host asset (Phase B / B5 #667 tail). It is deliberately NOT the full endpoint.ProcessEntity aggregate —
// only the fields a consumer needs to answer "what is running on this host right now" (the running side of
// running-vs-installed exposure, X5 #634): the stable A1 EntityID, the exec identity (comm/path), liveness,
// and the last-seen time. AssetID is the HOST/fleet asset the process runs on.
type ProcessSnapshot struct {
	TenantID   shared.ID
	AssetID    shared.ID
	EntityID   shared.ID
	PID        int
	Comm       string
	Path       string
	Running    bool
	LastSeenAt time.Time
}

// Validate enforces a well-formed snapshot.
func (p ProcessSnapshot) Validate() error {
	switch {
	case p.TenantID.IsZero():
		return fmt.Errorf("%w: process snapshot requires a tenant", shared.ErrValidation)
	case p.AssetID.IsZero():
		return fmt.Errorf("%w: process snapshot requires an asset id", shared.ErrValidation)
	case p.EntityID.IsZero():
		return fmt.Errorf("%w: process snapshot requires an entity id", shared.ErrValidation)
	case p.PID < 0:
		return fmt.Errorf("%w: process snapshot pid must be non-negative", shared.ErrValidation)
	}
	return nil
}

// EndpointProcessStore persists per-host process snapshots (B5). It is a MUTABLE projection keyed by
// (tenant, asset, entity) — a re-observation upserts a process in place, flipping Running to false when it
// exits — so it has no append-only trigger. Every method is tenant-scoped from the context.
type EndpointProcessStore interface {
	// SaveProcesses upserts the given snapshots idempotently by (tenant, asset, entity). Each snapshot's
	// TenantID must equal the context tenant, else it fails closed with shared.ErrValidation (no
	// cross-tenant write). Saving zero snapshots is a no-op.
	SaveProcesses(ctx context.Context, snapshots []ProcessSnapshot) error
	// ListRunningByAsset returns the currently-RUNNING process snapshots for one host asset, tenant-scoped,
	// ordered by EntityID for stability. An asset with no running processes returns an empty slice.
	ListRunningByAsset(ctx context.Context, assetID shared.ID) ([]ProcessSnapshot, error)
}
