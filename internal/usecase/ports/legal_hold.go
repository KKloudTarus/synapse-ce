package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/legalhold"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// LegalHoldStore persists legal holds (#635). All methods are tenant-scoped from ctx. Place is idempotent
// per (tenant, engagement) active hold; Release closes the active hold; IsHeld is the hot-path guard the
// retention deletion consults before expiring anything.
type LegalHoldStore interface {
	// Place records an active hold on the engagement. Placing when one is already active returns the
	// existing hold (idempotent), so a re-place is safe.
	Place(ctx context.Context, h legalhold.Hold) (legalhold.Hold, error)
	// Release closes the active hold on the engagement (no-op if none active). releasedBy + at attribute it.
	Release(ctx context.Context, engagementID shared.ID, releasedBy string, at time.Time) error
	// IsHeld reports whether the engagement currently has an ACTIVE hold (tenant-scoped).
	IsHeld(ctx context.Context, engagementID shared.ID) (bool, error)
	// ListActive returns the tenant's currently-active holds.
	ListActive(ctx context.Context) ([]legalhold.Hold, error)
}
