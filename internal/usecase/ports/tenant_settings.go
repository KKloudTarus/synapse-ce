package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
)

// TenantSettingsStore persists one tenancy.Settings row per tenant (#1359).
//
// GetTenantSettings reports found=false, not an error, for a tenant that never saved settings.
// SaveTenantSettings writes s when the stored revision equals expectedRevision (0 means "no row
// yet") and returns the stored settings with the next revision; a mismatch is shared.ErrConflict.
type TenantSettingsStore interface {
	GetTenantSettings(ctx context.Context, tenant shared.ID) (s tenancy.Settings, found bool, err error)
	SaveTenantSettings(ctx context.Context, s tenancy.Settings, expectedRevision int) (tenancy.Settings, error)
}
