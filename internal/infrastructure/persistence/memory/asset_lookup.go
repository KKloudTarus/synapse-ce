package memory

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// GetAssetByID returns one canonical technical asset by server-issued ID. It is intentionally a
// narrow extension used by desired-state admission; the broad AssetRepository contract remains keyed
// by natural identity for normal observation/upsert flows. Invalid identifiers are validation errors;
// a valid but absent/cross-tenant asset is reported as ErrNotFound. The memory AssetStore is keyed by
// natural identity rather than ID, so duplicate canonical IDs are detected across the whole store and
// fail closed to mirror PostgreSQL's global fleet_assets primary-key invariant.
func (s *AssetStore) GetAssetByID(_ context.Context, tenantID, id shared.ID) (*asset.Asset, error) {
	if tenantID.IsZero() || id.IsZero() {
		return nil, fmt.Errorf("%w: asset id lookup needs tenant and id", shared.ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var (
		found   *asset.Asset
		matches int
	)
	for _, a := range s.assets {
		if a.ID != id {
			continue
		}
		matches++
		if matches > 1 {
			return nil, fmt.Errorf("%w: duplicate canonical asset id %s in memory asset store",
				shared.ErrValidation, id)
		}
		if a.TenantID == tenantID {
			cp := *a
			cp.Attributes = cloneMap(a.Attributes)
			found = &cp
		}
	}
	if found == nil {
		return nil, shared.ErrNotFound
	}
	return found, nil
}
