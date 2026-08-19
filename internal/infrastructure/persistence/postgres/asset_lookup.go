package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// GetAssetByID returns one canonical technical asset by server-issued ID under tenant RLS. It is a
// narrow extension for control-plane policy admission; normal asset observation remains keyed by the
// natural (tenant, kind, key) identity. Cross-tenant and missing ids both resolve to ErrNotFound so a
// caller cannot distinguish another tenant's asset from an absent one.
func (r *AssetRepository) GetAssetByID(ctx context.Context, tenantID, id shared.ID) (*asset.Asset, error) {
	if tenantID.IsZero() || id.IsZero() {
		return nil, fmt.Errorf("%w: asset id lookup needs tenant and id", shared.ErrValidation)
	}
	var out *asset.Asset
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		var scanErr error
		out, scanErr = scanAsset(tx.QueryRow(ctx,
			`SELECT `+assetCols+` FROM fleet_assets WHERE tenant_id=$1 AND id=$2`,
			tenantID.String(), id.String()))
		return scanErr
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("asset %s: %w", id, shared.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("asset id lookup: %w", err)
	}
	if out == nil || out.TenantID != tenantID || out.ID != id {
		return nil, fmt.Errorf("%w: asset id lookup returned inconsistent identity", shared.ErrValidation)
	}
	return out, nil
}
