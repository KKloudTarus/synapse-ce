package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// AssetRepository is the Postgres-backed fleet asset model. It is the first store to route every
// operation through WithTenant, so the Row Level Security policies on fleet_assets,
// fleet_asset_edges and fleet_business_services (migration 0058, using the 0057 procedure) enforce
// tenant isolation at the database. A query that bypassed WithTenant would resolve the tenant to
// NULL and see nothing.
type AssetRepository struct{ pool *pgxpool.Pool }

// NewAssetRepository constructs the Postgres asset repository.
func NewAssetRepository(pool *pgxpool.Pool) *AssetRepository { return &AssetRepository{pool: pool} }

var _ ports.AssetRepository = (*AssetRepository)(nil)

const assetCols = `id, tenant_id, kind, "key", name, attributes, created_at, updated_at`

// UpsertAsset inserts or updates by the (tenant_id, kind, key) natural key, preserving the id and
// created_at of an existing row so re-observation does not churn identity.
func (r *AssetRepository) UpsertAsset(ctx context.Context, a *asset.Asset) error {
	attrs, err := json.Marshal(a.Attributes)
	if err != nil {
		return fmt.Errorf("asset: marshal attributes: %w", err)
	}
	return WithTenant(ctx, r.pool, a.TenantID.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO fleet_assets (`+assetCols+`)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (tenant_id, kind, "key") DO UPDATE
			SET name = EXCLUDED.name, attributes = EXCLUDED.attributes, updated_at = EXCLUDED.updated_at`,
			a.ID.String(), a.TenantID.String(), string(a.Kind), a.Key, a.Name, attrs,
			a.Audit.CreatedAt, a.Audit.UpdatedAt)
		return err
	})
}

// GetAssetByKey returns the asset for (tenantID, kind, key) or shared.ErrNotFound.
func (r *AssetRepository) GetAssetByKey(ctx context.Context, tenantID shared.ID, kind asset.Kind, key string) (*asset.Asset, error) {
	var out *asset.Asset
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		a, e := scanAsset(tx.QueryRow(ctx, `SELECT `+assetCols+` FROM fleet_assets WHERE tenant_id = $1 AND kind = $2 AND "key" = $3`,
			tenantID.String(), string(kind), key))
		if e != nil {
			return e
		}
		out = a
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ListAssets returns the tenant's assets ordered by (kind, key).
func (r *AssetRepository) ListAssets(ctx context.Context, tenantID shared.ID) ([]*asset.Asset, error) {
	var out []*asset.Asset
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT `+assetCols+` FROM fleet_assets WHERE tenant_id = $1 ORDER BY kind, "key"`, tenantID.String())
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			a, e := scanAsset(rows)
			if e != nil {
				return e
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// UpsertEdge inserts the edge idempotently by its full natural key.
func (r *AssetRepository) UpsertEdge(ctx context.Context, e *asset.Edge) error {
	return WithTenant(ctx, r.pool, e.TenantID.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO fleet_asset_edges (tenant_id, from_asset, to_asset, kind, provenance)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (tenant_id, from_asset, to_asset, kind, provenance) DO NOTHING`,
			e.TenantID.String(), e.From.String(), e.To.String(), string(e.Kind), e.Provenance.String())
		return err
	})
}

// ListEdges returns the tenant's edges ordered by (from, to, kind, provenance).
func (r *AssetRepository) ListEdges(ctx context.Context, tenantID shared.ID) ([]*asset.Edge, error) {
	var out []*asset.Edge
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `
			SELECT tenant_id, from_asset, to_asset, kind, provenance FROM fleet_asset_edges
			WHERE tenant_id = $1 ORDER BY from_asset, to_asset, kind, provenance`, tenantID.String())
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var tid, from, to, kind, prov string
			if e := rows.Scan(&tid, &from, &to, &kind, &prov); e != nil {
				return e
			}
			out = append(out, &asset.Edge{
				TenantID:   shared.ID(tid),
				From:       shared.ID(from),
				To:         shared.ID(to),
				Kind:       asset.EdgeKind(kind),
				Provenance: shared.ID(prov),
			})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// UpsertBusinessService inserts or updates by (tenant_id, name), preserving id and created_at.
func (r *AssetRepository) UpsertBusinessService(ctx context.Context, s *asset.BusinessService) error {
	return WithTenant(ctx, r.pool, s.TenantID.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO fleet_business_services (id, tenant_id, name, owner, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (tenant_id, name) DO UPDATE
			SET owner = EXCLUDED.owner, updated_at = EXCLUDED.updated_at`,
			s.ID.String(), s.TenantID.String(), s.Name, s.Owner, s.Audit.CreatedAt, s.Audit.UpdatedAt)
		return err
	})
}

// GetBusinessServiceByName returns the service for (tenantID, name) or shared.ErrNotFound.
func (r *AssetRepository) GetBusinessServiceByName(ctx context.Context, tenantID shared.ID, name string) (*asset.BusinessService, error) {
	var out *asset.BusinessService
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		s, e := scanBusinessService(tx.QueryRow(ctx,
			`SELECT id, tenant_id, name, owner, created_at, updated_at FROM fleet_business_services WHERE tenant_id = $1 AND name = $2`,
			tenantID.String(), name))
		if e != nil {
			return e
		}
		out = s
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ListBusinessServices returns the tenant's services ordered by name.
func (r *AssetRepository) ListBusinessServices(ctx context.Context, tenantID shared.ID) ([]*asset.BusinessService, error) {
	var out []*asset.BusinessService
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx,
			`SELECT id, tenant_id, name, owner, created_at, updated_at FROM fleet_business_services WHERE tenant_id = $1 ORDER BY name`,
			tenantID.String())
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			s, e := scanBusinessService(rows)
			if e != nil {
				return e
			}
			out = append(out, s)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func scanAsset(row rowScanner) (*asset.Asset, error) {
	var (
		id, tid, kind, key, name string
		attrs                    []byte
		a                        asset.Asset
	)
	if err := row.Scan(&id, &tid, &kind, &key, &name, &attrs, &a.Audit.CreatedAt, &a.Audit.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, err
	}
	a.ID = shared.ID(id)
	a.TenantID = shared.ID(tid)
	a.Kind = asset.Kind(kind)
	a.Key = key
	a.Name = name
	a.Attributes = map[string]string{}
	if len(attrs) > 0 {
		if err := json.Unmarshal(attrs, &a.Attributes); err != nil {
			return nil, fmt.Errorf("asset: unmarshal attributes: %w", err)
		}
	}
	return &a, nil
}

func scanBusinessService(row rowScanner) (*asset.BusinessService, error) {
	var id, tid, name, owner string
	var s asset.BusinessService
	if err := row.Scan(&id, &tid, &name, &owner, &s.Audit.CreatedAt, &s.Audit.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, err
	}
	s.ID = shared.ID(id)
	s.TenantID = shared.ID(tid)
	s.Name = name
	s.Owner = owner
	return &s, nil
}
