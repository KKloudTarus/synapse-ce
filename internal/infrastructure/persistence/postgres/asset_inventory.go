package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type AssetInventoryRepository struct{ pool *pgxpool.Pool }

func NewAssetInventoryRepository(pool *pgxpool.Pool) *AssetInventoryRepository {
	return &AssetInventoryRepository{pool: pool}
}

var _ ports.AssetInventoryRepository = (*AssetInventoryRepository)(nil)

const assetColumns = `id, tenant_id, name, category, identity_kind, identity_value, lifecycle, criticality, exposure, classification, version, created_at, updated_at, created_by, updated_by`

func requireInventoryTenant(ctx context.Context, tenantID shared.ID) error {
	currentTenant, ok := shared.TenantFrom(ctx)
	if !ok || currentTenant != tenantID {
		return fmt.Errorf("%w: tenant-scoped inventory command", shared.ErrValidation)
	}
	return nil
}

func (r *AssetInventoryRepository) CreateAsset(ctx context.Context, a asset.Asset) error {
	if err := a.Validate(); err != nil {
		return err
	}
	if err := requireInventoryTenant(ctx, a.TenantID); err != nil {
		return err
	}
	return WithContextTenantTx(ctx, r.pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO appsec_assets (`+assetColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, a.ID, a.TenantID, a.Name, a.Category, a.Identity.Kind, a.Identity.Value, a.Lifecycle, a.Criticality, a.Exposure, a.Classification, a.Version, a.Audit.CreatedAt, a.Audit.UpdatedAt, a.Audit.CreatedBy, a.Audit.UpdatedBy)
		if err != nil {
			return fmt.Errorf("create asset: %w", err)
		}
		return nil
	})
}
func (r *AssetInventoryRepository) GetAsset(ctx context.Context, id shared.ID) (asset.Asset, error) {
	var a asset.Asset
	err := WithContextTenantTx(ctx, r.pool, func(tx pgx.Tx) error {
		return scanAsset(tx.QueryRow(ctx, `SELECT `+assetColumns+` FROM appsec_assets WHERE id=$1`, id), &a)
	})
	return a, err
}
func (r *AssetInventoryRepository) ListAssets(ctx context.Context) ([]asset.Asset, error) {
	out := []asset.Asset{}
	err := WithContextTenantTx(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+assetColumns+` FROM appsec_assets ORDER BY name,id`)
		if err != nil {
			return fmt.Errorf("list assets: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var a asset.Asset
			if err := scanAsset(rows, &a); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}
func (r *AssetInventoryRepository) UpdateAsset(ctx context.Context, a asset.Asset, v asset.Version) error {
	if err := a.Validate(); err != nil {
		return err
	}
	if err := v.Validate(); err != nil {
		return err
	}
	if err := requireInventoryTenant(ctx, a.TenantID); err != nil {
		return err
	}
	if v.TenantID != a.TenantID {
		return fmt.Errorf("%w: asset version tenant mismatch", shared.ErrValidation)
	}
	snapshot := v.Snapshot
	return WithContextTenantTx(ctx, r.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE appsec_assets SET name=$2,lifecycle=$3,criticality=$4,exposure=$5,classification=$6,version=$7,updated_at=$8,updated_by=$9 WHERE id=$1 AND version=$10`, a.ID, a.Name, a.Lifecycle, a.Criticality, a.Exposure, a.Classification, a.Version, a.Audit.UpdatedAt, a.Audit.UpdatedBy, a.Version-1)
		if err != nil {
			return fmt.Errorf("update asset: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("asset %s: %w", a.ID, shared.ErrConflict)
		}
		_, err = tx.Exec(ctx, `INSERT INTO appsec_asset_versions (id,asset_id,tenant_id,number,snapshot,created_at,created_by) VALUES ($1,$2,$3,$4,$5,$6,$7)`, v.ID, v.AssetID, v.TenantID, v.Number, snapshot, v.CreatedAt, v.CreatedBy)
		if err != nil {
			return fmt.Errorf("create asset version: %w", err)
		}
		return nil
	})
}
func (r *AssetInventoryRepository) ListAssetVersions(ctx context.Context, id shared.ID) ([]asset.Version, error) {
	out := []asset.Version{}
	err := WithContextTenantTx(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id,tenant_id,asset_id,number,snapshot,created_at,created_by FROM appsec_asset_versions WHERE asset_id=$1 ORDER BY number`, id)
		if err != nil {
			return fmt.Errorf("list asset versions: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var v asset.Version
			var raw []byte
			if err := rows.Scan(&v.ID, &v.TenantID, &v.AssetID, &v.Number, &raw, &v.CreatedAt, &v.CreatedBy); err != nil {
				return err
			}
			if !json.Valid(raw) {
				return fmt.Errorf("invalid stored asset version snapshot")
			}
			v.Snapshot = append(v.Snapshot[:0], raw...)
			out = append(out, v)
		}
		return rows.Err()
	})
	return out, err
}
func (r *AssetInventoryRepository) CreateBusinessService(ctx context.Context, s asset.BusinessService) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if err := requireInventoryTenant(ctx, s.TenantID); err != nil {
		return err
	}
	return WithContextTenantTx(ctx, r.pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO appsec_business_services (id,tenant_id,name,description,criticality,lifecycle,created_at,updated_at,created_by,updated_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, s.ID, s.TenantID, s.Name, s.Description, s.Criticality, s.Lifecycle, s.Audit.CreatedAt, s.Audit.UpdatedAt, s.Audit.CreatedBy, s.Audit.UpdatedBy)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return fmt.Errorf("business service name: %w", shared.ErrConflict)
			}
			return fmt.Errorf("create business service: %w", err)
		}
		return nil
	})
}
func (r *AssetInventoryRepository) GetBusinessService(ctx context.Context, id shared.ID) (asset.BusinessService, error) {
	var s asset.BusinessService
	err := WithContextTenantTx(ctx, r.pool, func(tx pgx.Tx) error {
		return scanBusinessService(tx.QueryRow(ctx, `SELECT id,tenant_id,name,description,criticality,lifecycle,created_at,updated_at,created_by,updated_by FROM appsec_business_services WHERE id=$1`, id), &s)
	})
	return s, err
}
func (r *AssetInventoryRepository) ListBusinessServices(ctx context.Context) ([]asset.BusinessService, error) {
	out := []asset.BusinessService{}
	err := WithContextTenantTx(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id,tenant_id,name,description,criticality,lifecycle,created_at,updated_at,created_by,updated_by FROM appsec_business_services ORDER BY name,id`)
		if err != nil {
			return fmt.Errorf("list business services: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var s asset.BusinessService
			if err := scanBusinessService(rows, &s); err != nil {
				return err
			}
			out = append(out, s)
		}
		return rows.Err()
	})
	return out, err
}

func (r *AssetInventoryRepository) UpdateBusinessService(ctx context.Context, s asset.BusinessService) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if err := requireInventoryTenant(ctx, s.TenantID); err != nil {
		return err
	}
	return WithContextTenantTx(ctx, r.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE appsec_business_services SET name=$2,description=$3,criticality=$4,lifecycle=$5,updated_at=$6,updated_by=$7 WHERE id=$1`, s.ID, s.Name, s.Description, s.Criticality, s.Lifecycle, s.Audit.UpdatedAt, s.Audit.UpdatedBy)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return fmt.Errorf("business service name: %w", shared.ErrConflict)
			}
			return fmt.Errorf("update business service: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("business service %s: %w", s.ID, shared.ErrNotFound)
		}
		return nil
	})
}
func (r *AssetInventoryRepository) LinkBusinessServiceAsset(ctx context.Context, l asset.BusinessServiceAssetLink) error {
	if err := l.Validate(); err != nil {
		return err
	}
	return WithContextTenantTx(ctx, r.pool, func(tx pgx.Tx) error {
		var one int
		if err := tx.QueryRow(ctx, `SELECT 1 FROM appsec_business_services WHERE id=$1`, l.BusinessServiceID).Scan(&one); errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("business service %s: %w", l.BusinessServiceID, shared.ErrNotFound)
		} else if err != nil {
			return fmt.Errorf("read business service for asset link: %w", err)
		}
		if err := tx.QueryRow(ctx, `SELECT 1 FROM appsec_assets WHERE id=$1`, l.AssetID).Scan(&one); errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("asset %s: %w", l.AssetID, shared.ErrNotFound)
		} else if err != nil {
			return fmt.Errorf("read asset for business service link: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO appsec_business_service_assets (business_service_id,asset_id,role,created_at,created_by) VALUES ($1,$2,$3,$4,$5)`, l.BusinessServiceID, l.AssetID, l.Role, l.CreatedAt, l.CreatedBy); err != nil {
			return fmt.Errorf("link business service asset: %w", err)
		}
		return nil
	})
}
func (r *AssetInventoryRepository) ListBusinessServiceAssets(ctx context.Context, id shared.ID) ([]asset.BusinessServiceAssetLink, error) {
	out := []asset.BusinessServiceAssetLink{}
	err := WithContextTenantTx(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT business_service_id,asset_id,role,created_at,created_by FROM appsec_business_service_assets WHERE business_service_id=$1 ORDER BY asset_id`, id)
		if err != nil {
			return fmt.Errorf("list service assets: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var l asset.BusinessServiceAssetLink
			if err := rows.Scan(&l.BusinessServiceID, &l.AssetID, &l.Role, &l.CreatedAt, &l.CreatedBy); err != nil {
				return err
			}
			out = append(out, l)
		}
		return rows.Err()
	})
	return out, err
}
func (r *AssetInventoryRepository) CreateRelationship(ctx context.Context, rel asset.Relationship) error {
	if err := rel.Validate(); err != nil {
		return err
	}
	if err := requireInventoryTenant(ctx, rel.TenantID); err != nil {
		return err
	}
	return WithContextTenantTx(ctx, r.pool, func(tx pgx.Tx) error {
		if rel.Type == asset.RelationshipContains || rel.Type == asset.RelationshipPartOf {
			var cycle bool
			if err := tx.QueryRow(ctx, `WITH RECURSIVE reachable(id) AS (
				SELECT $1::TEXT
				UNION
				SELECT relationship.to_asset_id
				FROM appsec_asset_relationships relationship
				JOIN reachable ON relationship.from_asset_id = reachable.id
				WHERE relationship.relation_type IN ('contains', 'part_of')
			) SELECT EXISTS (SELECT 1 FROM reachable WHERE id = $2)`, rel.ToAssetID, rel.FromAssetID).Scan(&cycle); err != nil {
				return fmt.Errorf("check asset relationship cycle: %w", err)
			}
			if cycle {
				return fmt.Errorf("%w: asset relationship cycle", shared.ErrValidation)
			}
		}
		_, err := tx.Exec(ctx, `INSERT INTO appsec_asset_relationships (id,tenant_id,from_asset_id,to_asset_id,relation_type,created_at,created_by) VALUES ($1,$2,$3,$4,$5,$6,$7)`, rel.ID, rel.TenantID, rel.FromAssetID, rel.ToAssetID, rel.Type, rel.CreatedAt, rel.CreatedBy)
		if err != nil {
			return fmt.Errorf("create asset relationship: %w", err)
		}
		return nil
	})
}
func (r *AssetInventoryRepository) ListRelationships(ctx context.Context, id shared.ID) ([]asset.Relationship, error) {
	out := []asset.Relationship{}
	err := WithContextTenantTx(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id,tenant_id,from_asset_id,to_asset_id,relation_type,created_at,created_by FROM appsec_asset_relationships WHERE from_asset_id=$1 ORDER BY created_at,id`, id)
		if err != nil {
			return fmt.Errorf("list asset relationships: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var rel asset.Relationship
			if err := rows.Scan(&rel.ID, &rel.TenantID, &rel.FromAssetID, &rel.ToAssetID, &rel.Type, &rel.CreatedAt, &rel.CreatedBy); err != nil {
				return err
			}
			out = append(out, rel)
		}
		return rows.Err()
	})
	return out, err
}
func (r *AssetInventoryRepository) AssignOwner(ctx context.Context, o asset.OwnershipAssignment) error {
	if err := o.Validate(); err != nil {
		return err
	}
	if err := requireInventoryTenant(ctx, o.TenantID); err != nil {
		return err
	}
	return WithContextTenantTx(ctx, r.pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO appsec_asset_ownership_assignments (id,tenant_id,asset_id,principal,role,created_at,created_by) VALUES ($1,$2,$3,$4,$5,$6,$7)`, o.ID, o.TenantID, o.AssetID, o.Principal, o.Role, o.CreatedAt, o.CreatedBy)
		if err != nil {
			return fmt.Errorf("assign asset owner: %w", err)
		}
		return nil
	})
}
func (r *AssetInventoryRepository) ListOwners(ctx context.Context, id shared.ID) ([]asset.OwnershipAssignment, error) {
	out := []asset.OwnershipAssignment{}
	err := WithContextTenantTx(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id,tenant_id,asset_id,principal,role,created_at,created_by FROM appsec_asset_ownership_assignments WHERE asset_id=$1 ORDER BY created_at,id`, id)
		if err != nil {
			return fmt.Errorf("list asset owners: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var o asset.OwnershipAssignment
			if err := rows.Scan(&o.ID, &o.TenantID, &o.AssetID, &o.Principal, &o.Role, &o.CreatedAt, &o.CreatedBy); err != nil {
				return err
			}
			out = append(out, o)
		}
		return rows.Err()
	})
	return out, err
}

type assetRow interface{ Scan(...any) error }

func scanAsset(row assetRow, a *asset.Asset) error {
	var cat, lifecycle, criticality, exposure string
	err := row.Scan(&a.ID, &a.TenantID, &a.Name, &cat, &a.Identity.Kind, &a.Identity.Value, &lifecycle, &criticality, &exposure, &a.Classification, &a.Version, &a.Audit.CreatedAt, &a.Audit.UpdatedAt, &a.Audit.CreatedBy, &a.Audit.UpdatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("asset: %w", shared.ErrNotFound)
	}
	if err != nil {
		return err
	}
	a.Category = asset.Category(cat)
	a.Lifecycle = asset.Lifecycle(lifecycle)
	a.Criticality = asset.Criticality(criticality)
	a.Exposure = asset.Exposure(exposure)
	return nil
}
func scanBusinessService(row assetRow, s *asset.BusinessService) error {
	var criticality, lifecycle string
	err := row.Scan(&s.ID, &s.TenantID, &s.Name, &s.Description, &criticality, &lifecycle, &s.Audit.CreatedAt, &s.Audit.UpdatedAt, &s.Audit.CreatedBy, &s.Audit.UpdatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("business service: %w", shared.ErrNotFound)
	}
	if err != nil {
		return err
	}
	s.Criticality = asset.Criticality(criticality)
	s.Lifecycle = asset.Lifecycle(lifecycle)
	return nil
}

func (r *AssetInventoryRepository) DeleteAsset(ctx context.Context, id shared.ID) error {
	return WithContextTenantTx(ctx, r.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM appsec_assets WHERE id=$1`, id)
		if err != nil {
			return fmt.Errorf("delete asset: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("asset %s: %w", id, shared.ErrNotFound)
		}
		return nil
	})
}

func (r *AssetInventoryRepository) DeleteBusinessService(ctx context.Context, id shared.ID) error {
	return WithContextTenantTx(ctx, r.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM appsec_business_services WHERE id=$1`, id)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23503" {
				return fmt.Errorf("business service assessments: %w", shared.ErrConflict)
			}
			return fmt.Errorf("delete business service: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("business service %s: %w", id, shared.ErrNotFound)
		}
		return nil
	})
}
