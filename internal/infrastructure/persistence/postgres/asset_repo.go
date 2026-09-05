package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
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
const businessAssetCols = `id, tenant_id, "key", name, description, asset_type, criticality, lifecycle, owner, metadata, version, created_at, updated_at, created_by, updated_by`

// UpsertAsset inserts or updates by the (tenant_id, kind, key) natural key, preserving the id and
// created_at of an existing row so re-observation does not churn identity. A new host row that would
// take its reporting agent past the per-agent cap is refused by the fleet_assets trigger (migration
// 0132) and surfaces as shared.ErrForbidden.
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
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23514" && pgErr.ConstraintName == "fleet_assets_host_cap_per_agent" {
			return fmt.Errorf("%w: agent %s already reports the maximum number of hosts; a new host key is refused",
				shared.ErrForbidden, strings.TrimSpace(a.Attributes["reporting_agent_id"]))
		}
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
		rows, e := tx.Query(ctx, `SELECT `+assetCols+` FROM fleet_assets a
			WHERE a.tenant_id = $1 AND (
				a.attributes->>'scope_key' IS NULL OR
				EXISTS (SELECT 1 FROM cspm_observations o
					WHERE o.tenant_id=a.tenant_id AND o.observation_kind='asset' AND o.object_id=a.id AND o.active)
			) ORDER BY a.kind, a."key"`, tenantID.String())
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
			INSERT INTO fleet_asset_edges (tenant_id, from_asset, to_asset, kind, provenance, confidence)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (tenant_id, from_asset, to_asset, kind, provenance) DO UPDATE
			SET confidence = EXCLUDED.confidence`,
			e.TenantID.String(), e.From.String(), e.To.String(), string(e.Kind), e.Provenance.String(), string(e.Confidence))
		return err
	})
}

// ListEdges returns the tenant's edges ordered by (from, to, kind, provenance).
func (r *AssetRepository) ListEdges(ctx context.Context, tenantID shared.ID) ([]*asset.Edge, error) {
	var out []*asset.Edge
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `
			SELECT e.tenant_id, e.from_asset, e.to_asset, e.kind, e.provenance, e.confidence FROM fleet_asset_edges e
			WHERE e.tenant_id = $1 AND (
				e.provenance NOT LIKE 'cspm:%' OR
				EXISTS (SELECT 1 FROM cspm_observations o
					WHERE o.tenant_id=e.tenant_id AND o.producer=e.provenance AND o.observation_kind='edge'
					AND o.object_id=e.from_asset || '|' || e.to_asset || '|' || e.kind AND o.active)
			) ORDER BY e.from_asset, e.to_asset, e.kind, e.provenance`, tenantID.String())
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var tid, from, to, kind, prov, confidence string
			if e := rows.Scan(&tid, &from, &to, &kind, &prov, &confidence); e != nil {
				return e
			}
			out = append(out, &asset.Edge{
				TenantID:   shared.ID(tid),
				From:       shared.ID(from),
				To:         shared.ID(to),
				Kind:       asset.EdgeKind(kind),
				Provenance: shared.ID(prov),
				Confidence: asset.EdgeConfidence(confidence),
			})
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

func (r *AssetRepository) CreateBusinessAsset(ctx context.Context, a *asset.BusinessAsset) error {
	metadata, err := json.Marshal(a.Metadata)
	if err != nil {
		return fmt.Errorf("business asset: marshal metadata: %w", err)
	}
	return WithTenant(ctx, r.pool, a.TenantID.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO fleet_business_services (`+businessAssetCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
			a.ID.String(), a.TenantID.String(), a.Key, a.Name, a.Description, string(a.Type), string(a.Criticality), string(a.Lifecycle), a.Owner, metadata, a.Version, a.Audit.CreatedAt, a.Audit.UpdatedAt, a.Audit.CreatedBy, a.Audit.UpdatedBy)
		return err
	})
}

func (r *AssetRepository) UpdateBusinessAsset(ctx context.Context, a *asset.BusinessAsset, expectedVersion int) error {
	metadata, err := json.Marshal(a.Metadata)
	if err != nil {
		return fmt.Errorf("business asset: marshal metadata: %w", err)
	}
	return WithTenant(ctx, r.pool, a.TenantID.String(), func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `UPDATE fleet_business_services SET name=$3, description=$4, asset_type=$5, criticality=$6, lifecycle=$7, owner=$8, metadata=$9, version=$10, updated_at=$11, updated_by=$12 WHERE tenant_id=$1 AND id=$2 AND version=$13`,
			a.TenantID.String(), a.ID.String(), a.Name, a.Description, string(a.Type), string(a.Criticality), string(a.Lifecycle), a.Owner, metadata, a.Version, a.Audit.UpdatedAt, a.Audit.UpdatedBy, expectedVersion)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return shared.ErrConflict
		}
		return nil
	})
}

func (r *AssetRepository) GetBusinessAssetByID(ctx context.Context, tenantID, id shared.ID) (*asset.BusinessAsset, error) {
	var out *asset.BusinessAsset
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		var err error
		out, err = scanBusinessAsset(tx.QueryRow(ctx, `SELECT `+businessAssetCols+` FROM fleet_business_services WHERE tenant_id=$1 AND id=$2`, tenantID.String(), id.String()))
		return err
	})
	return out, err
}
func (r *AssetRepository) GetBusinessAssetByKey(ctx context.Context, tenantID shared.ID, key string) (*asset.BusinessAsset, error) {
	var out *asset.BusinessAsset
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		var err error
		out, err = scanBusinessAsset(tx.QueryRow(ctx, `SELECT `+businessAssetCols+` FROM fleet_business_services WHERE tenant_id=$1 AND "key"=$2`, tenantID.String(), key))
		return err
	})
	return out, err
}
func (r *AssetRepository) ListBusinessAssets(ctx context.Context, tenantID shared.ID) ([]*asset.BusinessAsset, error) {
	out := []*asset.BusinessAsset{}
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+businessAssetCols+` FROM fleet_business_services WHERE tenant_id=$1 ORDER BY "key"`, tenantID.String())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			a, err := scanBusinessAsset(rows)
			if err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

func (r *AssetRepository) ReplaceBusinessAssetProjects(ctx context.Context, tenantID, assetID shared.ID, links []asset.ComponentMembership) error {
	return r.replaceBusinessAssetLinks(ctx, tenantID, assetID, "business_asset_projects", "project_id", links)
}
func (r *AssetRepository) ListBusinessAssetProjects(ctx context.Context, tenantID, assetID shared.ID) ([]asset.ComponentMembership, error) {
	return r.listBusinessAssetLinks(ctx, tenantID, assetID, "business_asset_projects", "project_id")
}
func (r *AssetRepository) ReplaceBusinessAssetTechnicalAssets(ctx context.Context, tenantID, assetID shared.ID, links []asset.ComponentMembership) error {
	return r.replaceBusinessAssetLinks(ctx, tenantID, assetID, "business_asset_technical_assets", "technical_asset_id", links)
}
func (r *AssetRepository) ListBusinessAssetTechnicalAssets(ctx context.Context, tenantID, assetID shared.ID) ([]asset.ComponentMembership, error) {
	return r.listBusinessAssetLinks(ctx, tenantID, assetID, "business_asset_technical_assets", "technical_asset_id")
}

func (r *AssetRepository) replaceBusinessAssetLinks(ctx context.Context, tenantID, assetID shared.ID, table, idColumn string, links []asset.ComponentMembership) error {
	return WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM `+table+` WHERE tenant_id=$1 AND business_asset_id=$2`, tenantID.String(), assetID.String()); err != nil {
			return err
		}
		for _, link := range links {
			if _, err := tx.Exec(ctx, `INSERT INTO `+table+` (tenant_id,business_asset_id,`+idColumn+`,role,provenance) VALUES ($1,$2,$3,$4,$5)`, tenantID.String(), assetID.String(), link.ComponentID.String(), string(link.Role), link.Provenance); err != nil {
				return err
			}
		}
		return nil
	})
}
func (r *AssetRepository) listBusinessAssetLinks(ctx context.Context, tenantID, assetID shared.ID, table, idColumn string) ([]asset.ComponentMembership, error) {
	out := []asset.ComponentMembership{}
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT tenant_id,business_asset_id,`+idColumn+`,role,provenance FROM `+table+` WHERE tenant_id=$1 AND business_asset_id=$2 ORDER BY role,`+idColumn, tenantID.String(), assetID.String())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var tid, aid, cid, role, provenance string
			if err := rows.Scan(&tid, &aid, &cid, &role, &provenance); err != nil {
				return err
			}
			out = append(out, asset.ComponentMembership{TenantID: shared.ID(tid), AssetID: shared.ID(aid), ComponentID: shared.ID(cid), Role: asset.MembershipRole(role), Provenance: provenance})
		}
		return rows.Err()
	})
	return out, err
}

func (r *AssetRepository) AssignEngagementBusinessAsset(ctx context.Context, tenantID, engagementID, assetID shared.ID) error {
	return WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `UPDATE engagements SET business_asset_id=NULLIF($3,''), updated_at=now() WHERE tenant_id=$1 AND id=$2 AND project_id IS NULL AND host_asset_id IS NULL`, tenantID.String(), engagementID.String(), assetID.String())
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return shared.ErrNotFound
		}
		return nil
	})
}
func (r *AssetRepository) ListEngagementsByBusinessAsset(ctx context.Context, tenantID, assetID shared.ID) ([]*engagement.Engagement, error) {
	out := []*engagement.Engagement{}
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+engagementCols+` FROM engagements WHERE tenant_id=$1 AND business_asset_id=$2 AND project_id IS NULL AND host_asset_id IS NULL ORDER BY updated_at DESC,id`, tenantID.String(), assetID.String())
		if err != nil {
			return err
		}
		for rows.Next() {
			e, err := scanEngagement(rows)
			if err != nil {
				rows.Close()
				return err
			}
			out = append(out, e)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		for _, e := range out {
			scopeRows, err := tx.Query(ctx, `SELECT in_scope,kind,value FROM scope_targets WHERE tenant_id=$1 AND engagement_id=$2 ORDER BY id`, tenantID.String(), e.ID.String())
			if err != nil {
				return err
			}
			for scopeRows.Next() {
				var inScope bool
				var kind, value string
				if err := scopeRows.Scan(&inScope, &kind, &value); err != nil {
					scopeRows.Close()
					return err
				}
				target := engagement.Target{Kind: engagement.TargetKind(kind), Value: value}
				if inScope {
					e.Scope.InScope = append(e.Scope.InScope, target)
				} else {
					e.Scope.OutOfScope = append(e.Scope.OutOfScope, target)
				}
			}
			scopeRows.Close()
		}
		return nil
	})
	return out, err
}

func scanBusinessAsset(row rowScanner) (*asset.BusinessAsset, error) {
	var a asset.BusinessAsset
	var id, tid, typ, crit, lifecycle string
	var metadata []byte
	if err := row.Scan(&id, &tid, &a.Key, &a.Name, &a.Description, &typ, &crit, &lifecycle, &a.Owner, &metadata, &a.Version, &a.Audit.CreatedAt, &a.Audit.UpdatedAt, &a.Audit.CreatedBy, &a.Audit.UpdatedBy); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, err
	}
	a.ID, a.TenantID = shared.ID(id), shared.ID(tid)
	a.Type = asset.BusinessAssetType(typ)
	a.Criticality = asset.Criticality(crit)
	a.Lifecycle = asset.BusinessAssetLifecycle(lifecycle)
	a.Metadata = map[string]string{}
	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &a.Metadata); err != nil {
			return nil, err
		}
	}
	return &a, nil
}
