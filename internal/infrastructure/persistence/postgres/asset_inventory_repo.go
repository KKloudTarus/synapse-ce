package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/businessservice"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const businessServiceCols = `id, tenant_id, name, code, owner, criticality, created_at, updated_at, created_by, updated_by`
const assetCols = `id, tenant_id, name, category, identity_kind, identity_value, lifecycle, owner, criticality, exposure, classification, created_at, updated_at, created_by, updated_by`

type AssetInventoryRepository struct{ pool *pgxpool.Pool }
func NewAssetInventoryRepository(pool *pgxpool.Pool) *AssetInventoryRepository { return &AssetInventoryRepository{pool: pool} }
var _ ports.AssetInventoryRepository = (*AssetInventoryRepository)(nil)

func (r *AssetInventoryRepository) CreateBusinessService(ctx context.Context, s *businessservice.BusinessService) error {
	_, err := r.pool.Exec(ctx, `INSERT INTO appsec_business_services (`+businessServiceCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, s.ID.String(), s.TenantID.String(), s.Name, s.Code, s.Owner, s.Criticality, s.Audit.CreatedAt, s.Audit.UpdatedAt, s.Audit.CreatedBy, s.Audit.UpdatedBy)
	return inventoryWriteError(err, "business service")
}
func (r *AssetInventoryRepository) ListBusinessServices(ctx context.Context, tenantID shared.ID) ([]*businessservice.BusinessService, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+businessServiceCols+` FROM appsec_business_services WHERE tenant_id=$1 ORDER BY code`, tenantID.String()); if err != nil { return nil, fmt.Errorf("list business services: %w", err) }; defer rows.Close()
	out := make([]*businessservice.BusinessService, 0); for rows.Next() { s, err := scanBusinessService(rows); if err != nil { return nil, err }; out = append(out, s) }; return out, rows.Err()
}
func (r *AssetInventoryRepository) GetBusinessService(ctx context.Context, tenantID, id shared.ID) (*businessservice.BusinessService, error) {
	s, err := scanBusinessService(r.pool.QueryRow(ctx, `SELECT `+businessServiceCols+` FROM appsec_business_services WHERE tenant_id=$1 AND id=$2`, tenantID.String(), id.String())); if errors.Is(err, pgx.ErrNoRows) { return nil, shared.ErrNotFound }; if err != nil { return nil, fmt.Errorf("get business service: %w", err) }; return s, nil
}
func (r *AssetInventoryRepository) CreateAsset(ctx context.Context, a *asset.Asset) error {
	_, err := r.pool.Exec(ctx, `INSERT INTO appsec_assets (`+assetCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, a.ID.String(), a.TenantID.String(), a.Name, a.Category, a.Identity.Kind, a.Identity.Value, a.Lifecycle, a.Owner, a.Criticality, a.Exposure, a.Classification, a.Audit.CreatedAt, a.Audit.UpdatedAt, a.Audit.CreatedBy, a.Audit.UpdatedBy)
	return inventoryWriteError(err, "asset")
}
func (r *AssetInventoryRepository) GetAsset(ctx context.Context, tenantID, id shared.ID) (*asset.Asset, error) {
	a, err := scanAsset(r.pool.QueryRow(ctx, `SELECT `+assetCols+` FROM appsec_assets WHERE tenant_id=$1 AND id=$2`, tenantID.String(), id.String())); if errors.Is(err, pgx.ErrNoRows) { return nil, shared.ErrNotFound }; if err != nil { return nil, fmt.Errorf("get asset: %w", err) }; return a, nil
}
func (r *AssetInventoryRepository) ListAssets(ctx context.Context, tenantID shared.ID) ([]*asset.Asset, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+assetCols+` FROM appsec_assets WHERE tenant_id=$1 ORDER BY name, id`, tenantID.String()); if err != nil { return nil, fmt.Errorf("list assets: %w", err) }; defer rows.Close()
	out := make([]*asset.Asset, 0); for rows.Next() { a, err := scanAsset(rows); if err != nil { return nil, err }; out = append(out, a) }; return out, rows.Err()
}
func (r *AssetInventoryRepository) CreateVersion(ctx context.Context, v asset.Version) error {
	ct, err := r.pool.Exec(ctx, `INSERT INTO appsec_asset_versions (id,asset_id,value,source,created_at,updated_at,created_by,updated_by) SELECT $1,$2,$3,$4,$5,$6,$7,$8 WHERE EXISTS (SELECT 1 FROM appsec_assets WHERE id=$2)`, v.ID.String(), v.AssetID.String(), v.Value, v.Source, v.Audit.CreatedAt, v.Audit.UpdatedAt, v.Audit.CreatedBy, v.Audit.UpdatedBy)
	if err != nil { return inventoryWriteError(err, "asset version") }
	if ct.RowsAffected() == 0 { return shared.ErrNotFound }
	return nil
}
func (r *AssetInventoryRepository) ListVersions(ctx context.Context, tenantID, assetID shared.ID) ([]asset.Version, error) {
	if _, err := r.GetAsset(ctx, tenantID, assetID); err != nil { return nil, err }
	rows, err := r.pool.Query(ctx, `SELECT id,asset_id,value,source,created_at,updated_at,created_by,updated_by FROM appsec_asset_versions WHERE asset_id=$1 ORDER BY created_at DESC,id`, assetID.String()); if err != nil { return nil, fmt.Errorf("list asset versions: %w", err) }; defer rows.Close()
	out := make([]asset.Version, 0); for rows.Next() { var v asset.Version; var id, aid string; if err := rows.Scan(&id,&aid,&v.Value,&v.Source,&v.Audit.CreatedAt,&v.Audit.UpdatedAt,&v.Audit.CreatedBy,&v.Audit.UpdatedBy); err != nil { return nil, err }; v.ID, v.AssetID = shared.ID(id), shared.ID(aid); out = append(out,v) }; return out, rows.Err()
}
func (r *AssetInventoryRepository) LinkBusinessServiceAsset(ctx context.Context, link asset.BusinessServiceLink) error {
	ct, err := r.pool.Exec(ctx, `INSERT INTO appsec_business_service_assets (business_service_id,asset_id,role,created_at,updated_at,created_by,updated_by) SELECT $1,$2,$3,$4,$5,$6,$7 WHERE EXISTS (SELECT 1 FROM appsec_business_services s JOIN appsec_assets a ON a.tenant_id=s.tenant_id WHERE s.id=$1 AND a.id=$2)`, link.BusinessServiceID.String(),link.AssetID.String(),link.Role,link.Audit.CreatedAt,link.Audit.UpdatedAt,link.Audit.CreatedBy,link.Audit.UpdatedBy); if err != nil { return inventoryWriteError(err,"business service asset link") }; if ct.RowsAffected()==0 { return shared.ErrNotFound }; return nil
}
func (r *AssetInventoryRepository) ListBusinessServiceAssets(ctx context.Context, tenantID, serviceID shared.ID) ([]asset.BusinessServiceLink, error) {
	if _, err := r.GetBusinessService(ctx, tenantID, serviceID); err != nil { return nil, err }
	rows, err := r.pool.Query(ctx, `SELECT business_service_id,asset_id,role,created_at,updated_at,created_by,updated_by FROM appsec_business_service_assets WHERE business_service_id=$1 ORDER BY asset_id`,serviceID.String()); if err != nil { return nil,fmt.Errorf("list business service assets: %w",err)};defer rows.Close();out:=make([]asset.BusinessServiceLink,0);for rows.Next(){var l asset.BusinessServiceLink;var sid,aid string;if err:=rows.Scan(&sid,&aid,&l.Role,&l.Audit.CreatedAt,&l.Audit.UpdatedAt,&l.Audit.CreatedBy,&l.Audit.UpdatedBy);err!=nil{return nil,err};l.BusinessServiceID,l.AssetID=shared.ID(sid),shared.ID(aid);out=append(out,l)};return out,rows.Err()
}
func (r *AssetInventoryRepository) CreateRelationship(ctx context.Context, tenantID shared.ID, rel asset.Relationship) error {
	ct, err := r.pool.Exec(ctx, `INSERT INTO appsec_asset_relationships (from_asset_id,to_asset_id,relationship_type,created_at,updated_at,created_by,updated_by) SELECT $1,$2,$3,$4,$5,$6,$7 WHERE EXISTS (SELECT 1 FROM appsec_assets a JOIN appsec_assets b ON b.tenant_id=a.tenant_id WHERE a.id=$1 AND b.id=$2 AND a.tenant_id=$8)`,rel.FromAssetID.String(),rel.ToAssetID.String(),rel.Type,rel.Audit.CreatedAt,rel.Audit.UpdatedAt,rel.Audit.CreatedBy,rel.Audit.UpdatedBy,tenantID.String());if err!=nil{return inventoryWriteError(err,"asset relationship")};if ct.RowsAffected()==0{return shared.ErrNotFound};return nil
}
func (r *AssetInventoryRepository) ListRelationships(ctx context.Context, tenantID, assetID shared.ID) ([]asset.Relationship,error) {
	if _, err := r.GetAsset(ctx, tenantID, assetID); err != nil { return nil, err }
	rows, err := r.pool.Query(ctx, `SELECT from_asset_id,to_asset_id,relationship_type,created_at,updated_at,created_by,updated_by FROM appsec_asset_relationships WHERE from_asset_id=$1 OR to_asset_id=$1 ORDER BY created_at,from_asset_id,to_asset_id,relationship_type`, assetID.String())
	if err != nil { return nil, fmt.Errorf("list asset relationships: %w", err) }
	defer rows.Close()
	out := make([]asset.Relationship, 0)
	for rows.Next() {
		var rel asset.Relationship
		var from, to string
		if err := rows.Scan(&from, &to, &rel.Type, &rel.Audit.CreatedAt, &rel.Audit.UpdatedAt, &rel.Audit.CreatedBy, &rel.Audit.UpdatedBy); err != nil { return nil, err }
		rel.FromAssetID, rel.ToAssetID = shared.ID(from), shared.ID(to)
		out = append(out, rel)
	}
	return out, rows.Err()
}

type inventoryRowScanner interface{ Scan(...any) error }
func scanBusinessService(row inventoryRowScanner)(*businessservice.BusinessService,error){var s businessservice.BusinessService;var id,tenant string;err:=row.Scan(&id,&tenant,&s.Name,&s.Code,&s.Owner,&s.Criticality,&s.Audit.CreatedAt,&s.Audit.UpdatedAt,&s.Audit.CreatedBy,&s.Audit.UpdatedBy);s.ID,s.TenantID=shared.ID(id),shared.ID(tenant);return &s,err}
func scanAsset(row inventoryRowScanner)(*asset.Asset,error){var a asset.Asset;var id,tenant string;err:=row.Scan(&id,&tenant,&a.Name,&a.Category,&a.Identity.Kind,&a.Identity.Value,&a.Lifecycle,&a.Owner,&a.Criticality,&a.Exposure,&a.Classification,&a.Audit.CreatedAt,&a.Audit.UpdatedAt,&a.Audit.CreatedBy,&a.Audit.UpdatedBy);a.ID,a.TenantID=shared.ID(id),shared.ID(tenant);return &a,err}
func inventoryWriteError(err error, subject string) error { if err==nil{return nil};var pgErr *pgconn.PgError;if errors.As(err,&pgErr)&&pgErr.Code=="23505"{return fmt.Errorf("%s already exists: %w",subject,shared.ErrConflict)};return fmt.Errorf("persist %s: %w",subject,err) }
