package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sourcepackage"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type EngagementSourceRepository struct{ pool *pgxpool.Pool }

func NewEngagementSourceRepository(pool *pgxpool.Pool) *EngagementSourceRepository {
	return &EngagementSourceRepository{pool: pool}
}

var _ ports.EngagementSourceRepository = (*EngagementSourceRepository)(nil)

const sourcePackageColumns = `tenant_id,engagement_id,version_id,filename,size_bytes,sha256,locator,object_key,created_by,created_at,associated_by,associated_at,COALESCE(reused_from_version_id,'')`

func scanSourcePackage(row pgx.Row) (sourcepackage.Package, error) {
	var item sourcepackage.Package
	err := row.Scan(&item.TenantID, &item.EngagementID, &item.VersionID, &item.Filename, &item.Size, &item.SHA256, &item.Locator, &item.ObjectKey, &item.CreatedBy, &item.CreatedAt, &item.AssociatedBy, &item.AssociatedAt, &item.ReusedFromVersionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return item, shared.ErrNotFound
	}
	item.CreatedAt = item.CreatedAt.UTC()
	item.AssociatedAt = item.AssociatedAt.UTC()
	return item, err
}

func sourcePackageError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23503", "23505":
			return fmt.Errorf("%w: uploaded source package is already bound or referenced", shared.ErrConflict)
		case "23514":
			return fmt.Errorf("%w: uploaded source package metadata is invalid or immutable", shared.ErrValidation)
		}
	}
	return err
}

func (r *EngagementSourceRepository) Create(ctx context.Context, item sourcepackage.Package) (sourcepackage.Package, bool, error) {
	if err := item.ValidateVersion(); err != nil {
		return sourcepackage.Package{}, false, err
	}
	var stored sourcepackage.Package
	created := false
	err := WithTenant(ctx, r.pool, item.TenantID.String(), func(tx pgx.Tx) error {
		result, err := tx.Exec(ctx, `INSERT INTO engagement_source_packages
 (tenant_id,engagement_id,version_id,filename,size_bytes,sha256,locator,object_key,created_by,created_at,associated_by,associated_at,reused_from_version_id)
 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NULLIF($13,'')) ON CONFLICT DO NOTHING`, item.TenantID, item.EngagementID, item.VersionID, item.Filename, item.Size, item.SHA256, item.Locator, item.ObjectKey, item.CreatedBy, item.CreatedAt, item.AssociatedBy, item.AssociatedAt, item.ReusedFromVersionID)
		if err != nil {
			return err
		}
		created = result.RowsAffected() == 1
		stored, err = scanSourcePackage(tx.QueryRow(ctx, `SELECT `+sourcePackageColumns+` FROM engagement_source_packages WHERE tenant_id=$1 AND engagement_id=$2`, item.TenantID, item.EngagementID))
		if err != nil {
			return err
		}
		if stored.VersionID != item.VersionID || stored.Filename != item.Filename || stored.SHA256 != item.SHA256 || stored.Size != item.Size || stored.Locator != item.Locator || stored.ObjectKey != item.ObjectKey || stored.ReusedFromVersionID != item.ReusedFromVersionID || stored.CreatedBy != item.CreatedBy || !stored.CreatedAt.Equal(item.CreatedAt) || stored.AssociatedBy != item.AssociatedBy || !stored.AssociatedAt.Equal(item.AssociatedAt) {
			return shared.ErrConflict
		}
		return nil
	})
	return stored, created, sourcePackageError(err)
}

func (r *EngagementSourceRepository) Get(ctx context.Context, tenantID, engagementID shared.ID) (sourcepackage.Package, error) {
	return r.read(ctx, tenantID, `engagement_id=$2`, engagementID.String())
}
func (r *EngagementSourceRepository) GetByVersion(ctx context.Context, tenantID, engagementID, versionID shared.ID) (sourcepackage.Package, error) {
	item, err := r.Get(ctx, tenantID, engagementID)
	if err == nil && item.VersionID != versionID {
		return sourcepackage.Package{}, shared.ErrNotFound
	}
	return item, err
}
func (r *EngagementSourceRepository) GetByLocator(ctx context.Context, tenantID shared.ID, locator string) (sourcepackage.Package, error) {
	return r.read(ctx, tenantID, `locator=$2`, locator)
}
func (r *EngagementSourceRepository) read(ctx context.Context, tenantID shared.ID, predicate, value string) (sourcepackage.Package, error) {
	var item sourcepackage.Package
	if tenantID.IsZero() {
		return item, shared.ErrValidation
	}
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		var err error
		item, err = scanSourcePackage(tx.QueryRow(ctx, `SELECT `+sourcePackageColumns+` FROM engagement_source_packages WHERE tenant_id=$1 AND `+predicate, tenantID, value))
		return err
	})
	return item, sourcePackageError(err)
}

func (r *EngagementSourceRepository) Delete(ctx context.Context, tenantID, engagementID shared.ID) (sourcepackage.Package, bool, error) {
	var item sourcepackage.Package
	unreferenced := false
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		var err error
		item, err = scanSourcePackage(tx.QueryRow(ctx, `DELETE FROM engagement_source_packages WHERE tenant_id=$1 AND engagement_id=$2 RETURNING `+sourcePackageColumns, tenantID, engagementID))
		if err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM engagement_source_packages WHERE tenant_id=$1 AND object_key=$2)`, tenantID, item.ObjectKey).Scan(&unreferenced)
	})
	_, inTransaction, _ := contextTenantTx(ctx, tenantID)
	return item, unreferenced && !inTransaction, sourcePackageError(err)
}

func (r *EngagementSourceRepository) ObjectUnreferenced(ctx context.Context, tenantID shared.ID, objectKey string) (bool, error) {
	if _, inTransaction, err := contextTenantTx(ctx, tenantID); err != nil || inTransaction {
		return false, err // A matching uncommitted transaction defers cleanup.
	}
	if tenantID.IsZero() || objectKey == "" {
		return false, shared.ErrValidation
	}
	var unreferenced bool
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM engagement_source_packages WHERE tenant_id=$1 AND object_key=$2)`, tenantID, objectKey).Scan(&unreferenced)
	})
	return unreferenced, err
}
