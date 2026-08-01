package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/importedsbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ImportedSBOMStore persists the active imported SBOM per engagement.
type ImportedSBOMStore struct{ pool *pgxpool.Pool }

// NewImportedSBOMStore returns a Postgres-backed imported-SBOM store.
func NewImportedSBOMStore(pool *pgxpool.Pool) *ImportedSBOMStore {
	return &ImportedSBOMStore{pool: pool}
}

var _ ports.ImportedSBOMStore = (*ImportedSBOMStore)(nil)

// SaveActive upserts the active imported SBOM for an engagement.
func (s *ImportedSBOMStore) SaveActive(ctx context.Context, record importedsbom.Record) error {
	if err := record.Validate(); err != nil {
		return err
	}
	return WithTenantTx(ctx, s.pool, record.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO imported_sboms (
				id, tenant_id, engagement_id, filename, format, spec_version, target_ref,
				component_count, dependency_count, sha256, raw_json, created_by, created_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
			ON CONFLICT (tenant_id, engagement_id) DO UPDATE SET
				id = EXCLUDED.id, filename = EXCLUDED.filename, format = EXCLUDED.format,
				spec_version = EXCLUDED.spec_version, target_ref = EXCLUDED.target_ref,
				component_count = EXCLUDED.component_count, dependency_count = EXCLUDED.dependency_count,
				sha256 = EXCLUDED.sha256, raw_json = EXCLUDED.raw_json,
				created_by = EXCLUDED.created_by, created_at = EXCLUDED.created_at`,
			record.ID.String(), record.TenantID.String(), record.EngagementID.String(), record.Filename,
			record.Format, record.SpecVersion, record.TargetRef, record.ComponentCount, record.DependencyCount,
			record.SHA256, record.RawJSON, record.CreatedBy, record.CreatedAt)
		if err != nil {
			return fmt.Errorf("save imported SBOM: %w", err)
		}
		return nil
	})
}

// LatestByEngagement returns the active imported SBOM for a tenant-scoped engagement.
func (s *ImportedSBOMStore) LatestByEngagement(ctx context.Context, tenantID, engagementID shared.ID) (record importedsbom.Record, err error) {
	err = WithTenantTx(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT id, tenant_id, engagement_id, filename, format, spec_version, target_ref, component_count, dependency_count, sha256, raw_json, created_by, created_at FROM imported_sboms WHERE tenant_id = $1 AND engagement_id = $2`, tenantID.String(), engagementID.String()).Scan(
			&record.ID, &record.TenantID, &record.EngagementID, &record.Filename, &record.Format,
			&record.SpecVersion, &record.TargetRef, &record.ComponentCount, &record.DependencyCount,
			&record.SHA256, &record.RawJSON, &record.CreatedBy, &record.CreatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("imported SBOM for engagement %s: %w", engagementID, shared.ErrNotFound)
		}
		if err != nil {
			return fmt.Errorf("load imported SBOM: %w", err)
		}
		return nil
	})
	return record, err
}
