package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type ComponentInventoryStore struct{ pool *pgxpool.Pool }

func NewComponentInventoryStore(pool *pgxpool.Pool) *ComponentInventoryStore {
	return &ComponentInventoryStore{pool: pool}
}

var _ ports.ComponentInventoryStore = (*ComponentInventoryStore)(nil)

func (s *ComponentInventoryStore) ListCurrentComponents(ctx context.Context, query sbom.ComponentQuery) (sbom.ComponentPage, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return sbom.ComponentPage{}, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	tenantID = shared.TenantOrDefault(tenantID)
	if !query.TenantID.IsZero() && shared.TenantOrDefault(query.TenantID) != tenantID {
		return sbom.ComponentPage{}, fmt.Errorf("%w: component query tenant does not match context", shared.ErrValidation)
	}
	query.TenantID = tenantID
	query, err := query.Normalize()
	if err != nil {
		return sbom.ComponentPage{}, err
	}
	page := sbom.ComponentPage{}
	err = WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			WITH latest_sbom AS (
				SELECT id, created_at
				FROM sboms
				WHERE tenant_id=$1 AND engagement_id=$2
				ORDER BY created_at DESC, id DESC
				LIMIT 1
			)
			SELECT c.tenant_id, s.engagement_id, c.sbom_id, c.id, c.name, c.version, c.purl,
			       c.cpe, c.cpe_part, c.cpe_vendor, c.cpe_product, c.cpe_status, c.cpe_reason, c.cpe_hash,
			       c.ecosystem, c.package_name, c.identity_hash, c.identity_status, c.identity_reason,
			       c.component_scope, c.reachability, c.class_unreferenced,
			       s.created_at
			FROM components c
			JOIN latest_sbom s ON s.id=c.sbom_id
			WHERE c.tenant_id=$1
			  AND ((c.identity_status='resolved' AND c.ecosystem=$3 AND c.package_name=$4)
			       OR (c.cpe_status='resolved' AND c.cpe_part=$5 AND c.cpe_vendor=$6 AND c.cpe_product=$7))
			  AND ($8::timestamptz IS NULL OR (s.created_at, s.id, c.id) < ($8, $9, $10))
			ORDER BY s.created_at DESC, s.id DESC, c.id DESC
			LIMIT $11`, tenantID.String(), query.EngagementID.String(), query.Ecosystem, query.Package, query.CPEPart, query.CPEVendor, query.CPEProduct, nullableInventoryTime(query.Cursor.BeforeSBOMCreatedAt), nullableID(query.Cursor.BeforeSBOMID), nullableID(query.Cursor.BeforeComponentID), query.Limit+1)
		if err != nil {
			return fmt.Errorf("list current components: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var item sbom.ComponentRecord
			if err := rows.Scan(&item.TenantID, &item.EngagementID, &item.SBOMID, &item.ComponentID, &item.Name, &item.Version, &item.PURL,
				&item.CPE, &item.CPEPart, &item.CPEVendor, &item.CPEProduct, &item.CPEStatus, &item.CPEReason, &item.CPEHash,
				&item.Ecosystem, &item.Package, &item.IdentityHash, &item.IdentityStatus, &item.IdentityReason, &item.Scope, &item.Reachability, &item.Unreferenced, &item.SBOMCreatedAt); err != nil {
				return fmt.Errorf("scan current component: %w", err)
			}
			page.Items = append(page.Items, item)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate current components: %w", err)
		}
		if len(page.Items) > query.Limit {
			page.Items = page.Items[:query.Limit]
			last := page.Items[len(page.Items)-1]
			page.Next = &sbom.ComponentCursor{BeforeSBOMCreatedAt: last.SBOMCreatedAt, BeforeSBOMID: last.SBOMID, BeforeComponentID: last.ComponentID}
		}
		return nil
	})
	if err != nil {
		return sbom.ComponentPage{}, err
	}
	return page, nil
}

func nullableInventoryTime(value interface{ IsZero() bool }) any {
	if value.IsZero() {
		return nil
	}
	return value
}

func nullableID(value shared.ID) any {
	if value.IsZero() {
		return nil
	}
	return value.String()
}
