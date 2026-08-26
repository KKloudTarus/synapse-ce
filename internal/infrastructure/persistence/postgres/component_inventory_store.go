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

// ListCurrentComponentsByEngagement returns the components of the engagement's latest SBOM (id + name +
// package only — enough to resolve a vulnerable ComponentID to a package name for running-vs-installed
// matching). Unlike ListCurrentComponents it takes no package/CPE key, so it can enumerate all components.
// Tenant-scoped via WithTenant (RLS) + an explicit tenant_id predicate.
func (s *ComponentInventoryStore) ListCurrentComponentsByEngagement(ctx context.Context, tenantID, engagementID shared.ID) ([]sbom.ComponentRecord, error) {
	if tenantID.IsZero() || engagementID.IsZero() {
		return nil, fmt.Errorf("%w: tenant and engagement are required", shared.ErrValidation)
	}
	out := make([]sbom.ComponentRecord, 0)
	err := WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			WITH latest_sbom AS (
				SELECT id FROM sboms
				WHERE tenant_id=$1 AND engagement_id=$2
				ORDER BY created_at DESC, id DESC
				LIMIT 1
			)
			SELECT c.id, c.name, c.package_name
			FROM components c
			JOIN latest_sbom s ON s.id=c.sbom_id
			WHERE c.tenant_id=$1
			ORDER BY c.id COLLATE "C"`, tenantID.String(), engagementID.String())
		if err != nil {
			return fmt.Errorf("list components by engagement: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			item := sbom.ComponentRecord{TenantID: tenantID, EngagementID: engagementID}
			var id string
			if err := rows.Scan(&id, &item.Name, &item.Package); err != nil {
				return fmt.Errorf("scan component: %w", err)
			}
			item.ComponentID = shared.ID(id)
			out = append(out, item)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

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
				SELECT id, engagement_id, created_at
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
