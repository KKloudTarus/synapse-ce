package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

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
var _ ports.InventoryWorkStore = (*ComponentInventoryStore)(nil)

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
				SELECT id, engagement_id, created_at,
				       COALESCE(to_jsonb(s)->>'inventory_scope','') AS inventory_scope,
				       COALESCE(NULLIF(to_jsonb(s)->>'inventory_generation','')::bigint,0) AS inventory_generation
				FROM sboms s
				WHERE tenant_id=$1 AND engagement_id=$2
				  AND ($8='' OR (id=$8 AND COALESCE(to_jsonb(s)->>'inventory_scope','')=$9
				       AND COALESCE(NULLIF(to_jsonb(s)->>'inventory_generation','')::bigint,0)=$10))
				ORDER BY created_at DESC, id DESC
				LIMIT 1
			)
			SELECT c.tenant_id, s.engagement_id, c.sbom_id, c.id, c.name, c.version, c.purl,
			       c.cpe, c.cpe_part, c.cpe_vendor, c.cpe_product, c.cpe_status, c.cpe_reason, c.cpe_hash,
			       c.ecosystem, c.package_name, c.identity_hash, c.identity_status, c.identity_reason,
			       c.component_scope, c.reachability, c.class_unreferenced,
			       s.created_at, s.inventory_scope, s.inventory_generation
			FROM components c
			JOIN latest_sbom s ON s.id=c.sbom_id
			WHERE c.tenant_id=$1
			  AND ((c.identity_status='resolved' AND c.ecosystem=$3 AND c.package_name=$4)
			       OR (c.cpe_status='resolved' AND c.cpe_part=$5 AND c.cpe_vendor=$6 AND c.cpe_product=$7))
			  AND ($11::timestamptz IS NULL OR (s.created_at, s.id, c.id) < ($11, $12, $13))
			ORDER BY s.created_at DESC, s.id DESC, c.id DESC
			LIMIT $14`, tenantID.String(), query.EngagementID.String(), query.Ecosystem, query.Package, query.CPEPart, query.CPEVendor, query.CPEProduct,
			query.SBOMID.String(), query.InventoryScope, query.InventoryGeneration,
			nullableInventoryTime(query.Cursor.BeforeSBOMCreatedAt), nullableID(query.Cursor.BeforeSBOMID), nullableID(query.Cursor.BeforeComponentID), query.Limit+1)
		if err != nil {
			return fmt.Errorf("list current components: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var item sbom.ComponentRecord
			if err := rows.Scan(&item.TenantID, &item.EngagementID, &item.SBOMID, &item.ComponentID, &item.Name, &item.Version, &item.PURL,
				&item.CPE, &item.CPEPart, &item.CPEVendor, &item.CPEProduct, &item.CPEStatus, &item.CPEReason, &item.CPEHash,
				&item.Ecosystem, &item.Package, &item.IdentityHash, &item.IdentityStatus, &item.IdentityReason, &item.Scope, &item.Reachability, &item.Unreferenced,
				&item.SBOMCreatedAt, &item.InventoryScope, &item.InventoryGeneration); err != nil {
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

func (s *ComponentInventoryStore) ListSnapshotComponents(ctx context.Context, query sbom.SnapshotQuery) (sbom.ComponentPage, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return sbom.ComponentPage{}, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	tenantID = shared.TenantOrDefault(tenantID)
	if !query.TenantID.IsZero() && shared.TenantOrDefault(query.TenantID) != tenantID {
		return sbom.ComponentPage{}, fmt.Errorf("%w: snapshot query tenant does not match context", shared.ErrValidation)
	}
	query.TenantID = tenantID
	query, err := query.Normalize()
	if err != nil {
		return sbom.ComponentPage{}, err
	}
	page := sbom.ComponentPage{}
	err = WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT c.tenant_id, s.engagement_id, c.sbom_id, c.id, c.name, c.version, c.purl,
			c.cpe, c.cpe_part, c.cpe_vendor, c.cpe_product, c.cpe_status, c.cpe_reason, c.cpe_hash,
			c.ecosystem, c.package_name, c.identity_hash, c.identity_status, c.identity_reason,
			c.component_scope, c.reachability, c.class_unreferenced, s.created_at, s.inventory_scope, s.inventory_generation
			FROM sboms s JOIN components c ON c.tenant_id=s.tenant_id AND c.sbom_id=s.id
			WHERE s.tenant_id=$1 AND s.engagement_id=$2 AND s.id=$3 AND s.inventory_scope=$4 AND s.inventory_generation=$5
			  AND c.id>$6
			ORDER BY c.id COLLATE "C" LIMIT $7`, tenantID.String(), query.EngagementID.String(), query.SBOMID.String(),
			query.InventoryScope, query.InventoryGeneration, query.AfterComponentID.String(), query.Limit+1)
		if err != nil {
			return fmt.Errorf("list immutable snapshot components: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var item sbom.ComponentRecord
			if err := rows.Scan(&item.TenantID, &item.EngagementID, &item.SBOMID, &item.ComponentID, &item.Name, &item.Version, &item.PURL,
				&item.CPE, &item.CPEPart, &item.CPEVendor, &item.CPEProduct, &item.CPEStatus, &item.CPEReason, &item.CPEHash,
				&item.Ecosystem, &item.Package, &item.IdentityHash, &item.IdentityStatus, &item.IdentityReason, &item.Scope, &item.Reachability, &item.Unreferenced,
				&item.SBOMCreatedAt, &item.InventoryScope, &item.InventoryGeneration); err != nil {
				return fmt.Errorf("scan immutable snapshot component: %w", err)
			}
			page.Items = append(page.Items, item)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate immutable snapshot components: %w", err)
		}
		if len(page.Items) > query.Limit {
			page.Items = page.Items[:query.Limit]
			last := page.Items[len(page.Items)-1]
			page.Next = &sbom.ComponentCursor{BeforeSBOMID: query.SBOMID, BeforeComponentID: last.ComponentID}
		}
		return nil
	})
	return page, err
}

func (s *ComponentInventoryStore) ListCurrentInventoryPublications(ctx context.Context, tenantID shared.ID, cursor sbom.InventoryCursor, limit int) (sbom.InventoryPublicationPage, error) {
	contextTenant, ok := shared.TenantFrom(ctx)
	tenantID = shared.TenantOrDefault(tenantID)
	if !ok || shared.TenantOrDefault(contextTenant) != tenantID {
		return sbom.InventoryPublicationPage{}, fmt.Errorf("%w: inventory publication tenant does not match context", shared.ErrValidation)
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	page := sbom.InventoryPublicationPage{}
	err := WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT s.tenant_id,s.engagement_id,s.inventory_scope,s.inventory_generation,
			s.inventory_admitted_at,s.id,s.inventory_completeness,s.inventory_authoritative,s.inventory_authority_reason,
			s.identity_total,s.identity_resolved,s.identity_unsupported,s.inventory_published_at
			FROM vulnerability_inventory_scopes inventory
			JOIN sboms s ON s.tenant_id=inventory.tenant_id AND s.id=inventory.current_sbom_id
			WHERE inventory.tenant_id=$1 AND ROW(inventory.engagement_id COLLATE "C",inventory.inventory_scope COLLATE "C")
				> ROW($2::text COLLATE "C",$3::text COLLATE "C")
			ORDER BY inventory.engagement_id COLLATE "C",inventory.inventory_scope COLLATE "C" LIMIT $4`,
			tenantID.String(), cursor.AfterEngagementID.String(), cursor.AfterScope, limit+1)
		if err != nil {
			return fmt.Errorf("list current inventory publications: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			item, err := scanInventoryPublication(rows)
			if err != nil {
				return err
			}
			page.Items = append(page.Items, item)
		}
		return rows.Err()
	})
	if err != nil {
		return sbom.InventoryPublicationPage{}, err
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[len(page.Items)-1]
		page.Next = &sbom.InventoryCursor{AfterEngagementID: last.EngagementID, AfterScope: last.Scope}
	}
	return page, nil
}

func (s *ComponentInventoryStore) GetCurrentInventoryPublication(ctx context.Context, tenantID, engagementID shared.ID, scope string) (sbom.InventoryPublication, error) {
	contextTenant, ok := shared.TenantFrom(ctx)
	tenantID = shared.TenantOrDefault(tenantID)
	if !ok || shared.TenantOrDefault(contextTenant) != tenantID || engagementID.IsZero() || scope == "" {
		return sbom.InventoryPublication{}, fmt.Errorf("%w: inventory publication identity is invalid", shared.ErrValidation)
	}
	var item sbom.InventoryPublication
	err := WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		var err error
		item, err = scanInventoryPublication(tx.QueryRow(ctx, `SELECT s.tenant_id,s.engagement_id,s.inventory_scope,s.inventory_generation,
			s.inventory_admitted_at,s.id,s.inventory_completeness,s.inventory_authoritative,s.inventory_authority_reason,
			s.identity_total,s.identity_resolved,s.identity_unsupported,s.inventory_published_at
			FROM vulnerability_inventory_scopes inventory
			JOIN sboms s ON s.tenant_id=inventory.tenant_id AND s.id=inventory.current_sbom_id
			WHERE inventory.tenant_id=$1 AND inventory.engagement_id=$2 AND inventory.inventory_scope=$3`, tenantID.String(), engagementID.String(), scope))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return sbom.InventoryPublication{}, shared.ErrNotFound
	}
	return item, err
}

type inventoryPublicationScanner interface{ Scan(...any) error }

func scanInventoryPublication(row inventoryPublicationScanner) (sbom.InventoryPublication, error) {
	var item sbom.InventoryPublication
	var completeness string
	if err := row.Scan(&item.TenantID, &item.EngagementID, &item.Scope, &item.Generation, &item.AdmittedAt, &item.SBOMID,
		&completeness, &item.Authoritative, &item.AuthorityReason, &item.Coverage.Total, &item.Coverage.Resolved,
		&item.Coverage.Unsupported, &item.PublishedAt); err != nil {
		return sbom.InventoryPublication{}, err
	}
	item.Completeness = sbom.InventoryCompleteness(completeness)
	item.Current = true
	if err := item.Validate(); err != nil {
		return sbom.InventoryPublication{}, err
	}
	return item, nil
}

func (s *ComponentInventoryStore) ClaimInventoryWork(ctx context.Context, tenantID shared.ID, owner string, at time.Time, lease time.Duration, limit int) ([]sbom.InventoryWork, error) {
	contextTenant, ok := shared.TenantFrom(ctx)
	tenantID = shared.TenantOrDefault(tenantID)
	owner = strings.TrimSpace(owner)
	if !ok || shared.TenantOrDefault(contextTenant) != tenantID || owner == "" || at.IsZero() || lease <= 0 {
		return nil, fmt.Errorf("%w: inventory work lease identity is invalid", shared.ErrValidation)
	}
	if limit <= 0 {
		limit = 25
	}
	if limit > 100 {
		limit = 100
	}
	result := make([]sbom.InventoryWork, 0)
	err := WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE vulnerability_inventory_work work SET state='skipped',stage='completed',reason='superseded_inventory_generation',lease_owner='',lease_until=NULL,updated_at=$2
			WHERE work.tenant_id=$1 AND work.state IN ('pending','retry','running') AND NOT EXISTS (
				SELECT 1 FROM vulnerability_inventory_scopes inventory WHERE inventory.tenant_id=work.tenant_id
				AND inventory.engagement_id=work.engagement_id AND inventory.inventory_scope=work.inventory_scope
				AND inventory.current_generation=work.inventory_generation AND inventory.current_sbom_id=work.sbom_id)`, tenantID.String(), at.UTC()); err != nil {
			return fmt.Errorf("skip superseded inventory work: %w", err)
		}
		rows, err := tx.Query(ctx, `WITH candidates AS (
			SELECT work.tenant_id,work.engagement_id,work.inventory_scope,work.inventory_generation
			FROM vulnerability_inventory_work work
			WHERE work.tenant_id=$1 AND (((work.state='pending' OR work.state='retry') AND work.next_attempt_at<=$3)
				OR (work.state='running' AND work.lease_until<=$3))
			ORDER BY work.next_attempt_at,work.engagement_id COLLATE "C",work.inventory_scope COLLATE "C",work.inventory_generation
			FOR UPDATE SKIP LOCKED LIMIT $5
		), claimed AS (
			UPDATE vulnerability_inventory_work work SET state='running',attempt=work.attempt+1,lease_owner=$2,lease_until=$3+($4 * interval '1 microsecond'),updated_at=$3
			FROM candidates c WHERE work.tenant_id=c.tenant_id AND work.engagement_id=c.engagement_id
				AND work.inventory_scope=c.inventory_scope AND work.inventory_generation=c.inventory_generation
			RETURNING work.*
		)
		SELECT s.tenant_id,s.engagement_id,s.inventory_scope,s.inventory_generation,s.inventory_admitted_at,s.id,
			s.inventory_completeness,s.inventory_authoritative,s.inventory_authority_reason,s.identity_total,s.identity_resolved,
			s.identity_unsupported,s.inventory_published_at,c.state,c.attempt,c.reason,c.lease_owner,c.lease_until,c.next_attempt_at,c.created_at,c.updated_at
		FROM claimed c JOIN sboms s ON s.tenant_id=c.tenant_id AND s.id=c.sbom_id
		ORDER BY c.next_attempt_at,c.engagement_id COLLATE "C",c.inventory_scope COLLATE "C",c.inventory_generation`,
			tenantID.String(), owner, at.UTC(), lease.Microseconds(), limit)
		if err != nil {
			return fmt.Errorf("claim inventory correlation work: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var work sbom.InventoryWork
			var completeness, state string
			if err := rows.Scan(&work.Publication.TenantID, &work.Publication.EngagementID, &work.Publication.Scope,
				&work.Publication.Generation, &work.Publication.AdmittedAt, &work.Publication.SBOMID, &completeness,
				&work.Publication.Authoritative, &work.Publication.AuthorityReason, &work.Publication.Coverage.Total,
				&work.Publication.Coverage.Resolved, &work.Publication.Coverage.Unsupported, &work.Publication.PublishedAt,
				&state, &work.Attempt, &work.Reason, &work.LeaseOwner, &work.LeaseUntil, &work.NextAttemptAt, &work.CreatedAt, &work.UpdatedAt); err != nil {
				return err
			}
			work.Publication.Completeness, work.Publication.Current = sbom.InventoryCompleteness(completeness), true
			work.State = sbom.InventoryWorkState(state)
			if err := work.Validate(); err != nil {
				return err
			}
			result = append(result, work)
		}
		return rows.Err()
	})
	return result, err
}

func (s *ComponentInventoryStore) FinishInventoryWork(ctx context.Context, work sbom.InventoryWork, owner string, state sbom.InventoryWorkState, reason string, nextAttemptAt, at time.Time) error {
	tenantID, ok := shared.TenantFrom(ctx)
	owner, reason = strings.TrimSpace(owner), strings.TrimSpace(reason)
	if !ok || shared.TenantOrDefault(tenantID) != shared.TenantOrDefault(work.Publication.TenantID) || owner == "" || (!state.Terminal() && state != sbom.InventoryWorkRetry) || at.IsZero() {
		return fmt.Errorf("%w: invalid inventory work completion", shared.ErrValidation)
	}
	if len(reason) > 2048 {
		reason = reason[:2048]
	}
	if state == sbom.InventoryWorkRetry && (nextAttemptAt.IsZero() || nextAttemptAt.Before(at)) {
		return fmt.Errorf("%w: invalid inventory retry time", shared.ErrValidation)
	}
	return WithContextTenant(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE vulnerability_inventory_work work SET state=$6,stage=CASE WHEN $6 IN ('completed','skipped','poisoned') THEN 'completed' ELSE stage END,
			reason=$7,lease_owner='',lease_until=NULL,next_attempt_at=CASE WHEN $6='retry' THEN $8 ELSE next_attempt_at END,updated_at=$9
			WHERE work.tenant_id=current_setting('app.current_tenant') AND work.engagement_id=$1 AND work.inventory_scope=$2
				AND work.inventory_generation=$3 AND work.sbom_id=$4 AND work.state='running' AND work.lease_owner=$5 AND work.lease_until>$9
				AND EXISTS (SELECT 1 FROM vulnerability_inventory_scopes inventory WHERE inventory.tenant_id=work.tenant_id
					AND inventory.engagement_id=work.engagement_id AND inventory.inventory_scope=work.inventory_scope
					AND inventory.current_generation=work.inventory_generation AND inventory.current_sbom_id=work.sbom_id)`,
			work.Publication.EngagementID.String(), work.Publication.Scope, work.Publication.Generation, work.Publication.SBOMID.String(), owner, string(state), reason, nextAttemptAt.UTC(), at.UTC())
		if err != nil {
			return fmt.Errorf("finish inventory correlation work: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return shared.ErrConflict
		}
		return nil
	})
}

func (s *ComponentInventoryStore) CompleteInventoryPublication(ctx context.Context, publication sbom.InventoryPublication, at time.Time) error {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || shared.TenantOrDefault(tenantID) != shared.TenantOrDefault(publication.TenantID) || at.IsZero() {
		return fmt.Errorf("%w: invalid inventory publication completion", shared.ErrValidation)
	}
	return WithContextTenant(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE vulnerability_inventory_work work SET state='completed',stage='completed',reason='',lease_owner='',lease_until=NULL,updated_at=$5
			WHERE work.tenant_id=current_setting('app.current_tenant') AND work.engagement_id=$1 AND work.inventory_scope=$2
				AND work.inventory_generation=$3 AND work.sbom_id=$4 AND work.state IN ('pending','retry','running','completed')
				AND EXISTS (SELECT 1 FROM vulnerability_inventory_scopes inventory WHERE inventory.tenant_id=work.tenant_id
					AND inventory.engagement_id=work.engagement_id AND inventory.inventory_scope=work.inventory_scope
					AND inventory.current_generation=work.inventory_generation AND inventory.current_sbom_id=work.sbom_id)`,
			publication.EngagementID.String(), publication.Scope, publication.Generation, publication.SBOMID.String(), at.UTC())
		if err != nil {
			return fmt.Errorf("complete inventory publication: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return shared.ErrConflict
		}
		return nil
	})
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
