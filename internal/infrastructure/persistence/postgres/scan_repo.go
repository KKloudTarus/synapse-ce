package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ScanRepository persists SCA scans (SBOM + components + vulnerabilities).
type ScanRepository struct{ pool *pgxpool.Pool }

// NewScanRepository returns a repository backed by the given pool.
func NewScanRepository(pool *pgxpool.Pool) *ScanRepository { return &ScanRepository{pool: pool} }

var _ ports.ScanRepository = (*ScanRepository)(nil)

func (r *ScanRepository) AdmitInventory(ctx context.Context, engagementID shared.ID, scope string, admittedAt time.Time) (sbom.InventoryAdmission, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return sbom.InventoryAdmission{}, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	tenantID = shared.TenantOrDefault(tenantID)
	scope = strings.TrimSpace(scope)
	if engagementID.IsZero() || scope == "" || admittedAt.IsZero() {
		return sbom.InventoryAdmission{}, fmt.Errorf("%w: inventory admission identity is required", shared.ErrValidation)
	}
	admission := sbom.InventoryAdmission{TenantID: tenantID, EngagementID: engagementID, Scope: scope, AdmittedAt: admittedAt.UTC()}
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO vulnerability_inventory_scopes
			(tenant_id, engagement_id, inventory_scope, latest_admitted_generation, created_at, updated_at)
			VALUES ($1,$2,$3,1,$4,$4)
			ON CONFLICT (tenant_id, engagement_id, inventory_scope) DO UPDATE SET
				latest_admitted_generation=vulnerability_inventory_scopes.latest_admitted_generation+1,
				updated_at=EXCLUDED.updated_at
			RETURNING latest_admitted_generation`, tenantID.String(), engagementID.String(), scope, admission.AdmittedAt).Scan(&admission.Generation)
	})
	if err != nil {
		return sbom.InventoryAdmission{}, fmt.Errorf("admit inventory generation: %w", err)
	}
	return admission, nil
}

// SaveScan stores the SBOM, its components, and the vulnerabilities found against
// them in one transaction – a new immutable snapshot per scan. It returns the
// number of vulns that could not be linked to a component in this SBOM (skipped,
// never orphaned); the caller surfaces a non-zero count on the audit log so a
// dropped advisory is never invisible on a chain-of-custody tool.
func (r *ScanRepository) SaveScan(ctx context.Context, engagementID shared.ID, doc *sbom.SBOM, vulns []vulnerability.Vulnerability, snap ports.ScanSnapshot) (ports.ScanSaveResult, error) {
	if doc == nil {
		return ports.ScanSaveResult{}, nil
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return ports.ScanSaveResult{}, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	tenantID = shared.TenantOrDefault(tenantID)
	admission := snap.InventoryAdmission
	legacyAdmission := admission.Generation <= 0
	if legacyAdmission {
		var err error
		admission, err = r.AdmitInventory(ctx, engagementID, sbom.InventoryScope(doc.TargetRef), time.Now().UTC())
		if err != nil {
			return ports.ScanSaveResult{}, err
		}
	}
	if err := admission.Validate(); err != nil || admission.TenantID != tenantID || admission.EngagementID != engagementID {
		return ports.ScanSaveResult{}, fmt.Errorf("%w: inventory admission does not match scan", shared.ErrValidation)
	}
	toolVersions, err := json.Marshal(snap.ToolVersions)
	if err != nil {
		return ports.ScanSaveResult{}, fmt.Errorf("marshal tool versions: %w", err)
	}
	skipped := 0
	publication := sbom.InventoryPublication{}
	err = WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		var ownerTenant string
		if err := tx.QueryRow(ctx, `SELECT tenant_id FROM engagements WHERE id=$1`, engagementID.String()).Scan(&ownerTenant); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("engagement %s: %w", engagementID, shared.ErrNotFound)
			}
			return fmt.Errorf("load engagement tenant: %w", err)
		}

		var latestGeneration int64
		if err := tx.QueryRow(ctx, `SELECT latest_admitted_generation FROM vulnerability_inventory_scopes
			WHERE tenant_id=$1 AND engagement_id=$2 AND inventory_scope=$3 FOR UPDATE`, tenantID.String(), engagementID.String(), admission.Scope).Scan(&latestGeneration); err != nil {
			return fmt.Errorf("load admitted inventory generation: %w", err)
		}
		if admission.Generation > latestGeneration {
			return fmt.Errorf("%w: inventory generation was not admitted", shared.ErrValidation)
		}

		sbomID := inventorySBOMID(admission)
		source := doc.Source
		if source == "" {
			source = "syft"
		}
		coverage := sbom.IdentityCoverage{Total: len(doc.Components)}
		for _, component := range doc.Components {
			identity := sbom.IdentityFromComponent(component)
			cpeIdentity := sbom.IdentityFromCPE(component.CPE, component.Version)
			if identity.Status == sbom.IdentityResolved || cpeIdentity.Status == sbom.IdentityResolved {
				coverage.Resolved++
			} else {
				coverage.Unsupported++
			}
		}
		completeness := snap.InventoryCompleteness
		if !completeness.Valid() {
			completeness = sbom.InventoryUnknown
		}
		authoritative := snap.InventoryAuthoritative && !legacyAdmission
		reason := strings.TrimSpace(snap.InventoryAuthorityReason)
		if legacyAdmission {
			reason = "legacy_writer_without_admission"
		}
		publishedAt := time.Now().UTC()
		publication = sbom.InventoryPublication{InventoryAdmission: admission, SBOMID: shared.ID(sbomID), Completeness: completeness,
			Authoritative: authoritative, AuthorityReason: reason, Coverage: coverage, PublishedAt: publishedAt}
		if err := publication.Validate(); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx,
			`INSERT INTO sboms (id, tenant_id, engagement_id, target_ref, source, tool_versions, vuln_db_snapshot, grype_database_version,
			 inventory_scope, inventory_generation, inventory_completeness, inventory_authoritative, inventory_authority_reason,
			 identity_total, identity_resolved, identity_unsupported, inventory_admitted_at, inventory_published_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
			 ON CONFLICT (id) DO NOTHING`,
			sbomID, ownerTenant, engagementID.String(), doc.TargetRef, source, string(toolVersions), snap.VulnDBSnapshot, snap.GrypeDBVersion,
			admission.Scope, admission.Generation, completeness, authoritative, reason, coverage.Total, coverage.Resolved, coverage.Unsupported, admission.AdmittedAt, publishedAt)
		if err != nil {
			return fmt.Errorf("insert sbom: %w", err)
		}
		if tag.RowsAffected() == 0 {
			var storedCompleteness string
			if err := tx.QueryRow(ctx, `SELECT inventory_completeness, inventory_authoritative, inventory_authority_reason,
				identity_total, identity_resolved, identity_unsupported, inventory_admitted_at, inventory_published_at,
				EXISTS (SELECT 1 FROM vulnerability_inventory_scopes inventory
					WHERE inventory.tenant_id=s.tenant_id AND inventory.engagement_id=s.engagement_id
					  AND inventory.inventory_scope=s.inventory_scope AND inventory.current_generation=s.inventory_generation
					  AND inventory.current_sbom_id=s.id)
				FROM sboms s WHERE s.tenant_id=$1 AND s.engagement_id=$2 AND s.id=$3
				  AND s.inventory_scope=$4 AND s.inventory_generation=$5`, tenantID.String(), engagementID.String(), sbomID, admission.Scope, admission.Generation).Scan(
				&storedCompleteness, &publication.Authoritative, &publication.AuthorityReason, &publication.Coverage.Total,
				&publication.Coverage.Resolved, &publication.Coverage.Unsupported, &publication.AdmittedAt, &publication.PublishedAt, &publication.Current); err != nil {
				return fmt.Errorf("load idempotent inventory publication: %w", err)
			}
			publication.TenantID = tenantID
			publication.EngagementID = engagementID
			publication.Scope = admission.Scope
			publication.Generation = admission.Generation
			publication.SBOMID = shared.ID(sbomID)
			publication.Completeness = sbom.InventoryCompleteness(storedCompleteness)
			publication.Superseded = publication.Authoritative && publication.Completeness == sbom.InventoryComplete && !publication.Current
			skipped = countUnlinkedVulnerabilities(doc, vulns)
			return publication.Validate()
		}

		compID := make(map[string]string, len(doc.Components))
		for _, c := range doc.Components {
			cid := newID()
			identity := sbom.IdentityFromComponent(c)
			cpeIdentity := sbom.IdentityFromCPE(c.CPE, c.Version)
			scope, reachability, unreferenced := inventoryRiskContext(c)
			if _, err := tx.Exec(ctx,
				`INSERT INTO components (id, tenant_id, sbom_id, name, version, purl, cpe, cpe_part, cpe_vendor, cpe_product, cpe_hash, cpe_status, cpe_reason, ecosystem, package_name, identity_hash, identity_status, identity_reason, component_scope, reachability, class_unreferenced)
				 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)`,
				cid, ownerTenant, sbomID, c.Name, c.Version, c.PURL, cpeIdentity.Canonical, cpeIdentity.CPE.Part, cpeIdentity.CPE.Vendor, cpeIdentity.CPE.Product, cpeIdentity.Fingerprint, cpeIdentity.Status, cpeIdentity.Reason,
				identity.Ecosystem, identity.Package, identity.Fingerprint, identity.Status, identity.Reason, scope, reachability, unreferenced); err != nil {
				return fmt.Errorf("insert component: %w", err)
			}
			compID[c.Name+"\x00"+c.Version] = cid
		}

		for _, v := range vulns {
			cid, ok := compID[v.Component+"\x00"+v.Version]
			if !ok {
				skipped++
				continue
			}
			src := v.Source
			if src == "" {
				src = "osv"
			}
			sources := strings.Join(v.Sources, ",")
			if sources == "" {
				sources = src
			}
			confidence := v.Confidence
			if confidence == "" {
				confidence = "medium"
			}
			meta, err := json.Marshal(v.Detections)
			if err != nil {
				return fmt.Errorf("marshal source metadata: %w", err)
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO vulnerabilities (id, tenant_id, component_id, advisory_id, source, severity, cvss_vector, cvss_score, kev, epss, fixed_version, description, sources, confidence, source_metadata)
				 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
				newID(), ownerTenant, cid, v.ID, src, string(v.Severity), v.CVSSVector, v.CVSSScore, v.KEV, v.EPSS, v.FixedVersion, v.Description, sources, confidence, meta); err != nil {
				return fmt.Errorf("insert vulnerability: %w", err)
			}
		}
		if authoritative && completeness == sbom.InventoryComplete {
			tag, err := tx.Exec(ctx, `UPDATE vulnerability_inventory_scopes SET
				current_generation=$4, current_sbom_id=$5, current_published_at=$6, updated_at=$6
				WHERE tenant_id=$1 AND engagement_id=$2 AND inventory_scope=$3
				  AND latest_admitted_generation=$4 AND COALESCE(current_generation,0)<$4`,
				tenantID.String(), engagementID.String(), admission.Scope, admission.Generation, sbomID, publishedAt)
			if err != nil {
				return fmt.Errorf("publish current inventory generation: %w", err)
			}
			if tag.RowsAffected() == 1 {
				publication.Current = true
				if _, err := tx.Exec(ctx, `INSERT INTO vulnerability_inventory_work
					(tenant_id, engagement_id, inventory_scope, inventory_generation, sbom_id, state, stage, next_attempt_at, created_at, updated_at)
					VALUES ($1,$2,$3,$4,$5,'pending','candidates',$6,$6,$6)
					ON CONFLICT (tenant_id, engagement_id, inventory_scope, inventory_generation) DO NOTHING`,
					tenantID.String(), engagementID.String(), admission.Scope, admission.Generation, sbomID, publishedAt); err != nil {
					return fmt.Errorf("persist inventory correlation work: %w", err)
				}
			} else {
				publication.Superseded = true
			}
		}
		return nil
	})
	if err != nil {
		return ports.ScanSaveResult{}, err
	}
	return ports.ScanSaveResult{SkippedVulnerabilities: skipped, Publication: publication}, nil
}

func inventorySBOMID(admission sbom.InventoryAdmission) string {
	digest := sha256.Sum256([]byte(strings.Join([]string{admission.TenantID.String(), admission.EngagementID.String(), admission.Scope, fmt.Sprint(admission.Generation)}, "\x00")))
	return "vi-" + hex.EncodeToString(digest[:16])
}

func countUnlinkedVulnerabilities(doc *sbom.SBOM, vulns []vulnerability.Vulnerability) int {
	components := make(map[string]struct{}, len(doc.Components))
	for _, component := range doc.Components {
		components[component.Name+"\x00"+component.Version] = struct{}{}
	}
	skipped := 0
	for _, item := range vulns {
		if _, ok := components[item.Component+"\x00"+item.Version]; !ok {
			skipped++
		}
	}
	return skipped
}

func inventoryRiskContext(component sbom.Component) (string, string, bool) {
	scope := strings.TrimSpace(component.Scope)
	if scope == "" {
		scope = sbom.ScopeUnknown
	}
	switch component.Reachability {
	case sbom.ReachabilityReachable:
		return scope, vulnerability.ReachHigh, false
	case sbom.ReachabilityUnreferenced:
		return scope, vulnerability.ReachLow, true
	default:
		return scope, vulnerability.ReachUnknown, false
	}
}

// newID returns a random, unpredictable id for infra-only rows (SBOM / component /
// vulnerability have no domain identity, so they don't use ports.IDGenerator).
func newID() string {
	return rand.Text()
}
