package postgres

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

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

// SaveScan stores the SBOM, its components, and the vulnerabilities found against
// them in one transaction – a new immutable snapshot per scan. It returns the
// number of vulns that could not be linked to a component in this SBOM (skipped,
// never orphaned); the caller surfaces a non-zero count on the audit log so a
// dropped advisory is never invisible on a chain-of-custody tool.
func (r *ScanRepository) SaveScan(ctx context.Context, engagementID shared.ID, doc *sbom.SBOM, vulns []vulnerability.Vulnerability, snap ports.ScanSnapshot) (int, error) {
	if doc == nil {
		return 0, nil
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return 0, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	toolVersions, err := json.Marshal(snap.ToolVersions)
	if err != nil {
		return 0, fmt.Errorf("marshal tool versions: %w", err)
	}
	skipped := 0
	err = WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		var ownerTenant string
		if err := tx.QueryRow(ctx, `SELECT tenant_id FROM engagements WHERE id=$1`, engagementID.String()).Scan(&ownerTenant); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("engagement %s: %w", engagementID, shared.ErrNotFound)
			}
			return fmt.Errorf("load engagement tenant: %w", err)
		}

		sbomID := newID()
		source := doc.Source
		if source == "" {
			source = "syft"
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO sboms (id, tenant_id, engagement_id, target_ref, source, tool_versions, vuln_db_snapshot, grype_database_version)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			sbomID, ownerTenant, engagementID.String(), doc.TargetRef, source, string(toolVersions), snap.VulnDBSnapshot, snap.GrypeDBVersion); err != nil {
			return fmt.Errorf("insert sbom: %w", err)
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
		return nil
	})
	if err != nil {
		return 0, err
	}
	return skipped, nil
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
