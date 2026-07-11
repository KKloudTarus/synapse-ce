package postgres

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"

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
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	sbomID := newID()
	source := doc.Source
	if source == "" {
		source = "syft"
	}
	toolVersions, err := json.Marshal(snap.ToolVersions)
	if err != nil {
		return 0, fmt.Errorf("marshal tool versions: %w", err)
	}
	// tenant_id '' = default tenant. Engagement-scoped READS are tenant-isolated at the
	// service/handler layer; deriving this row's tenant_id from the engagement is a
	// remaining row-level follow-up and does not affect read isolation today.
	// tool_versions + vuln_db_snapshot record reproducibility provenance.
	if _, err := tx.Exec(ctx,
		`INSERT INTO sboms (id, tenant_id, engagement_id, target_ref, source, tool_versions, vuln_db_snapshot, grype_database_version)
		 VALUES ($1, '', $2, $3, $4, $5, $6, $7)`,
		sbomID, engagementID.String(), doc.TargetRef, source, string(toolVersions), snap.VulnDBSnapshot, snap.GrypeDBVersion); err != nil {
		return 0, fmt.Errorf("insert sbom: %w", err)
	}

	// component identity (name\x00version -> generated component id) to link vulns.
	// The key relies on NUL being absent from a name/version (true for PURL-derived
	// values); a duplicate (name,version) in one SBOM resolves to the last inserted.
	compID := make(map[string]string, len(doc.Components))
	for _, c := range doc.Components {
		cid := newID()
		if _, err := tx.Exec(ctx,
			`INSERT INTO components (id, sbom_id, name, version, purl) VALUES ($1, $2, $3, $4, $5)`,
			cid, sbomID, c.Name, c.Version, c.PURL); err != nil {
			return 0, fmt.Errorf("insert component: %w", err)
		}
		compID[c.Name+"\x00"+c.Version] = cid
	}

	skipped := 0
	for _, v := range vulns {
		cid, ok := compID[v.Component+"\x00"+v.Version]
		if !ok {
			skipped++ // component not in this SBOM – counted + surfaced by the caller
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
			return 0, fmt.Errorf("marshal source metadata: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO vulnerabilities (id, component_id, advisory_id, source, severity, cvss_vector, cvss_score, kev, epss, fixed_version, description, sources, confidence, source_metadata)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
			newID(), cid, v.ID, src, string(v.Severity), v.CVSSVector, v.CVSSScore, v.KEV, v.EPSS, v.FixedVersion, v.Description, sources, confidence, meta); err != nil {
			return 0, fmt.Errorf("insert vulnerability: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return skipped, nil
}

// newID returns a random, unpredictable id for infra-only rows (SBOM / component /
// vulnerability have no domain identity, so they don't use ports.IDGenerator).
func newID() string {
	return rand.Text()
}
