package postgres

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestScanRepository(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := shared.WithTenant(context.Background(), shared.DefaultTenant)
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	eid := shared.ID("sc-" + randHex(t))
	e, err := engagement.New(eid, "", "scan-test", "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := NewEngagementRepository(pool).Create(ctx, e); err != nil {
		t.Fatalf("create engagement: %v", err)
	}
	t.Cleanup(func() {
		// components + vulns cascade from sboms; delete sboms by engagement first
		// (sboms.engagement_id is ON DELETE SET NULL, so it won't cascade from engagement).
		_, _ = pool.Exec(ctx, "DELETE FROM sboms WHERE engagement_id=$1", eid.String())
		_, _ = pool.Exec(ctx, "DELETE FROM engagements WHERE id=$1", eid.String())
	})

	doc := &sbom.SBOM{
		TargetRef: "/tmp/x", Source: "syft",
		Components: []sbom.Component{
			{Name: "django", Version: "2.2.0", PURL: "pkg:pypi/django@2.2.0"},
			{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"},
		},
	}
	vulns := []vulnerability.Vulnerability{
		{ID: "CVE-2019-1", Source: "osv", Severity: shared.SeverityCritical, CVSSScore: 9.8, CVSSVector: "CVSS:3.1/AV:N", Component: "django", Version: "2.2.0", FixedVersion: "2.2.28", Description: "x"},
		{ID: "CVE-orphan", Component: "ghost", Version: "9.9"}, // no matching component → skipped, not orphaned
	}

	snap := ports.ScanSnapshot{
		ToolVersions:   map[string]string{"syft": "1.45.1", "go-enry": "v2.9.0"},
		VulnDBSnapshot: "osv.dev@2026-06-20T00:00:00Z",
	}
	skipped, err := NewScanRepository(pool).SaveScan(ctx, eid, doc, vulns, snap)
	if err != nil {
		t.Fatalf("SaveScan: %v", err)
	}
	if skipped != 1 {
		t.Errorf("expected 1 skipped (orphan) vuln, got %d", skipped)
	}
	if _, err := NewScanRepository(pool).SaveScan(context.Background(), eid, doc, nil, snap); err == nil {
		t.Fatal("SaveScan without tenant context succeeded")
	}

	var nSbom, nComp, nVuln int
	pool.QueryRow(ctx, "SELECT count(*) FROM sboms WHERE engagement_id=$1 AND tenant_id='default'", eid.String()).Scan(&nSbom)
	pool.QueryRow(ctx, "SELECT count(*) FROM components c JOIN sboms s ON c.sbom_id=s.id WHERE s.engagement_id=$1 AND c.tenant_id=s.tenant_id", eid.String()).Scan(&nComp)
	pool.QueryRow(ctx, "SELECT count(*) FROM vulnerabilities v JOIN components c ON v.component_id=c.id JOIN sboms s ON c.sbom_id=s.id WHERE s.engagement_id=$1 AND v.tenant_id=c.tenant_id", eid.String()).Scan(&nVuln)
	if nSbom != 1 || nComp != 2 || nVuln != 1 {
		t.Errorf("persisted sbom=%d comp=%d vuln=%d, want 1/2/1 (orphan vuln skipped)", nSbom, nComp, nVuln)
	}

	var advisory, severity string
	var score float64
	pool.QueryRow(ctx,
		"SELECT advisory_id, severity, cvss_score FROM vulnerabilities v JOIN components c ON v.component_id=c.id JOIN sboms s ON c.sbom_id=s.id WHERE s.engagement_id=$1",
		eid.String()).Scan(&advisory, &severity, &score)
	if advisory != "CVE-2019-1" || severity != "critical" || score != 9.8 {
		t.Errorf("persisted vuln = %s/%s/%v, want CVE-2019-1/critical/9.8", advisory, severity, score)
	}

	// reproducibility: tool_versions + vuln_db_snapshot persisted
	var tvRaw, snapRaw string
	if err := pool.QueryRow(ctx,
		"SELECT COALESCE(tool_versions::text, ''), COALESCE(vuln_db_snapshot, '') FROM sboms WHERE engagement_id=$1",
		eid.String()).Scan(&tvRaw, &snapRaw); err != nil {
		t.Fatalf("read provenance: %v", err)
	}
	if !strings.Contains(tvRaw, `"syft"`) || snapRaw != "osv.dev@2026-06-20T00:00:00Z" {
		t.Errorf("provenance not persisted: tool_versions=%q snapshot=%q", tvRaw, snapRaw)
	}
}
