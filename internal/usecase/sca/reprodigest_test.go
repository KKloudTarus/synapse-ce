package sca

import (
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
)

func comp(name, ver, purl string) sbom.Component {
	return sbom.Component{Name: name, Version: ver, PURL: purl}
}
func find(dedup string, sev shared.Severity) finding.Finding {
	return finding.Finding{Kind: finding.KindSCA, DedupKey: dedup, Severity: sev}
}

// TestReproDigestStableAcrossOrderTimestampDBAndID: the same reproducible CONTENT yields the same digest even
// when component/finding order differs and the (excluded) timestamps, vuln-DB snapshot, tool versions, and
// finding ids all differ – proving the digest reflects only reproducible content.
func TestReproDigestStableAcrossOrderTimestampDBAndID(t *testing.T) {
	a := &ScanResult{
		SBOM:     &sbom.SBOM{Components: []sbom.Component{comp("a", "1.0", "pkg:golang/a@1.0"), comp("b", "2.0", "pkg:npm/b@2.0")}},
		Findings: []finding.Finding{find("vuln:CVE-1:a:1.0", shared.SeverityHigh)},
	}
	b := &ScanResult{
		// components + findings in a DIFFERENT order; per-run fields all differ (must be ignored)
		SBOM: &sbom.SBOM{Components: []sbom.Component{comp("b", "2.0", "pkg:npm/b@2.0"), comp("a", "1.0", "pkg:golang/a@1.0")}},
		Findings: []finding.Finding{{
			Kind: finding.KindSCA, DedupKey: "vuln:CVE-1:a:1.0", Severity: shared.SeverityHigh,
			ID: "a-different-id", Audit: shared.Audit{CreatedAt: time.Unix(42, 0), UpdatedAt: time.Unix(99, 0)},
		}},
		ToolVersions:   map[string]string{"syft": "9.9.9", "epss-date": "2099-01-01"},
		VulnDBSnapshot: "osv.dev@2099-01-01T00:00:00Z",
	}
	da, db := ReproDigest(a), ReproDigest(b)
	if da == "" || da != db {
		t.Fatalf("same content must yield the same digest regardless of order/timestamp/db/id: %q vs %q", da, db)
	}
	if da != ReproDigest(a) {
		t.Fatal("digest must be deterministic across calls")
	}
}

func TestReproDigestContentSensitive(t *testing.T) {
	d0 := ReproDigest(&ScanResult{
		SBOM:     &sbom.SBOM{Components: []sbom.Component{comp("a", "1.0", "pkg:golang/a@1.0")}},
		Findings: []finding.Finding{find("vuln:CVE-1:a:1.0", shared.SeverityHigh)},
	})
	cases := map[string]*ScanResult{
		"extra component": {
			SBOM:     &sbom.SBOM{Components: []sbom.Component{comp("a", "1.0", "pkg:golang/a@1.0"), comp("c", "3.0", "pkg:golang/c@3.0")}},
			Findings: []finding.Finding{find("vuln:CVE-1:a:1.0", shared.SeverityHigh)},
		},
		"changed severity": {
			SBOM:     &sbom.SBOM{Components: []sbom.Component{comp("a", "1.0", "pkg:golang/a@1.0")}},
			Findings: []finding.Finding{find("vuln:CVE-1:a:1.0", shared.SeverityCritical)},
		},
		"extra finding": {
			SBOM:     &sbom.SBOM{Components: []sbom.Component{comp("a", "1.0", "pkg:golang/a@1.0")}},
			Findings: []finding.Finding{find("vuln:CVE-1:a:1.0", shared.SeverityHigh), find("vuln:CVE-2:a:1.0", shared.SeverityLow)},
		},
	}
	for name, r := range cases {
		if ReproDigest(r) == d0 {
			t.Errorf("%s must change the digest", name)
		}
	}
}

// TestReproDigestReflectsAdvisoryContent: with the same component + finding identity + severity, a changed
// FIX VERSION or CVSS VECTOR in the correlated vuln (e.g. a new advisory-DB snapshot) must change the digest
// – so "different DB → different digest" holds even for a remediation-only change.
func TestReproDigestReflectsAdvisoryContent(t *testing.T) {
	mk := func(fix, cvss string) *ScanResult {
		return &ScanResult{
			SBOM:            &sbom.SBOM{Components: []sbom.Component{comp("a", "1.0", "pkg:golang/a@1.0")}},
			Findings:        []finding.Finding{find("vuln:CVE-1:a:1.0", shared.SeverityHigh)},
			Vulnerabilities: []vulnerability.Vulnerability{{ID: "CVE-1", Component: "a", Version: "1.0", FixedVersion: fix, CVSSVector: cvss}},
		}
	}
	base := ReproDigest(mk("1.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))
	if ReproDigest(mk("1.2", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")) == base {
		t.Error("a changed fix version (same identity/severity) must change the digest")
	}
	if ReproDigest(mk("1.1", "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")) == base {
		t.Error("a changed CVSS vector must change the digest")
	}
	if ReproDigest(mk("1.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")) != base {
		t.Error("identical advisory content must yield the same digest")
	}
}

func TestReproDigestNilAndEmptyStable(t *testing.T) {
	if ReproDigest(nil) != "" {
		t.Error("nil result → empty digest")
	}
	if d1, d2 := ReproDigest(&ScanResult{}), ReproDigest(&ScanResult{}); d1 != d2 {
		t.Error("empty result digest must be stable")
	}
}
