package osv

import (
	"encoding/json"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// canonicalOSV is a representative OSV-schema record – the open standard osv.dev serves:
// id + CVE alias, a CVSS_V3 severity vector, an affected[] block with a range (introduced/fixed events)
// and the Go-ecosystem affected symbols, plus a database_specific severity label. Mirrors a real
// vulns/{id} payload so the fields Synapse keys on are exercised end-to-end from JSON.
const canonicalOSV = `{
  "id": "GHSA-jfh8-c2jp-5v3q",
  "aliases": ["CVE-2021-44228"],
  "summary": "Remote code injection",
  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
  "affected": [{
    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0.0"}, {"fixed": "2.3.1"}]}],
    "ecosystem_specific": {"imports": [{"path": "github.com/example/log4j", "symbols": ["Lookup", "JndiManager"]}]}
  }],
  "database_specific": {"severity": "CRITICAL"}
}`

// TestOSVSchemaConformance locks parsing of the OSV open standard end-to-end: a
// canonical vulns/{id} record decodes and maps to the normalized RawFinding with the fields Synapse
// keys on – the CVE alias preferred as the advisory id, the CVSS_V3 vector + computed base score, the
// fixed version from the range events, the curated severity label, and the path-qualified affected
// symbols. Symmetric with TestCycloneDX17Conformance (CDX) + TestPURLSpecConformance (PURL).
func TestOSVSchemaConformance(t *testing.T) {
	var v osvVuln
	if err := json.Unmarshal([]byte(canonicalOSV), &v); err != nil {
		t.Fatalf("decode OSV record: %v", err)
	}
	comp := sbom.Component{Name: "github.com/example/log4j", Version: "2.14.0", PURL: "pkg:golang/github.com/example/log4j@2.14.0"}
	got := osvToRaw(comp, v)

	if got.Source != "osv" {
		t.Errorf("Source = %q, want osv", got.Source)
	}
	if got.AdvisoryID != "CVE-2021-44228" {
		t.Errorf("AdvisoryID = %q, want the CVE alias preferred", got.AdvisoryID)
	}
	if len(got.Aliases) < 2 || got.Aliases[0] != "GHSA-jfh8-c2jp-5v3q" {
		t.Errorf("Aliases = %v, want [GHSA…, CVE…]", got.Aliases)
	}
	if got.CVSSVector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" {
		t.Errorf("CVSSVector = %q, want the CVSS_V3 vector verbatim", got.CVSSVector)
	}
	if got.CVSSScore < 9.9 { // scope-changed + all-high => 10.0
		t.Errorf("CVSSScore = %.2f, want ~10.0 computed from the vector", got.CVSSScore)
	}
	if got.Severity != shared.SeverityCritical {
		t.Errorf("Severity = %q, want critical", got.Severity)
	}
	if got.FixedVersion != "2.3.1" {
		t.Errorf("FixedVersion = %q, want 2.3.1 from the range events", got.FixedVersion)
	}
	if len(got.AffectedSymbols) != 2 ||
		got.AffectedSymbols[0] != "github.com/example/log4j.Lookup" ||
		got.AffectedSymbols[1] != "github.com/example/log4j.JndiManager" {
		t.Errorf("AffectedSymbols = %v, want path-qualified [Lookup JndiManager]", got.AffectedSymbols)
	}
}
