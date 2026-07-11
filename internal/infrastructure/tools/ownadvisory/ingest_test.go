package ownadvisory

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const osvAdvisoryJSON = `{
  "id": "GHSA-xxxx-yyyy-zzzz",
  "aliases": ["CVE-2024-12345"],
  "summary": "Remote code execution in foo",
  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
  "affected": [{
    "package": {"ecosystem": "Go", "name": "github.com/foo/bar"},
    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.0"}]}],
    "versions": ["1.0.0", "1.1.0"]
  }]
}`

func TestParseOSV(t *testing.T) {
	adv, err := ParseOSV([]byte(osvAdvisoryJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if adv.ID != "GHSA-xxxx-yyyy-zzzz" || len(adv.Aliases) != 1 || adv.Aliases[0] != "CVE-2024-12345" {
		t.Fatalf("id/aliases wrong: %+v", adv)
	}
	if adv.CVSSVector == "" || adv.CVSSScore < 9.0 { // ~9.8 from the vector
		t.Errorf("CVSS not derived from the vector: vec=%q score=%.1f", adv.CVSSVector, adv.CVSSScore)
	}
	if len(adv.Affected) != 1 {
		t.Fatalf("want 1 affected package, got %d", len(adv.Affected))
	}
	ap := adv.Affected[0]
	if ap.Ecosystem != "Go" || ap.Package != "github.com/foo/bar" || ap.FixedVersion != "1.2.0" ||
		len(ap.Ranges) != 1 || ap.Ranges[0].Type != "SEMVER" || len(ap.Versions) != 2 {
		t.Errorf("affected package wrong: %+v", ap)
	}
}

// TestParseOSVThenMatch is the round trip: a parsed advisory, loaded into a store, matches an SBOM via the
// owned DetectionSource – ingest→store→match end-to-end with one canonical OSV fixture.
func TestParseOSVThenMatch(t *testing.T) {
	adv, err := ParseOSV([]byte(osvAdvisoryJSON))
	if err != nil {
		t.Fatal(err)
	}
	store := memStore{byKey: map[string][]advisory.Advisory{"Go|github.com/foo/bar": {adv}}}
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "github.com/foo/bar", Version: "1.1.0", PURL: "pkg:golang/github.com/foo/bar@1.1.0"}, // in range
		{Name: "github.com/foo/bar", Version: "1.2.0", PURL: "pkg:golang/github.com/foo/bar@1.2.0"}, // == fixed
	}}
	raws, err := New(store).Scan(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(raws) != 1 || raws[0].AdvisoryID != "CVE-2024-12345" || raws[0].Version != "1.1.0" ||
		raws[0].Severity != shared.SeverityCritical {
		t.Fatalf("round-trip match wrong: %+v", raws)
	}
}

// TestParseOSVPyPINameNormalized (the MAJOR key-contract fix): an OSV PyPI advisory carries a
// non-normalized name ("Django"); the SBOM component is PEP 503-normalized ("django"). Ingest must store
// the canonical key so the round trip matches – else a silent missed CVE for the 2nd-largest ecosystem.
func TestParseOSVPyPINameNormalized(t *testing.T) {
	const j = `{
	  "id": "GHSA-pypi-1", "aliases": ["CVE-2024-7"],
	  "affected": [{
	    "package": {"ecosystem": "PyPI", "name": "Django"},
	    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.2.0"}]}],
	    "versions": ["4.1.0"]
	  }]
	}`
	adv, err := ParseOSV([]byte(j))
	if err != nil {
		t.Fatal(err)
	}
	if adv.Affected[0].Package != "django" {
		t.Fatalf("PyPI name must be PEP-503 normalized on ingest, got %q", adv.Affected[0].Package)
	}
	// round trip: the SBOM component "django" (normalized) matches the stored advisory via the versions list
	store := memStore{byKey: map[string][]advisory.Advisory{"PyPI|django": {adv}}}
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "django", Version: "4.1.0", PURL: "pkg:pypi/django@4.1.0"},
	}}
	raws, err := New(store).Scan(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(raws) != 1 || raws[0].AdvisoryID != "CVE-2024-7" {
		t.Fatalf("normalized PyPI name must match (no silent miss), got %+v", raws)
	}
}

func TestParseOSVRejectsNoID(t *testing.T) {
	if _, err := ParseOSV([]byte(`{"summary":"no id"}`)); err == nil {
		t.Error("an advisory with no id must be rejected")
	}
	if _, err := ParseOSV([]byte(`not json`)); err == nil {
		t.Error("malformed JSON must error")
	}
}

func TestParseOSVSkipsPackagelessEntry(t *testing.T) {
	// an affected[] entry with no package (e.g. a GIT-only or malformed entry) is dropped, not matched.
	const j = `{"id":"GHSA-1","affected":[{"ranges":[{"type":"GIT","events":[{"introduced":"0"}]}]}]}`
	adv, err := ParseOSV([]byte(j))
	if err != nil {
		t.Fatal(err)
	}
	if len(adv.Affected) != 0 {
		t.Errorf("a package-less affected entry must be skipped, got %+v", adv.Affected)
	}
}
