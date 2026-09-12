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

// symbolsPresent reports whether every want symbol is in got (order-independent).
func symbolsPresent(got, want []string) bool {
	set := map[string]bool{}
	for _, g := range got {
		set[g] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return len(got) == len(want)
}

// TestParseOSVGoSymbolsCarry is the D4.1 core: the owned OSV ingester parses the Go vuln DB's
// ecosystem_specific.imports symbols (qualified importPath.Symbol) onto the advisory, and the owned matcher
// carries them onto the finding, so an OFFLINE scan drives symbol-level reachability, not only the live path.
func TestParseOSVGoSymbolsCarry(t *testing.T) {
	const j = `{
	  "id": "GO-2024-0001", "aliases": ["CVE-2024-9999"],
	  "affected": [{
	    "package": {"ecosystem": "Go", "name": "github.com/foo/bar"},
	    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.0"}]}],
	    "ecosystem_specific": {"imports": [{"path": "github.com/foo/bar", "symbols": ["Vuln", "T.Method"]}]}
	  }]
	}`
	adv, err := ParseOSV([]byte(j))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"github.com/foo/bar.Vuln", "github.com/foo/bar.T.Method"}
	if !symbolsPresent(adv.Affected[0].AffectedSymbols, want) {
		t.Fatalf("ingested affected symbols = %v, want %v (qualified importPath.Symbol)", adv.Affected[0].AffectedSymbols, want)
	}
	store := memStore{byKey: map[string][]advisory.Advisory{"Go|github.com/foo/bar": {adv}}}
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "github.com/foo/bar", Version: "1.1.0", PURL: "pkg:golang/github.com/foo/bar@1.1.0"},
	}}
	raws, err := New(store).Scan(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(raws) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(raws), raws)
	}
	if !symbolsPresent(raws[0].AffectedSymbols, want) {
		t.Errorf("finding must carry the affected symbols offline, got %v", raws[0].AffectedSymbols)
	}
}

// RustSec (crates.io) publishes affected functions as ecosystem_specific.affects.functions (already
// fully-qualified crate::Type::method paths); the owned parser must carry them as AffectedSymbols exactly
// like the Go imports form, and they must reach the finding offline. (D4.6 data half)
func TestParseOSVRustAffectedFunctions(t *testing.T) {
	const j = `{
	  "id": "RUSTSEC-2019-0033", "aliases": ["CVE-2019-25009"],
	  "affected": [{
	    "package": {"ecosystem": "crates.io", "name": "http"},
	    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.1.20"}]}],
	    "ecosystem_specific": {"affects": {"functions": ["http::header::HeaderMap::reserve", "http::header::HeaderMap::try_reserve"]}}
	  }]
	}`
	adv, err := ParseOSV([]byte(j))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"http::header::HeaderMap::reserve", "http::header::HeaderMap::try_reserve"}
	if !symbolsPresent(adv.Affected[0].AffectedSymbols, want) {
		t.Fatalf("Rust affected functions not carried: got %v, want %v", adv.Affected[0].AffectedSymbols, want)
	}
	store := memStore{byKey: map[string][]advisory.Advisory{"crates.io|http": {adv}}}
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "http", Version: "0.1.19", PURL: "pkg:cargo/http@0.1.19"},
	}}
	raws, err := New(store).Scan(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(raws) != 1 || !symbolsPresent(raws[0].AffectedSymbols, want) {
		t.Fatalf("finding must carry Rust affected symbols offline, got %+v", raws)
	}
}

// Both the Go imports form and the Rust affects.functions form are read into one symbol set, and duplicate
// entries within a form are de-duplicated.
func TestOSVImportSymbolsDedupAndBothForms(t *testing.T) {
	const j = `{
	  "id": "X-1",
	  "affected": [{
	    "package": {"ecosystem": "crates.io", "name": "c"},
	    "ecosystem_specific": {
	      "imports": [{"path": "example.com/p", "symbols": ["Vuln", "Vuln"]}],
	      "affects": {"functions": ["c::A::f", "c::A::f", "c::B::g"]}
	    }
	  }]
	}`
	adv, err := ParseOSV([]byte(j))
	if err != nil {
		t.Fatal(err)
	}
	got := adv.Affected[0].AffectedSymbols
	// the Go import (deduped to one "example.com/p.Vuln") plus the two distinct Rust functions
	if len(got) != 3 || !symbolsPresent(got, []string{"example.com/p.Vuln", "c::A::f", "c::B::g"}) {
		t.Fatalf("expected both forms de-duplicated to [example.com/p.Vuln c::A::f c::B::g], got %v", got)
	}
}
