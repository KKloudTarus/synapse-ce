package sca

import (
	"reflect"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
)

// TestUnanalyzedReachabilityEcosystems: a finding in an ecosystem with NO reachability engine (swift, pub,
// hex, conda, cran, julia) is reported so the surface can mark it no_analysis; an engine-backed ecosystem
// (golang, npm) is never reported (EPIC #1042 E.1). The result is sorted and de-duplicated.
func TestUnanalyzedReachabilityEcosystems(t *testing.T) {
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "swiftpkg", Version: "1", PURL: "pkg:swift/github.com/x/swiftpkg@1"},
		{Name: "dartpkg", Version: "1", PURL: "pkg:pub/dartpkg@1"},
		{Name: "hexpkg", Version: "1", PURL: "pkg:hex/hexpkg@1"},
		{Name: "condapkg", Version: "1", PURL: "pkg:conda/condapkg@1"},
		{Name: "cranpkg", Version: "1", PURL: "pkg:cran/cranpkg@1"},
		{Name: "juliapkg", Version: "1", PURL: "pkg:julia/juliapkg@1"},
		{Name: "gopkg", Version: "1", PURL: "pkg:golang/example.com/gopkg@1"},
		{Name: "npmpkg", Version: "1", PURL: "pkg:npm/npmpkg@1"},
	}}
	vulns := []vulnerability.Vulnerability{
		{ID: "V1", Component: "swiftpkg", Version: "1"},
		{ID: "V2", Component: "dartpkg", Version: "1"},
		{ID: "V3", Component: "hexpkg", Version: "1"},
		{ID: "V4", Component: "condapkg", Version: "1"},
		{ID: "V5", Component: "cranpkg", Version: "1"},
		{ID: "V6", Component: "juliapkg", Version: "1"},
		{ID: "V7", Component: "gopkg", Version: "1"},  // engine-backed -> not reported
		{ID: "V8", Component: "npmpkg", Version: "1"}, // engine-backed -> not reported
	}
	findings := make([]finding.Finding, len(vulns))
	for i, v := range vulns {
		findings[i] = finding.Finding{DedupKey: vulnDedupKey(v)}
	}

	got := unanalyzedReachabilityEcosystems(findings, vulns, doc)
	want := []string{"conda", "cran", "hex", "julia", "pub", "swift"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unanalyzed ecosystems = %v, want %v (engine-backed golang/npm excluded, sorted)", got, want)
	}

	// A scan with only engine-backed ecosystems reports nothing.
	goOnly := unanalyzedReachabilityEcosystems(
		[]finding.Finding{{DedupKey: vulnDedupKey(vulns[6])}},
		[]vulnerability.Vulnerability{vulns[6]}, doc)
	if len(goOnly) != 0 {
		t.Fatalf("engine-backed-only scan must report no unanalyzed ecosystem, got %v", goOnly)
	}
}

// TestUnanalyzedReachabilityEcosystemsNameCollision: a package name shared across an engine-backed and an
// engine-less ecosystem is disambiguated by version, so a finding is mapped to the RIGHT ecosystem (the join
// is name+version, not name alone).
func TestUnanalyzedReachabilityEcosystemsNameCollision(t *testing.T) {
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "shared", Version: "1", PURL: "pkg:npm/shared@1"},   // engine-backed
		{Name: "shared", Version: "2", PURL: "pkg:swift/shared@2"}, // engine-less
	}}
	swiftVuln := vulnerability.Vulnerability{ID: "V1", Component: "shared", Version: "2"}
	npmVuln := vulnerability.Vulnerability{ID: "V2", Component: "shared", Version: "1"}
	vulns := []vulnerability.Vulnerability{swiftVuln, npmVuln}

	// A finding on the swift@2 component reports swift; the npm@1 finding does not leak an engine-less label.
	if got := unanalyzedReachabilityEcosystems([]finding.Finding{{DedupKey: vulnDedupKey(swiftVuln)}}, vulns, doc); !reflect.DeepEqual(got, []string{"swift"}) {
		t.Fatalf("swift@2 finding must map to swift, got %v", got)
	}
	if got := unanalyzedReachabilityEcosystems([]finding.Finding{{DedupKey: vulnDedupKey(npmVuln)}}, vulns, doc); len(got) != 0 {
		t.Fatalf("npm@1 finding (engine-backed) must report nothing, got %v", got)
	}
}

func TestReachabilityEngineExists(t *testing.T) {
	for _, eco := range []string{"golang", "pypi", "npm", "cargo", "composer", "gem", "nuget", "maven"} {
		if !reachabilityEngineExists(eco) {
			t.Errorf("%s must have a reachability engine", eco)
		}
	}
	for _, eco := range []string{"swift", "pub", "hex", "conda", "cran", "julia", "deb", ""} {
		if reachabilityEngineExists(eco) {
			t.Errorf("%s must NOT have a reachability engine", eco)
		}
	}
}
