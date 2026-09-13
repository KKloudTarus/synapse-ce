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

// TestUnanalyzedReachabilityEcosystemsOSPackages pins #1062: an OS-package (deb/rpm/apk) finding is ALWAYS
// reported as unanalyzed under its DISTRO ecosystem key (Debian:12, ...), so an OS-package finding can never
// read as reachability-clean. This is independent of the engine set (OS packages are reachability-blind), and
// a distro-keyed label is more honest than the bare PURL type. An unmapped distro falls back to the bare type
// (still emitted, never dropped).
func TestUnanalyzedReachabilityEcosystemsOSPackages(t *testing.T) {
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "bash", Version: "5.1-2", PURL: "pkg:deb/debian/bash@5.1-2?arch=amd64&distro=debian-12"},
		{Name: "openssl", Version: "3.0.9", PURL: "pkg:rpm/rocky/openssl@3.0.9?arch=x86_64&distro=rocky-9.3"},
		{Name: "busybox", Version: "1.36.1", PURL: "pkg:apk/alpine/busybox@1.36.1?arch=x86_64&distro=alpine-3.18.12"},
		{Name: "centospkg", Version: "1", PURL: "pkg:rpm/centos/centospkg@1?arch=x86_64&distro=centos-8"}, // unmapped distro
		{Name: "gopkg", Version: "1", PURL: "pkg:golang/example.com/gopkg@1"},                             // engine-backed -> not reported
	}}
	vulns := []vulnerability.Vulnerability{
		{ID: "V1", Component: "bash", Version: "5.1-2"},
		{ID: "V2", Component: "openssl", Version: "3.0.9"},
		{ID: "V3", Component: "busybox", Version: "1.36.1"},
		{ID: "V4", Component: "centospkg", Version: "1"},
		{ID: "V5", Component: "gopkg", Version: "1"},
	}
	findings := make([]finding.Finding, len(vulns))
	for i, v := range vulns {
		findings[i] = finding.Finding{DedupKey: vulnDedupKey(v)}
	}
	got := unanalyzedReachabilityEcosystems(findings, vulns, doc)
	// Debian:12, Rocky Linux:9, Alpine:v3.18 (distro-keyed); centos-8 is unmapped -> bare "rpm" fallback.
	want := []string{"Alpine:v3.18", "Debian:12", "Rocky Linux:9", "rpm"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("OS-package unanalyzed ecosystems = %v, want %v", got, want)
	}
	for _, os := range []string{"Debian:12", "Rocky Linux:9", "Alpine:v3.18"} {
		if !containsString(got, os) {
			t.Fatalf("OS finding %q must be reported unanalyzed (never reachability-clean): %v", os, got)
		}
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
