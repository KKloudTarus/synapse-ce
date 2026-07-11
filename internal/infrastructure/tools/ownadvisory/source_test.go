package ownadvisory

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// memStore is an in-memory AdvisoryStore keyed by "ecosystem|name" (stands in for the future Postgres store).
type memStore struct {
	byKey map[string][]advisory.Advisory
}

func (m memStore) ByPackage(_ context.Context, ecosystem, name string) ([]advisory.Advisory, error) {
	return m.byKey[ecosystem+"|"+name], nil
}

func goAdv() advisory.Advisory {
	return advisory.Advisory{
		ID: "GHSA-go-1", Aliases: []string{"CVE-2024-9"}, Summary: "bad", CVSSScore: 9.8,
		Affected: []advisory.AffectedPackage{{
			Ecosystem: "Go", Package: "github.com/foo/bar",
			Ranges:       []advisory.Range{{Type: "SEMVER", Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.2.0"}}}},
			FixedVersion: "1.2.0",
		}},
	}
}

func TestScanMatches(t *testing.T) {
	store := memStore{byKey: map[string][]advisory.Advisory{
		"Go|github.com/foo/bar": {goAdv()},
	}}
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "github.com/foo/bar", Version: "1.1.0", PURL: "pkg:golang/github.com/foo/bar@1.1.0"},   // affected
		{Name: "github.com/foo/bar", Version: "1.2.0", PURL: "pkg:golang/github.com/foo/bar@1.2.0"},   // == fixed, not affected
		{Name: "github.com/safe/pkg", Version: "1.0.0", PURL: "pkg:golang/github.com/safe/pkg@1.0.0"}, // no advisory
	}}
	raws, err := New(store).Scan(context.Background(), doc)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(raws) != 1 {
		t.Fatalf("want 1 finding (only the 1.1.0 affected), got %d: %+v", len(raws), raws)
	}
	r := raws[0]
	if r.Source != "advisory-store" || r.AdvisoryID != "CVE-2024-9" || r.Component != "github.com/foo/bar" ||
		r.Version != "1.1.0" || r.FixedVersion != "1.2.0" || r.Severity != shared.SeverityCritical {
		t.Errorf("raw finding wrong: %+v", r)
	}
}

func TestScanSkipsUnmappedEcosystemAndUnresolvedVersion(t *testing.T) {
	store := memStore{byKey: map[string][]advisory.Advisory{
		"Go|github.com/foo/bar": {goAdv()},
	}}
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "somepkg", Version: "1.0.0", PURL: "pkg:deb/debian/somepkg@1.0.0"},                     // deb but no distro qualifier -> no ecosystem -> skip
		{Name: "github.com/foo/bar", Version: "", PURL: "pkg:golang/github.com/foo/bar"},              // no resolvable version -> skip
		{Name: "github.com/foo/bar", Version: "latest", PURL: "pkg:golang/github.com/foo/bar@latest"}, // floating -> skip
	}}
	raws, err := New(store).Scan(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(raws) != 0 {
		t.Fatalf("unmapped/unresolved components must produce no findings, got %+v", raws)
	}
}

func TestScanMatchesDebianOSPackage(t *testing.T) {
	// Epic B: an owned Debian advisory matches a deb component via the distro-qualifier → "Debian:9"
	// bridge + the dpkg range comparator – no grype involved (detection independence).
	adv := advisory.Advisory{
		ID: "CVE-2024-OS", Summary: "openssl", CVSSScore: 7.5,
		Affected: []advisory.AffectedPackage{{
			Ecosystem: "Debian:9", Package: "openssl",
			Ranges:       []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.1.0l-1~deb9u1"}}}},
			FixedVersion: "1.1.0l-1~deb9u1",
		}},
	}
	store := memStore{byKey: map[string][]advisory.Advisory{"Debian:9|openssl": {adv}}}
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "openssl", Version: "1.1.0k-1", PURL: "pkg:deb/debian/openssl@1.1.0k-1?arch=amd64&distro=debian-9"},    // affected
		{Name: "openssl", Version: "1.1.0l-1~deb9u1", PURL: "pkg:deb/debian/openssl@1.1.0l-1~deb9u1?distro=debian-9"}, // patched -> not affected
		{Name: "openssl", Version: "1.1.0k-1", PURL: "pkg:deb/debian/openssl@1.1.0k-1?distro=debian-10"},              // wrong release -> no Debian:10 advisory
	}}
	raws, err := New(store).Scan(context.Background(), doc)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(raws) != 1 {
		t.Fatalf("want 1 finding (only the vulnerable debian-9 openssl), got %d: %+v", len(raws), raws)
	}
	if raws[0].AdvisoryID != "CVE-2024-OS" || raws[0].Version != "1.1.0k-1" {
		t.Errorf("raw finding wrong: %+v", raws[0])
	}
}

func TestOsDistroEcosystem(t *testing.T) {
	cases := map[string]string{
		"pkg:deb/debian/openssl@1.1?distro=debian-9":             "Debian:9",
		"pkg:deb/debian/openssl@1.1?arch=amd64&distro=debian-10": "Debian:10",
		"pkg:apk/alpine/musl@1.2.2-r0?distro=alpine-3.18.12":     "Alpine:v3.18",
		"pkg:deb/ubuntu/bash@5?distro=ubuntu-22.04":              "Ubuntu:22.04", // mapped: owned OVAL feed keys "Ubuntu:<version>"
		"pkg:deb/ubuntu/openssl@3?distro=ubuntu-20.04":           "Ubuntu:20.04",
		"pkg:rpm/rocky/bash@4.4-1?distro=rocky-9.3":              "Rocky Linux:9", // mapped: OSV keys "<Name>:<major>"
		"pkg:rpm/almalinux/openssl@3?distro=almalinux-8.9":       "AlmaLinux:8",
		"pkg:rpm/ol/glibc@2?distro=ol-9":                         "Oracle Linux:9",
		"pkg:rpm/redhat/bash@4.4?distro=rhel-9":                  "", // rhel/centos/fedora: module-qualified/uncertain OSV keys → unmapped (flagged, not silent)
		"pkg:rpm/fedora/bash@5?distro=fedora-39":                 "",
		"pkg:deb/debian/openssl@1.1":                             "", // no distro qualifier
		"pkg:npm/lodash@4.0.0":                                   "", // not an OS package
	}
	for purl, want := range cases {
		if got := osDistroEcosystem(purl); got != want {
			t.Errorf("osDistroEcosystem(%q) = %q, want %q", purl, got, want)
		}
	}
}

func TestPurlQualifier(t *testing.T) {
	p := "pkg:deb/debian/openssl@1.1?arch=amd64&distro=debian-9&upstream=openssl"
	if got := purlQualifier(p, "distro"); got != "debian-9" {
		t.Errorf("distro qualifier = %q", got)
	}
	if got := purlQualifier(p, "arch"); got != "amd64" {
		t.Errorf("arch qualifier = %q", got)
	}
	if got := purlQualifier("pkg:npm/lodash@4.0.0", "distro"); got != "" {
		t.Errorf("missing qualifier should be empty, got %q", got)
	}
}

func TestScanNilDoc(t *testing.T) {
	raws, err := New(memStore{}).Scan(context.Background(), nil)
	if err != nil || raws != nil {
		t.Errorf("nil doc -> nil findings, no error; got %v / %+v", err, raws)
	}
}

// TestScanMavenKeyContract pins the Maven key format (group:artifact, colon): the SBOM component Name +
// the stored advisory Package must agree, else every Maven advisory silently misses (HIGH-1). pkg:maven/
// <group>/<artifact> PURL, Name "group:artifact".
func TestScanMavenKeyContract(t *testing.T) {
	const pkg = "com.google.guava:guava"
	store := memStore{byKey: map[string][]advisory.Advisory{
		"Maven|" + pkg: {{
			ID: "GHSA-mvn", CVSSScore: 7.5,
			Affected: []advisory.AffectedPackage{{
				Ecosystem: "Maven", Package: pkg,
				Ranges: []advisory.Range{{Type: "SEMVER", Events: []advisory.Event{{Introduced: "0"}, {Fixed: "32.0.0"}}}},
			}},
		}},
	}}
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: pkg, Version: "31.0.0", PURL: "pkg:maven/com.google.guava/guava@31.0.0"},
	}}
	raws, err := New(store).Scan(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(raws) != 1 || raws[0].Component != pkg {
		t.Fatalf("Maven group:artifact key must match, got %+v", raws)
	}
}

// TestScanSeverityFromVector (MED-2): when the advisory has a CVSS vector but no precomputed score, the
// severity is derived from the vector (not left Unknown) – parity with the OSV adapter.
func TestScanSeverityFromVector(t *testing.T) {
	store := memStore{byKey: map[string][]advisory.Advisory{
		"Go|github.com/foo/bar": {{
			ID:         "GHSA-vec",
			CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // ~9.8, no precomputed score
			Affected: []advisory.AffectedPackage{{
				Ecosystem: "Go", Package: "github.com/foo/bar",
				Ranges: []advisory.Range{{Type: "SEMVER", Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.2.0"}}}},
			}},
		}},
	}}
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "github.com/foo/bar", Version: "1.1.0", PURL: "pkg:golang/github.com/foo/bar@1.1.0"},
	}}
	raws, err := New(store).Scan(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(raws) != 1 || raws[0].Severity != shared.SeverityCritical || raws[0].CVSSScore < 9.0 {
		t.Fatalf("severity must be derived from the vector, got %+v", raws[0])
	}
}

// TestScanNpmScopedKeyContract (#2): a scoped npm package (@scope/name) keeps its name verbatim on both
// sides – the store key and the SBOM component Name agree, so it matches.
func TestScanNpmScopedKeyContract(t *testing.T) {
	const pkg = "@vue/cli"
	store := memStore{byKey: map[string][]advisory.Advisory{
		"npm|" + pkg: {{
			ID: "GHSA-npm", CVSSScore: 6.1,
			Affected: []advisory.AffectedPackage{{
				Ecosystem: "npm", Package: pkg,
				Ranges: []advisory.Range{{Type: "SEMVER", Events: []advisory.Event{{Introduced: "0"}, {Fixed: "5.0.0"}}}},
			}},
		}},
	}}
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: pkg, Version: "4.5.0", PURL: "pkg:npm/%40vue/cli@4.5.0"},
	}}
	raws, err := New(store).Scan(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(raws) != 1 || raws[0].Component != pkg {
		t.Fatalf("scoped npm name must match, got %+v", raws)
	}
}

func TestScanNilStoreFailsLoud(t *testing.T) {
	if _, err := (&Source{}).Scan(context.Background(), &sbom.SBOM{}); err == nil {
		t.Error("a nil store must fail loud, not nil-deref panic / silent no-findings")
	}
}
