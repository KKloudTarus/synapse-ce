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
		"pkg:rpm/redhat/bash@4.4?distro=rhel-9":                  "Red Hat:9", // mapped: owned RedHat CSAF feed keys "Red Hat:<major>"
		"pkg:rpm/redhat/bash@4.4?distro=redhat-8.9":              "Red Hat:8", // the "redhat" distro id maps the same
		"pkg:rpm/centos/bash@4.4?distro=centos-9":                "",          // CentOS Stream drifts ahead of RHEL → deliberately unmapped
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

// D1.3: the owned matcher carries KEV/EPSS projected on the corpus advisory onto the finding, so an offline
// scan orders by exploitation risk without the live network enricher.
func TestScanCarriesRisk(t *testing.T) {
	adv := goAdv()
	adv.KEV = true
	adv.EPSS = 0.87
	store := memStore{byKey: map[string][]advisory.Advisory{"Go|github.com/foo/bar": {adv}}}
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "github.com/foo/bar", Version: "1.1.0", PURL: "pkg:golang/github.com/foo/bar@1.1.0"},
	}}
	raws, err := New(store).Scan(context.Background(), doc)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(raws) != 1 || !raws[0].KEV || raws[0].EPSS != 0.87 {
		t.Fatalf("finding must carry KEV/EPSS from the corpus advisory, got %+v", raws)
	}
}

func TestScanMatchesDebianBinaryViaSourcePackage(t *testing.T) {
	// D2.8: a Debian advisory is keyed by the SOURCE package "openssl", but the installed BINARY is
	// "libssl1.1" (built from openssl). Without source-package matching the binary is invisible; with it,
	// the binary matches via its Syft "upstream=openssl" PURL qualifier.
	adv := advisory.Advisory{
		ID: "CVE-2024-SRC", Summary: "openssl", CVSSScore: 7.5,
		Affected: []advisory.AffectedPackage{{
			Ecosystem: "Debian:11", Package: "openssl",
			Ranges:       []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.1.1n-0+deb11u4"}}}},
			FixedVersion: "1.1.1n-0+deb11u4",
		}},
	}
	store := memStore{byKey: map[string][]advisory.Advisory{"Debian:11|openssl": {adv}}}
	doc := &sbom.SBOM{Components: []sbom.Component{
		// binary built from openssl, vulnerable version, source recorded in upstream=
		{Name: "libssl1.1", Version: "1.1.1n-0+deb11u3", PURL: "pkg:deb/debian/libssl1.1@1.1.1n-0+deb11u3?arch=amd64&distro=debian-11&upstream=openssl"},
		// same source, patched version -> not affected
		{Name: "libcrypto1.1", Version: "1.1.1n-0+deb11u4", PURL: "pkg:deb/debian/libcrypto1.1@1.1.1n-0+deb11u4?distro=debian-11&upstream=openssl"},
		// a binary whose upstream is unrelated -> no match
		{Name: "zlib1g", Version: "1.2.11", PURL: "pkg:deb/debian/zlib1g@1.2.11?distro=debian-11&upstream=zlib"},
	}}
	raws, err := New(store).Scan(context.Background(), doc)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(raws) != 1 {
		t.Fatalf("want 1 finding (the vulnerable libssl1.1 via source openssl), got %d: %+v", len(raws), raws)
	}
	if raws[0].Component != "libssl1.1" || raws[0].AdvisoryID != "CVE-2024-SRC" {
		t.Errorf("finding must be the binary libssl1.1 matched via source openssl, got %+v", raws[0])
	}
}

func TestScanSourceMatchDoesNotDoubleEmit(t *testing.T) {
	// A source package whose binary name equals the source name must not double-emit (binary + source hit
	// the same advisory); the emit dedup handles it.
	adv := advisory.Advisory{
		ID: "CVE-2024-DUP", Summary: "openssl", CVSSScore: 7.5,
		Affected: []advisory.AffectedPackage{{
			Ecosystem: "Debian:11", Package: "openssl",
			Ranges: []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}, {Fixed: "9"}}}},
		}},
	}
	store := memStore{byKey: map[string][]advisory.Advisory{"Debian:11|openssl": {adv}}}
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "openssl", Version: "1.1.1n", PURL: "pkg:deb/debian/openssl@1.1.1n?distro=debian-11&upstream=openssl"},
	}}
	raws, err := New(store).Scan(context.Background(), doc)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(raws) != 1 {
		t.Fatalf("binary==source must emit exactly once, got %d: %+v", len(raws), raws)
	}
}

func TestScanSourceMatchUsesUpstreamVersionNotBinary(t *testing.T) {
	// D2.8 soundness (Codex): when Syft records upstream=<source>@<version>, the SOURCE version differs from
	// the binary and the source-keyed advisory must be matched against the SOURCE version. Here the binary
	// version (1.1.1n) is >= the fix (1.1.1m) and would be missed, but the source version (1.1.1k) is below
	// the fix and IS affected — using the source version finds it.
	adv := advisory.Advisory{
		ID: "CVE-2024-UPV", Summary: "openssl", CVSSScore: 7.5,
		Affected: []advisory.AffectedPackage{{
			Ecosystem: "Debian:11", Package: "openssl",
			Ranges:       []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.1.1m"}}}},
			FixedVersion: "1.1.1m",
		}},
	}
	store := memStore{byKey: map[string][]advisory.Advisory{"Debian:11|openssl": {adv}}}
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "libssl1.1", Version: "1.1.1n", PURL: "pkg:deb/debian/libssl1.1@1.1.1n?distro=debian-11&upstream=openssl%401.1.1k"},
	}}
	raws, err := New(store).Scan(context.Background(), doc)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(raws) != 1 || raws[0].AdvisoryID != "CVE-2024-UPV" {
		t.Fatalf("want the finding via source version 1.1.1k (< fix 1.1.1m), got %+v", raws)
	}
}

// TestDistroEcosystemLockstep pins the scan-side matcher key (osDistroEcosystem, this package) to the
// inventory/correlation identity key (sbom.IdentityFromComponent). Both derive the advisory ecosystem for an
// OS-package PURL and MUST agree, or a component keyed one way at scan time and another in the correlation path
// would silently miss its advisories (a false negative) or hit a foreign ecosystem's (a false match). Both now
// delegate to the shared sbom.DistroEcosystem, so they cannot drift; this table is the regression guard that
// keeps it that way (and documents the exact keys, case-variants, and unmapped families).
func TestDistroEcosystemLockstep(t *testing.T) {
	purls := []string{
		"pkg:deb/debian/openssl@1.0?distro=debian-12",
		"pkg:deb/ubuntu/bash@5?arch=amd64&distro=ubuntu-22.04",
		"pkg:deb/ubuntu/bash@5?distro=ubuntu-22.04.1", // point release keys to major.minor
		"pkg:apk/alpine/musl@1.2?distro=alpine-3.19",
		"pkg:rpm/rhel/openssl@3.0-1?arch=x86_64&distro=rhel-9.2&epoch=1",
		"pkg:rpm/redhat/kernel@5.14-1?distro=redhat-9",
		"pkg:rpm/rocky/bash@5-1?distro=rocky-9.3",
		"pkg:rpm/almalinux/bash@5-1?distro=almalinux-9",
		"pkg:rpm/ol/openssl@3.0-1?distro=ol-8",
		"pkg:rpm/amzn/openssl@1.0.2k-24?distro=amzn-2",
		"pkg:rpm/amzn/curl@8.5.0-1?distro=amzn-2023",
		"pkg:rpm/opensuse-leap/bash@5.1-1?arch=x86_64&distro=opensuse-leap-15.6",
		// Unmapped families must agree on "" (cataloged for inventory, never keyed to an advisory ecosystem).
		"pkg:rpm/fedora/bash@5-1?distro=fedora-40",
		"pkg:rpm/centos/bash@5-1?distro=centos-9",
		"pkg:rpm/sles/bash@5-1?distro=sles-15.6",
		// Case-variant distro qualifiers must still agree (both functions lowercase the qualifier).
		"pkg:rpm/amzn/bash@5-1?distro=AMZN-2",
		"pkg:rpm/opensuse-leap/bash@5-1?distro=OpenSUSE-Leap-15.6",
		// apk family: Alpine keys by release, Wolfi/Chainguard are rolling (version-less), matching the secdb feed.
		"pkg:apk/alpine/musl@1.2?distro=alpine-3.20",
		"pkg:apk/wolfi/glibc@2.39?distro=wolfi",
		"pkg:apk/wolfi/glibc@2.39?distro=wolfi-20230201",
		"pkg:apk/chainguard/glibc@2.39?distro=chainguard",
		// Degenerate qualifiers must agree on "" (empty id, empty version, no hyphen).
		"pkg:rpm/x/bash@5-1?distro=-2",
		"pkg:rpm/x/bash@5-1?distro=rhel-",
		"pkg:rpm/x/bash@5-1?distro=rhel",
	}
	for _, purl := range purls {
		scanKey := osDistroEcosystem(purl)
		identity := sbom.IdentityFromComponent(sbom.Component{PURL: purl})
		if scanKey != identity.Ecosystem {
			t.Errorf("lockstep drift for %s: osDistroEcosystem=%q but IdentityFromComponent.Ecosystem=%q", purl, scanKey, identity.Ecosystem)
		}
	}
}
