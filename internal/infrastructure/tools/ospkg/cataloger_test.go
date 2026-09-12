package ospkg

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/distro"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func writeRootfs(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func byName(comps []sbom.Component) map[string]sbom.Component {
	m := map[string]sbom.Component{}
	for _, c := range comps {
		m[c.Name] = c
	}
	return m
}

func distroQualifier(purl string) string {
	i := strings.IndexByte(purl, '?')
	if i < 0 {
		return ""
	}
	for _, kv := range strings.Split(purl[i+1:], "&") {
		if v, ok := strings.CutPrefix(kv, "distro="); ok {
			return v
		}
	}
	return ""
}

func TestCatalogDebian(t *testing.T) {
	rootfs := writeRootfs(t, map[string]string{
		"etc/os-release": "PRETTY_NAME=\"Debian GNU/Linux 12\"\nID=debian\nVERSION_ID=\"12\"\n",
		"var/lib/dpkg/status": "Package: bash\nStatus: install ok installed\nVersion: 5.1-2+deb12u1\nArchitecture: amd64\n\n" +
			"Package: coreutils\nStatus: install ok installed\nVersion: 9.1-1\nArchitecture: amd64\n\n" +
			"Package: halfconf\nStatus: install ok half-configured\nVersion: 1.0\nArchitecture: amd64\n",
	})
	res, err := New().Catalog(context.Background(), rootfs)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	if len(res.Components) != 2 || !res.DistroResolved { // halfconf skipped; debian-12 resolves
		t.Fatalf("want 2 installed deb packages + resolved distro, got %d / resolved=%v: %+v", len(res.Components), res.DistroResolved, res.Components)
	}
	bash := byName(res.Components)["bash"]
	// The version's '+' is percent-encoded in the PURL (%2B); Name/Version keep the RAW value for matching.
	if bash.Version != "5.1-2+deb12u1" || bash.PURL != "pkg:deb/debian/bash@5.1-2%2Bdeb12u1?arch=amd64&distro=debian-12" {
		t.Errorf("bash = %+v; want raw version + a percent-encoded PURL with distro=debian-12", bash)
	}
	if bash.Scope != sbom.ScopeProduction {
		t.Errorf("OS packages should be production scope, got %q", bash.Scope)
	}
	// Location is the package DB path, so the component can be attributed to the image layer that wrote the DB.
	if want := filepath.Join(rootfs, "var/lib/dpkg/status"); bash.Location != want {
		t.Errorf("bash Location = %q, want the dpkg DB path %q", bash.Location, want)
	}
	if _, ok := byName(res.Components)["halfconf"]; ok {
		t.Error("a half-configured (not installed) package must be skipped")
	}
}

func TestCatalogAlpine(t *testing.T) {
	rootfs := writeRootfs(t, map[string]string{
		"etc/os-release":       "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.18.12\n",
		"lib/apk/db/installed": "P:busybox\nV:1.36.1-r0\nA:x86_64\n\nP:musl\nV:1.2.4-r2\nA:x86_64\n",
	})
	res, err := New().Catalog(context.Background(), rootfs)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	if len(res.Components) != 2 || !res.DistroResolved {
		t.Fatalf("want 2 apk packages + resolved distro, got %d / %v: %+v", len(res.Components), res.DistroResolved, res.Components)
	}
	if p := byName(res.Components)["busybox"].PURL; p != "pkg:apk/alpine/busybox@1.36.1-r0?arch=x86_64&distro=alpine-3.18.12" {
		t.Errorf("busybox PURL = %q; want the Syft-style apk PURL with distro=alpine-3.18.12", p)
	}
}

func TestCatalogNoOSRelease(t *testing.T) {
	// A dpkg DB with no os-release: packages still emit (namespace debian) but with NO distro qualifier, and
	// DistroResolved is false so the pipeline warns rather than presenting a clean OS posture.
	rootfs := writeRootfs(t, map[string]string{
		"var/lib/dpkg/status": "Package: bash\nStatus: install ok installed\nVersion: 5.1-2\nArchitecture: amd64\n",
	})
	res, err := New().Catalog(context.Background(), rootfs)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	if len(res.Components) != 1 || res.Components[0].PURL != "pkg:deb/debian/bash@5.1-2?arch=amd64" {
		t.Errorf("without os-release, want a deb PURL with no distro qualifier, got %+v", res.Components)
	}
	if res.DistroResolved {
		t.Error("without a resolvable os-release, DistroResolved must be false")
	}
}

func TestCatalogMismatchedOSRelease(t *testing.T) {
	// A dpkg DB but an os-release claiming ID=alpine (a lying/mismatched image): the deb packages must NOT be
	// tagged alpine, so they get no distro qualifier and DistroResolved is false (never a silent zero-match).
	rootfs := writeRootfs(t, map[string]string{
		"etc/os-release":      "ID=alpine\nVERSION_ID=3.18\n",
		"var/lib/dpkg/status": "Package: bash\nStatus: install ok installed\nVersion: 5.1\nArchitecture: amd64\n",
	})
	res, err := New().Catalog(context.Background(), rootfs)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	if len(res.Components) != 1 || distroQualifier(res.Components[0].PURL) != "" || res.DistroResolved {
		t.Errorf("a dpkg DB with an alpine os-release must not be tagged; want no distro qualifier + unresolved, got %+v resolved=%v", res.Components, res.DistroResolved)
	}
}

func TestCatalogEmptyRootfs(t *testing.T) {
	res, err := New().Catalog(context.Background(), t.TempDir())
	if err != nil || len(res.Components) != 0 {
		t.Errorf("an empty rootfs must yield no components + no error, got %d / %v", len(res.Components), err)
	}
	if res, _ := New().Catalog(context.Background(), ""); len(res.Components) != 0 {
		t.Error("an empty rootfs path must yield no components")
	}
}

func TestCatalogEncodesHostileFields(t *testing.T) {
	// PURL-breaking characters in a package name/version are percent-encoded (not dropped, not smuggled) so the
	// PURL stays unambiguous; a control character drops the package; a garbled os-release yields no distro tag.
	rootfs := writeRootfs(t, map[string]string{
		"etc/os-release": "ID=deb?ian\nVERSION_ID=12\n", // '?' -> not a clean token -> no distro tag
		"var/lib/dpkg/status": "Package: ev@il\nStatus: install ok installed\nVersion: 1?0\nArchitecture: amd64\n\n" +
			"Package: nul\x00name\nStatus: install ok installed\nVersion: 1.0\nArchitecture: amd64\n\n" +
			"Package: good\nStatus: install ok installed\nVersion: 2.0\nArchitecture: amd64\n",
	})
	res, err := New().Catalog(context.Background(), rootfs)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	by := byName(res.Components)
	if _, ok := by["nul\x00name"]; ok {
		t.Error("a control-character package name must be dropped")
	}
	// ev@il / 1?0 are kept but percent-encoded; the only literal '?' is the qualifier separator.
	evil := by["ev@il"]
	if evil.PURL != "pkg:deb/debian/ev%40il@1%3F0?arch=amd64" {
		t.Errorf("hostile name/version must be percent-encoded (unambiguous PURL), got %q", evil.PURL)
	}
	if strings.Count(evil.PURL, "?") != 1 || strings.Contains(strings.SplitN(evil.PURL, "?", 2)[0], "@1") == false {
		// sanity: exactly one '?' (the qualifier separator) and the name/version boundary is a single literal '@'
		t.Errorf("PURL structure ambiguous: %q", evil.PURL)
	}
	if res.DistroResolved {
		t.Error("a garbled os-release ID must yield DistroResolved=false")
	}
}

func TestCatalogSkipsSymlinkedDB(t *testing.T) {
	// Defense-in-depth: a symlinked DB path (the assembler skips symlink entries, so it should not occur) must
	// not be read/followed out of the rootfs.
	rootfs := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootfs, "var/lib/dpkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(rootfs, "var/lib/dpkg/status")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	res, err := New().Catalog(context.Background(), rootfs)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	if len(res.Components) != 0 {
		t.Errorf("a symlinked dpkg DB must not be read, got %+v", res.Components)
	}
}

func TestCatalogDistroTagRoundTrips(t *testing.T) {
	// Lock the tag ospkg emits to the domain SSOT (distro.ParseTag), so a delimiter/format change here cannot
	// silently desync OS-advisory matching.
	cases := []struct{ id, verID, dbPath, dbContent, wantID, wantVer string }{
		{"debian", "12", "var/lib/dpkg/status", "Package: bash\nStatus: install ok installed\nVersion: 5.1\nArchitecture: amd64\n", "debian", "12"},
		{"ubuntu", "22.04", "var/lib/dpkg/status", "Package: bash\nStatus: install ok installed\nVersion: 5.1\nArchitecture: amd64\n", "ubuntu", "22.04"},
		{"alpine", "3.18.12", "lib/apk/db/installed", "P:busybox\nV:1.36\nA:x86_64\n", "alpine", "3.18"},
	}
	for _, tc := range cases {
		rootfs := writeRootfs(t, map[string]string{
			"etc/os-release": "ID=" + tc.id + "\nVERSION_ID=" + tc.verID + "\n",
			tc.dbPath:        tc.dbContent,
		})
		res, err := New().Catalog(context.Background(), rootfs)
		if err != nil || len(res.Components) != 1 || !res.DistroResolved {
			t.Fatalf("%s: catalog: %v / resolved=%v / %+v", tc.id, err, res.DistroResolved, res.Components)
		}
		tag := distroQualifier(res.Components[0].PURL)
		rel, ok := distro.ParseTag(tag)
		if !ok || rel.ID != tc.wantID || rel.Version != tc.wantVer {
			t.Errorf("%s: emitted tag %q -> ParseTag %+v ok=%v; want %s/%s", tc.id, tag, rel, ok, tc.wantID, tc.wantVer)
		}
	}
}

// TestCatalogRPMDistroResolution locks which rpm-family os-release IDs mark DistroResolved, in lockstep with
// rpmMatchableIDs and osDistroEcosystem: Amazon Linux resolves now that its updateinfo feed exists, while
// Fedora (no feed) and CentOS (Stream drifts ahead of RHEL) stay cataloged-but-unresolved. It reuses the real
// BerkeleyDB rpm fixture (the packages are inventory; only the os-release drives the resolved flag).
func TestCatalogRPMDistroResolution(t *testing.T) {
	cases := []struct {
		id, ver  string
		resolved bool
	}{
		{"amzn", "2", true},
		{"amzn", "2023", true},
		{"fedora", "40", true}, // resolves now that the owned Fedora updateinfo feed exists (Fedora:40)
		{"centos", "9", false}, // deliberately unmapped: CentOS Stream runs ahead of RHEL
	}
	for _, tc := range cases {
		t.Run(tc.id+"-"+tc.ver, func(t *testing.T) {
			rootfs := decompressFixture(t, "ubi8-micro.rpmdb.bdb.gz", rpmBDBPath)
			if err := os.MkdirAll(filepath.Join(rootfs, "etc"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(rootfs, "etc/os-release"), []byte("ID="+tc.id+"\nVERSION_ID=\""+tc.ver+"\"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			res, err := New().Catalog(context.Background(), rootfs)
			if err != nil {
				t.Fatalf("catalog: %v", err)
			}
			if len(res.Components) == 0 {
				t.Fatal("packages must still be cataloged for inventory")
			}
			if res.DistroResolved != tc.resolved {
				t.Errorf("%s-%s: DistroResolved=%v, want %v", tc.id, tc.ver, res.DistroResolved, tc.resolved)
			}
		})
	}
}

// TestCatalogWolfi: a Wolfi image (rolling apk distro) resolves its distro to the version-less "wolfi" key the
// owned apk secdb feed and osDistroEcosystem/DistroEcosystem agree on, and emits pkg:apk/wolfi PURLs.
func TestCatalogWolfi(t *testing.T) {
	for _, id := range []string{"wolfi", "chainguard"} {
		t.Run(id, func(t *testing.T) {
			rootfs := writeRootfs(t, map[string]string{
				"etc/os-release":       "ID=" + id + "\nVERSION_ID=\"20230201\"\n",
				"lib/apk/db/installed": "P:glibc\nV:2.39-r0\nA:x86_64\n",
			})
			res, err := New().Catalog(context.Background(), rootfs)
			if err != nil {
				t.Fatalf("catalog: %v", err)
			}
			if len(res.Components) != 1 || !res.DistroResolved {
				t.Fatalf("want 1 apk package + resolved distro, got %d / %v", len(res.Components), res.DistroResolved)
			}
			want := "pkg:apk/" + id + "/glibc@2.39-r0?arch=x86_64&distro=" + id
			if p := byName(res.Components)["glibc"].PURL; p != want {
				t.Errorf("glibc PURL = %q; want %q", p, want)
			}
			// The distro qualifier keys the family ecosystem the secdb feed writes.
			wantEco := "Wolfi"
			if id == "chainguard" {
				wantEco = "Chainguard"
			}
			if eco := sbom.IdentityFromComponent(byName(res.Components)["glibc"]).Ecosystem; eco != wantEco {
				t.Errorf("glibc ecosystem = %q, want %q", eco, wantEco)
			}
		})
	}
}

// upstreamQualifier extracts the raw (still percent-encoded) value of the deb PURL "upstream=" qualifier.
func upstreamQualifier(purl string) string {
	i := strings.IndexByte(purl, '?')
	if i < 0 {
		return ""
	}
	for _, kv := range strings.Split(purl[i+1:], "&") {
		if v, ok := strings.CutPrefix(kv, "upstream="); ok {
			return v
		}
	}
	return ""
}

func TestDpkgSourceQualifier(t *testing.T) {
	for _, tc := range []struct {
		name         string
		source, bin  string
		wantUpstream string
	}{
		{"absent source (binary is the source)", "", "coreutils", ""},
		{"same name, no version", "coreutils", "coreutils", ""},
		{"distinct source name only", "gnupg2", "gpgv", "gnupg2"},
		{"distinct source with version (binNMU)", "util-linux (2.38.1-5)", "libblkid1", "util-linux@2.38.1-5"},
		{"same name but explicit version is dropped (primary lookup owns it)", "bash (5.2.15-2)", "bash", ""},
		{"whitespace tolerated", "  glibc  ", "libc6", "glibc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := dpkgSourceQualifier(tc.source, tc.bin); got != tc.wantUpstream {
				t.Errorf("dpkgSourceQualifier(%q,%q) = %q, want %q", tc.source, tc.bin, got, tc.wantUpstream)
			}
		})
	}
}

// TestCatalogDebianSourceUpstream is the regression guard for EPIC #860 Debian OS-CVE recall: a binary
// package whose SOURCE name differs (gpgv from gnupg2, libgnutls30 from gnutls28) must carry an "upstream="
// qualifier so the advisory matcher, which keys Debian advisories by the SOURCE package, still matches it.
// Measured impact on python:3.9.18-slim: Debian CVE recall vs Trivy rose from 29% to 98% once this landed.
func TestCatalogDebianSourceUpstream(t *testing.T) {
	rootfs := writeRootfs(t, map[string]string{
		"etc/os-release": "ID=debian\nVERSION_ID=\"12\"\n",
		"var/lib/dpkg/status": "" +
			// distinct source name, no source version
			"Package: gpgv\nStatus: install ok installed\nVersion: 2.2.40-1.1\nArchitecture: amd64\nSource: gnupg2\n\n" +
			// distinct source name WITH a binNMU source version (binary version has +b1)
			"Package: libblkid1\nStatus: install ok installed\nVersion: 2.38.1-5+b1\nArchitecture: amd64\nSource: util-linux (2.38.1-5)\n\n" +
			// no Source field: the binary name IS the source, so no upstream qualifier
			"Package: coreutils\nStatus: install ok installed\nVersion: 9.1-1\nArchitecture: amd64\n",
	})
	res, err := New().Catalog(context.Background(), rootfs)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	by := byName(res.Components)
	if got := upstreamQualifier(by["gpgv"].PURL); got != "gnupg2" {
		t.Errorf("gpgv upstream = %q, want gnupg2 (%s)", got, by["gpgv"].PURL)
	}
	// util-linux@2.38.1-5, percent-encoded: '@' -> %40 (so a hostile Source cannot inject a qualifier).
	if got := upstreamQualifier(by["libblkid1"].PURL); got != "util-linux%402.38.1-5" {
		t.Errorf("libblkid1 upstream = %q, want util-linux%%402.38.1-5 (%s)", got, by["libblkid1"].PURL)
	}
	if got := upstreamQualifier(by["coreutils"].PURL); got != "" {
		t.Errorf("coreutils upstream = %q, want empty (no distinct source) (%s)", got, by["coreutils"].PURL)
	}
}

// TestCatalogDebianSourceQualifierInjectionSafe pins the qualifier-injection safety of the untrusted dpkg
// Source: field (the image controls /var/lib/dpkg/status). A Source value carrying PURL qualifier separators
// (&, =, ?) must be percent-encoded into the upstream= value and can never inject a SECOND qualifier such as
// distro=, which would cross-key the component to a foreign release and forge a CVE. This is a defense-in-depth
// regression guard on the #1 no-false-positive path: if purlEncode's allowlist were ever weakened, this fails.
func TestCatalogDebianSourceQualifierInjectionSafe(t *testing.T) {
	rootfs := writeRootfs(t, map[string]string{
		"etc/os-release":      "ID=debian\nVERSION_ID=\"12\"\n",
		"var/lib/dpkg/status": "Package: evilbin\nStatus: install ok installed\nVersion: 1.0\nArchitecture: amd64\nSource: evil&distro=lies (1.0)\n",
	})
	res, err := New().Catalog(context.Background(), rootfs)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	c := byName(res.Components)["evilbin"]
	// The only distro qualifier is the legit release, never an injected distro=lies.
	if got := distroQualifier(c.PURL); got != "debian-12" {
		t.Errorf("distro qualifier = %q, want debian-12 (a hostile Source must not inject distro=): %s", got, c.PURL)
	}
	if strings.Count(c.PURL, "distro=") != 1 {
		t.Errorf("PURL carries an injected qualifier: %s", c.PURL)
	}
	// The hostile separators are percent-encoded inside the upstream value (& -> %26, = -> %3D, @ -> %40).
	if up := upstreamQualifier(c.PURL); up != "evil%26distro%3Dlies%401.0" {
		t.Errorf("upstream = %q, want evil%%26distro%%3Dlies%%401.0 (separators percent-encoded)", up)
	}
}
