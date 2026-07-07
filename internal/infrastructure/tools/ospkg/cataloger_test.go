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
