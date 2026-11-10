package ospkg

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCatalogDpkgFragments(t *testing.T) {
	root := writeRootfs(t, map[string]string{
		"etc/os-release":                        "ID=debian\nVERSION_ID=12\n",
		"var/lib/dpkg/status":                   "Package: base-files\nStatus: install ok installed\nVersion: 12.4\nArchitecture: amd64\n",
		"var/lib/dpkg/status.d/base-files":      "Package: base-files\nVersion: 12.4\nArchitecture: amd64\n",
		"var/lib/dpkg/status.d/libssl3":         "Package: libssl3\nVersion: 3.0.11-1\nArchitecture: amd64\nSource: openssl (3.0.11-1)\n",
		"var/lib/dpkg/status.d/libssl3.md5sums": "Package: checksum-is-not-a-package\nVersion: 1\n",
		"var/lib/dpkg/status.d/removed":         "Package: removed\nStatus: deinstall ok config-files\nVersion: 1\n",
	})
	res, err := New().Catalog(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Components) != 2 || !res.DistroResolved {
		t.Fatalf("want two distinct installed Debian packages, got %+v", res)
	}
	ssl := byName(res.Components)["libssl3"]
	if ssl.PURL != "pkg:deb/debian/libssl3@3.0.11-1?arch=amd64&distro=debian-12&upstream=openssl%403.0.11-1" || ssl.Location != filepath.Join(root, "var/lib/dpkg/status.d/libssl3") {
		t.Fatalf("fragment identity and provenance lost: %+v", ssl)
	}
}

func TestCatalogDpkgFragmentsWithoutStatusDatabase(t *testing.T) {
	root := writeRootfs(t, map[string]string{
		"etc/os-release":                   "ID=debian\nVERSION_ID=12\n",
		"var/lib/dpkg/status.d/base-files": "Package: base-files\nVersion: 12.4\nArchitecture: arm64\n",
	})
	res, err := New().Catalog(context.Background(), root)
	if err != nil || len(res.Components) != 1 || !res.DistroResolved {
		t.Fatalf("distroless packages not inventoried: %+v, %v", res, err)
	}
}

func TestCatalogDpkgFragmentsRejectsUnsafeAndOversizedInputs(t *testing.T) {
	for _, kind := range []string{"symlink directory", "symlink package", "ancestor escape", "oversized package", "malformed package"} {
		t.Run(kind, func(t *testing.T) {
			root := writeRootfs(t, map[string]string{"etc/os-release": "ID=debian\nVERSION_ID=12\n"})
			dir := filepath.Join(root, "var/lib/dpkg/status.d")
			if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
				t.Fatal(err)
			}
			outside := writeRootfs(t, map[string]string{"package": "Package: outside\nVersion: 1\n"})
			switch kind {
			case "symlink directory":
				if err := os.Symlink(outside, dir); err != nil {
					t.Skip(err)
				}
			case "ancestor escape":
				if err := os.RemoveAll(filepath.Join(root, "var")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, filepath.Join(root, "var")); err != nil {
					t.Skip(err)
				}
			case "symlink package":
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(outside, "package"), filepath.Join(dir, "package")); err != nil {
					t.Skip(err)
				}
			default:
				content := "Package: missing-version\n"
				if kind == "oversized package" {
					content = "Package: big\nVersion: 1\nDescription: " + strings.Repeat("x", maxDBLine)
				}
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "package"), []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			res, err := New().Catalog(context.Background(), root)
			if len(res.Components) != 0 {
				t.Fatalf("unsafe input emitted packages: %+v", res)
			}
			if err == nil {
				t.Fatal("unreadable or invalid package inventory must be reported")
			}
		})
	}
}

func TestDpkgFragmentBoundsAndCancellation(t *testing.T) {
	root := writeRootfs(t, map[string]string{
		"var/lib/dpkg/status.d/a": "Package: alpha\nVersion: 1\n",
		"var/lib/dpkg/status.d/b": "Package: beta\nVersion: 2\n",
	})
	for _, tc := range []struct {
		name           string
		entries, bytes int
	}{
		{"entry limit", 1, maxDBBytes},
		{"aggregate bytes", 2, 40},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseDpkgFragments(context.Background(), root, "debian", "debian-12", tc.entries, tc.bytes); err == nil {
				t.Fatal("exhausted directory budget must be reported")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := parseDpkgFragments(ctx, root, "debian", "debian-12", 2, maxDBBytes); err != context.Canceled {
		t.Fatalf("cancellation lost: %v", err)
	}
}

func TestCatalogMissingOSInventoryWarning(t *testing.T) {
	for _, id := range []string{"debian", "wolfi", "unknown-linux"} {
		root := writeRootfs(t, map[string]string{"etc/os-release": "ID=" + id + "\nVERSION_ID=12\n"})
		res, err := New().Catalog(context.Background(), root)
		if err != nil || len(res.Components) != 0 || !strings.Contains(res.InventoryWarning, id) || !strings.Contains(res.InventoryWarning, "OS packages were not inventoried") {
			t.Fatalf("missing OS inventory must identify distro %s: %+v err=%v", id, res, err)
		}
	}
}
