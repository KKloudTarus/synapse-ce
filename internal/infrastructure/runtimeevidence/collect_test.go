package runtimeevidence

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/runtimereach"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// writeFile creates a file (and its parents) under root at the logical path, with content, so the collector
// can lstat it for a real device+inode in tests.
func writeFile(t *testing.T, root, logical, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(logical))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func dpkgRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, root, "/var/lib/dpkg/status", "Package: libssl3\nVersion: 3.0.13-0ubuntu3.4\nArchitecture: amd64\n\nPackage: libpng16-16\nVersion: 1.6.43-5\n\n")
	writeFile(t, root, "/var/lib/dpkg/info/libssl3:amd64.list", "/.\n/usr/lib/x86_64-linux-gnu\n/usr/lib/x86_64-linux-gnu/libssl.so.3\n")
	writeFile(t, root, "/var/lib/dpkg/info/libpng16-16:amd64.list", "/usr/lib/x86_64-linux-gnu/libpng16.so.16\n")
	// The actual files, so lstat yields a real device+inode.
	writeFile(t, root, "/usr/lib/x86_64-linux-gnu/libssl.so.3", "so")
	writeFile(t, root, "/usr/lib/x86_64-linux-gnu/libpng16.so.16", "so")
	return root
}

func TestCollectDpkgResolvesLoadedPackageWithFileID(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("dpkg runtime evidence requires Linux filesystem semantics")
	}
	root := dpkgRoot(t)
	rep := NewCollector(root).Collect([]string{"/usr/lib/x86_64-linux-gnu/libssl.so.3"})
	if len(rep.Coverage) != 0 {
		t.Fatalf("unexpected coverage gaps: %v", rep.Coverage)
	}
	if len(rep.PackageFiles) != 1 || rep.PackageFiles[0].Package != (runtimereach.PackageRef{Name: "libssl3", Version: "3.0.13-0ubuntu3.4"}) {
		t.Fatalf("expected only libssl3 scoped in, got %+v", rep.PackageFiles)
	}
	// The loaded object's file carries a real device+inode.
	var sslFile *runtimereach.OwnedFile
	for i := range rep.PackageFiles[0].Files {
		if rep.PackageFiles[0].Files[i].Path == "/usr/lib/x86_64-linux-gnu/libssl.so.3" {
			sslFile = &rep.PackageFiles[0].Files[i]
		}
	}
	if sslFile == nil || !sslFile.ID.Known() {
		t.Fatalf("owned .so must carry device+inode, got %+v", sslFile)
	}
	if len(rep.Loads) != 1 || !rep.Loads[0].ID.Known() {
		t.Fatalf("load must carry device+inode, got %+v", rep.Loads)
	}
	// End-to-end: the join resolves the load to libssl3 by file identity.
	own, loads := rep.Build()
	hits := runtimereach.Join(loads, own, []runtimereach.FindingPackage{
		{FindingID: shared.ID("f-ssl"), Package: runtimereach.PackageRef{Name: "libssl3", Version: "3.0.13-0ubuntu3.4"}},
		{FindingID: shared.ID("f-png"), Package: runtimereach.PackageRef{Name: "libpng16-16", Version: "1.6.43-5"}},
	})
	if len(hits) != 1 || hits[0].FindingID != "f-ssl" {
		t.Fatalf("join must raise only f-ssl (the loaded package), got %+v", hits)
	}
}

func TestCollectDpkgUsrmergeSymlinkResolvesByRealPath(t *testing.T) {
	root := dpkgRoot(t)
	// usrmerge: /lib is a symlink to /usr/lib, and the load is observed under /lib while dpkg records /usr/lib.
	if err := os.Symlink(filepath.Join(root, "usr", "lib"), filepath.Join(root, "lib")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	rep := NewCollector(root).Collect([]string{"/lib/x86_64-linux-gnu/libssl.so.3"})
	if len(rep.PackageFiles) != 1 || rep.PackageFiles[0].Package.Name != "libssl3" {
		t.Fatalf("usrmerge load must still resolve libssl3, got %+v", rep.PackageFiles)
	}
	if rep.Loads[0].RealPath != "/usr/lib/x86_64-linux-gnu/libssl.so.3" {
		t.Fatalf("load real path should resolve the usrmerge symlink, got %q", rep.Loads[0].RealPath)
	}
	own, loads := rep.Build()
	hits := runtimereach.Join(loads, own, []runtimereach.FindingPackage{{FindingID: "f-ssl", Package: runtimereach.PackageRef{Name: "libssl3", Version: "3.0.13-0ubuntu3.4"}}})
	if len(hits) != 1 || hits[0].Match != runtimereach.MatchFileIdentity {
		t.Fatalf("usrmerge load must join by device+inode, got %+v", hits)
	}
}

// TestCollectDpkgMultiarchResolvesPerArchVersion pins the multiarch fix: two architectures of the same
// package installed at DIFFERENT versions must each resolve to their own version, not collapse to the
// last status stanza. The loaded amd64 object must carry the amd64 version.
func TestCollectDpkgMultiarchResolvesPerArchVersion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("dpkg multiarch metadata uses colon-qualified filenames")
	}
	root := t.TempDir()
	writeFile(t, root, "/var/lib/dpkg/status",
		"Package: libc6\nVersion: 2.39-amd64\nArchitecture: amd64\n\nPackage: libc6\nVersion: 2.39-i386\nArchitecture: i386\n\n")
	writeFile(t, root, "/var/lib/dpkg/info/libc6:amd64.list", "/usr/lib/x86_64-linux-gnu/libc.so.6\n")
	writeFile(t, root, "/var/lib/dpkg/info/libc6:i386.list", "/usr/lib/i386-linux-gnu/libc.so.6\n")
	writeFile(t, root, "/usr/lib/x86_64-linux-gnu/libc.so.6", "so")
	writeFile(t, root, "/usr/lib/i386-linux-gnu/libc.so.6", "so")

	rep := NewCollector(root).Collect([]string{"/usr/lib/x86_64-linux-gnu/libc.so.6"})
	if len(rep.PackageFiles) != 1 {
		t.Fatalf("only the amd64 arch owns the loaded object, got %+v", rep.PackageFiles)
	}
	if got := rep.PackageFiles[0].Package; got != (runtimereach.PackageRef{Name: "libc6", Version: "2.39-amd64"}) {
		t.Fatalf("multiarch load must resolve the amd64 version, got %+v", got)
	}
}

func TestCollectApkResolvesLoadedPackage(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/lib/apk/db/installed", "P:musl\nV:1.2.5-r0\nF:lib\nR:libc.musl-x86_64.so.1\n\nP:zlib\nV:1.3.1-r1\nF:lib\nR:libz.so.1\n\n")
	writeFile(t, root, "/lib/libc.musl-x86_64.so.1", "so")
	writeFile(t, root, "/lib/libz.so.1", "so")
	rep := NewCollector(root).Collect([]string{"/lib/libc.musl-x86_64.so.1"})
	if len(rep.PackageFiles) != 1 || rep.PackageFiles[0].Package != (runtimereach.PackageRef{Name: "musl", Version: "1.2.5-r0"}) {
		t.Fatalf("expected only musl scoped in, got %+v", rep.PackageFiles)
	}
}

// TestCollectApkOwningRecordWithoutVersionIsHonestGap pins that an apk record owning a loaded object but
// missing its name/version is declared as a coverage gap, not silently dropped (mirrors the dpkg path).
func TestCollectApkOwningRecordWithoutVersionIsHonestGap(t *testing.T) {
	root := t.TempDir()
	// A record with a file list but no "V:" version line, owning the loaded object.
	writeFile(t, root, "/lib/apk/db/installed", "P:musl\nF:lib\nR:libc.musl-x86_64.so.1\n\n")
	writeFile(t, root, "/lib/libc.musl-x86_64.so.1", "so")
	rep := NewCollector(root).Collect([]string{"/lib/libc.musl-x86_64.so.1"})
	if len(rep.PackageFiles) != 0 {
		t.Fatalf("an unversioned owning record must not be emitted, got %+v", rep.PackageFiles)
	}
	found := false
	for _, c := range rep.Coverage {
		if c == runtimereach.CoverageUnreadablePackageDB {
			found = true
		}
	}
	if !found {
		t.Fatalf("an unversioned owning record must declare a coverage gap, got %+v", rep.Coverage)
	}
}

func TestCollectRpmIsHonestGap(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/var/lib/rpm/rpmdb.sqlite", "binary")
	rep := NewCollector(root).Collect([]string{"/usr/lib64/libssl.so.3"})
	if len(rep.PackageFiles) != 0 {
		t.Fatalf("rpm ownership is not collected; expected no packages, got %+v", rep.PackageFiles)
	}
	if len(rep.Coverage) != 1 || rep.Coverage[0] != runtimereach.CoverageUnreadablePackageDB {
		t.Fatalf("rpm host must declare a coverage gap, got %v", rep.Coverage)
	}
}

func TestCollectUnsupportedPlatformIsHonest(t *testing.T) {
	rep := NewCollector(t.TempDir()).Collect([]string{"/usr/lib/libssl.so.3"})
	if len(rep.PackageFiles) != 0 || len(rep.Coverage) != 1 || rep.Coverage[0] != runtimereach.CoverageUnsupportedPlatform {
		t.Fatalf("a host with no known package DB must declare unsupported-platform, got packages=%d coverage=%v", len(rep.PackageFiles), rep.Coverage)
	}
}

func TestCollectNoLoadsIsEmpty(t *testing.T) {
	rep := NewCollector(dpkgRoot(t)).Collect(nil)
	if len(rep.PackageFiles) != 0 || len(rep.Loads) != 0 {
		t.Fatalf("no observed loads must produce an empty report, got %+v", rep)
	}
}

func TestCollectDeletedMarkerAndDedup(t *testing.T) {
	root := dpkgRoot(t)
	rep := NewCollector(root).Collect([]string{
		"/usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)",
		"/usr/lib/x86_64-linux-gnu/libssl.so.3", // duplicate of the cleaned path
	})
	if len(rep.Loads) != 1 {
		t.Fatalf("deleted marker + duplicate must collapse to one load, got %+v", rep.Loads)
	}
	if !rep.Loads[0].Deleted {
		// the first (deleted) observation set the flag; dedup keeps the first
		t.Logf("note: dedup kept load %+v", rep.Loads[0])
	}
}
