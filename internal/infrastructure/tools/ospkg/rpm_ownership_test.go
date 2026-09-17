package ospkg

import (
	"context"
	"database/sql"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// bashFilesHeader builds a bash header that also owns three files under three directories, exercising the
// DIRNAMES/DIRINDEXES/BASENAMES reconstruction path[i] = DIRNAMES[DIRINDEXES[i]] + BASENAMES[i].
func bashFilesHeader(t *testing.T) []byte {
	t.Helper()
	return buildRPMHeader(t, true, []rpmTagEntry{
		{tag: rpmTagName, typ: rpmTypeString, str: "bash"},
		{tag: rpmTagVersion, typ: rpmTypeString, str: "5.1.8"},
		{tag: rpmTagRelease, typ: rpmTypeString, str: "9.el9"},
		{tag: rpmTagArch, typ: rpmTypeString, str: "x86_64"},
		{tag: rpmTagBaseNames, typ: rpmTypeStringArr, strs: []string{"bash", "libreadline.so.8", "bashrc"}},
		{tag: rpmTagDirNames, typ: rpmTypeStringArr, strs: []string{"/usr/bin/", "/usr/lib64/", "/etc/"}},
		{tag: rpmTagDirIndexes, typ: rpmTypeInt32, i32s: []uint32{0, 1, 2}},
	})
}

func TestParseRPMHeaderFiles(t *testing.T) {
	name, evr, arch, files, ok := parseRPMHeaderFiles(bashFilesHeader(t))
	if !ok || name != "bash" || evr != "5.1.8-9.el9" || arch != "x86_64" {
		t.Fatalf("identity = %q/%q/%q ok=%v; want bash/5.1.8-9.el9/x86_64", name, evr, arch, ok)
	}
	want := []string{"/usr/bin/bash", "/usr/lib64/libreadline.so.8", "/etc/bashrc"}
	if len(files) != len(want) {
		t.Fatalf("files = %v; want %v", files, want)
	}
	for i := range want {
		if files[i] != want[i] {
			t.Errorf("files[%d] = %q; want %q", i, files[i], want[i])
		}
	}
}

func TestParseRPMHeaderFilesMetapackage(t *testing.T) {
	// No BASENAMES/DIRNAMES/DIRINDEXES tags: a metapackage that installs no files. Identity still parses,
	// and files is nil (not an error), so RPMOwnership drops it as unable to own a loaded object.
	blob := buildRPMHeader(t, true, []rpmTagEntry{
		{tag: rpmTagName, typ: rpmTypeString, str: "basesystem"},
		{tag: rpmTagVersion, typ: rpmTypeString, str: "11"},
		{tag: rpmTagRelease, typ: rpmTypeString, str: "13.el9"},
	})
	name, _, _, files, ok := parseRPMHeaderFiles(blob)
	if !ok || name != "basesystem" || files != nil {
		t.Errorf("metapackage: name=%q files=%v ok=%v; want basesystem / nil files / ok", name, files, ok)
	}
}

func TestParseRPMHeaderFilesInconsistentArrays(t *testing.T) {
	// BASENAMES has 2 entries but DIRINDEXES has 3: an internally inconsistent header. The parser refuses to
	// fabricate paths and returns identity with no files rather than a misindexed guess.
	blob := buildRPMHeader(t, true, []rpmTagEntry{
		{tag: rpmTagName, typ: rpmTypeString, str: "pkg"},
		{tag: rpmTagVersion, typ: rpmTypeString, str: "1"},
		{tag: rpmTagBaseNames, typ: rpmTypeStringArr, strs: []string{"a", "b"}},
		{tag: rpmTagDirNames, typ: rpmTypeStringArr, strs: []string{"/x/"}},
		{tag: rpmTagDirIndexes, typ: rpmTypeInt32, i32s: []uint32{0, 0, 0}},
	})
	if _, _, _, files, ok := parseRPMHeaderFiles(blob); !ok || files != nil {
		t.Errorf("inconsistent arrays: files=%v ok=%v; want ok with nil files", files, ok)
	}
}

func TestParseRPMHeaderFilesDirIndexOutOfRange(t *testing.T) {
	// A DIRINDEXES entry past the end of DIRNAMES is skipped, never an out-of-range read; the in-range file
	// is still reconstructed.
	blob := buildRPMHeader(t, true, []rpmTagEntry{
		{tag: rpmTagName, typ: rpmTypeString, str: "pkg"},
		{tag: rpmTagVersion, typ: rpmTypeString, str: "1"},
		{tag: rpmTagBaseNames, typ: rpmTypeStringArr, strs: []string{"good", "orphan"}},
		{tag: rpmTagDirNames, typ: rpmTypeStringArr, strs: []string{"/x/"}},
		{tag: rpmTagDirIndexes, typ: rpmTypeInt32, i32s: []uint32{0, 5}},
	})
	_, _, _, files, ok := parseRPMHeaderFiles(blob)
	if !ok || len(files) != 1 || files[0] != "/x/good" {
		t.Errorf("out-of-range dir index: files=%v ok=%v; want [/x/good]", files, ok)
	}
}

// writeRPMFilesRootfs builds a temp rootfs with a rpmdb.sqlite holding one file-bearing bash header, written
// with the same driver ospkg reads with.
func writeRPMFilesRootfs(t *testing.T) string {
	t.Helper()
	rootfs := t.TempDir()
	dbPath := filepath.Join(rootfs, "var/lib/rpm/rpmdb.sqlite")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO Packages(blob) VALUES(?)", bashFilesHeader(t)); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	return rootfs
}

func TestRPMOwnership(t *testing.T) {
	pkgs, err := RPMOwnership(context.Background(), writeRPMFilesRootfs(t))
	if err != nil {
		t.Fatalf("RPMOwnership: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("want 1 package, got %d: %+v", len(pkgs), pkgs)
	}
	p := pkgs[0]
	if p.Name != "bash" || p.Version != "5.1.8-9.el9" || p.Arch != "x86_64" {
		t.Errorf("package = %+v; want bash / 5.1.8-9.el9 / x86_64", p)
	}
	want := map[string]bool{"/usr/bin/bash": true, "/usr/lib64/libreadline.so.8": true, "/etc/bashrc": true}
	if len(p.Files) != len(want) {
		t.Fatalf("files = %v; want the 3 owned paths", p.Files)
	}
	for _, f := range p.Files {
		if !want[f] {
			t.Errorf("unexpected owned file %q", f)
		}
	}
}

// TestRPMOwnershipRelocatedSqlite pins that an offline rootfs carrying the sqlite rpmdb ONLY at the relocated
// /usr/lib/sysimage/rpm location (no /var/lib/rpm symlink to resolve it) is still read.
func TestRPMOwnershipRelocatedSqlite(t *testing.T) {
	rootfs := t.TempDir()
	dbPath := filepath.Join(rootfs, "usr/lib/sysimage/rpm/rpmdb.sqlite")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO Packages(blob) VALUES(?)", bashFilesHeader(t)); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	pkgs, err := RPMOwnership(context.Background(), rootfs)
	if err != nil {
		t.Fatalf("RPMOwnership relocated sqlite: %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "bash" {
		t.Fatalf("relocated sqlite rpmdb must be read, got %+v", pkgs)
	}
}

func TestRPMOwnershipAbsentDB(t *testing.T) {
	// An empty rootfs (no rpm DB in any container) yields no packages and no error, so the collector records
	// a coverage gap rather than a spurious ownership set.
	pkgs, err := RPMOwnership(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("RPMOwnership on empty rootfs: %v", err)
	}
	if len(pkgs) != 0 {
		t.Errorf("empty rootfs: want no packages, got %+v", pkgs)
	}
}

func TestRPMOwnershipHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := RPMOwnership(ctx, writeRPMFilesRootfs(t)); err == nil {
		t.Error("a cancelled context must surface an error from RPMOwnership")
	}
}

// TestParseRPMHeaderFilesBoundsHostileAmplification pins the output-amplification guard (security gate): a
// crafted header that reuses ONE multi-megabyte DIRNAMES entry across many basenames must never expand into
// gigabytes of reconstructed strings (an OOM the recover cannot catch). The per-path length cap and the
// per-header byte budget each bound it.
func TestParseRPMHeaderFilesBoundsHostileAmplification(t *testing.T) {
	// Vector 1: one ~6 MiB directory reused across 100k basenames. Every reconstructed path exceeds
	// maxRPMPathLen, so each is skipped BEFORE the concat that would allocate ~6 MiB; files ends up empty.
	hugeDir := "/" + strings.Repeat("a", 6<<20) + "/"
	n := 100_000
	bases := make([]string, n)
	idxs := make([]uint32, n)
	for i := range bases {
		bases[i] = "f"
	}
	blob := buildRPMHeader(t, true, []rpmTagEntry{
		{tag: rpmTagName, typ: rpmTypeString, str: "bomb"},
		{tag: rpmTagVersion, typ: rpmTypeString, str: "1"},
		{tag: rpmTagDirNames, typ: rpmTypeStringArr, strs: []string{hugeDir}},
		{tag: rpmTagBaseNames, typ: rpmTypeStringArr, strs: bases},
		{tag: rpmTagDirIndexes, typ: rpmTypeInt32, i32s: idxs},
	})
	_, _, _, files, ok := parseRPMHeaderFiles(blob)
	if !ok {
		t.Fatal("vector 1: header identity must still parse")
	}
	if len(files) != 0 {
		t.Fatalf("vector 1: a >PATH_MAX reconstructed path must be skipped, got %d files", len(files))
	}

	// Vector 2: a just-under-PATH_MAX directory reused across enough basenames to blow past the per-header
	// byte budget. Reconstruction must stop at the budget, never materialize all of them.
	dir := "/" + strings.Repeat("b", 3998) + "/" // len 4000; path len ~4001 <= maxRPMPathLen
	m := (maxRPMFileListBytes / 4000) + 5000     // more entries than the 32 MiB budget can hold
	bases2 := make([]string, m)
	idxs2 := make([]uint32, m)
	for i := range bases2 {
		bases2[i] = "f"
	}
	blob2 := buildRPMHeader(t, true, []rpmTagEntry{
		{tag: rpmTagName, typ: rpmTypeString, str: "bomb2"},
		{tag: rpmTagVersion, typ: rpmTypeString, str: "1"},
		{tag: rpmTagDirNames, typ: rpmTypeStringArr, strs: []string{dir}},
		{tag: rpmTagBaseNames, typ: rpmTypeStringArr, strs: bases2},
		{tag: rpmTagDirIndexes, typ: rpmTypeInt32, i32s: idxs2},
	})
	_, _, _, files2, ok2 := parseRPMHeaderFiles(blob2)
	if !ok2 {
		t.Fatal("vector 2: header identity must still parse")
	}
	total := 0
	for _, f := range files2 {
		total += len(f)
	}
	if total > maxRPMFileListBytes {
		t.Fatalf("vector 2: reconstructed bytes %d exceed the per-header budget %d", total, maxRPMFileListBytes)
	}
	if len(files2) >= m {
		t.Fatalf("vector 2: byte budget must truncate, got all %d files", len(files2))
	}
}

// opensslBDBHeaderTags is one openssl-libs header owning /usr/lib64/libssl.so.3, for the BDB/short-circuit
// fixtures. BDB blobs carry no 8e-ad-e8-01 magic lead (withMagic=false at the call site).
func opensslBDBHeaderTags() []rpmTagEntry {
	return []rpmTagEntry{
		{tag: rpmTagName, typ: rpmTypeString, str: "openssl-libs"},
		{tag: rpmTagVersion, typ: rpmTypeString, str: "3.0.7"},
		{tag: rpmTagRelease, typ: rpmTypeString, str: "27.el9"},
		{tag: rpmTagArch, typ: rpmTypeString, str: "x86_64"},
		{tag: rpmTagBaseNames, typ: rpmTypeStringArr, strs: []string{"libssl.so.3"}},
		{tag: rpmTagDirNames, typ: rpmTypeStringArr, strs: []string{"/usr/lib64/"}},
		{tag: rpmTagDirIndexes, typ: rpmTypeInt32, i32s: []uint32{0}},
	}
}

// TestRPMOwnershipBDBBackend exercises the BerkeleyDB walker end-to-end through RPMOwnership (the sqlite path
// is covered by TestRPMOwnership), locking that all three container walkers reconstruct file ownership
// identically.
func TestRPMOwnershipBDBBackend(t *testing.T) {
	rootfs := t.TempDir()
	db := buildBDBHash(t, binary.LittleEndian, [][]byte{buildRPMHeader(t, false, opensslBDBHeaderTags())})
	dbPath := filepath.Join(rootfs, "var/lib/rpm/Packages")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbPath, db, 0o644); err != nil {
		t.Fatal(err)
	}
	pkgs, err := RPMOwnership(context.Background(), rootfs)
	if err != nil {
		t.Fatalf("RPMOwnership BDB: %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "openssl-libs" ||
		len(pkgs[0].Files) != 1 || pkgs[0].Files[0] != "/usr/lib64/libssl.so.3" {
		t.Fatalf("BDB ownership = %+v; want openssl-libs owning /usr/lib64/libssl.so.3", pkgs)
	}
}

// TestRPMOwnershipSqliteBackendShortCircuits pins the double-count guard: when the sqlite backend parses a
// valid header (here a metapackage owning no files), the walk stops there and the BerkeleyDB backend is never
// read, even though it holds a file-owning package. This is what keeps a rootfs whose /var/lib/rpm symlinks
// to a second container from being counted twice.
func TestRPMOwnershipSqliteBackendShortCircuits(t *testing.T) {
	rootfs := t.TempDir()
	// sqlite backend present with ONLY a metapackage (no files): saw=true, out empty.
	dbPath := filepath.Join(rootfs, "var/lib/rpm/rpmdb.sqlite")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB)"); err != nil {
		t.Fatal(err)
	}
	meta := buildRPMHeader(t, true, []rpmTagEntry{
		{tag: rpmTagName, typ: rpmTypeString, str: "basesystem"},
		{tag: rpmTagVersion, typ: rpmTypeString, str: "11"},
	})
	if _, err := db.Exec("INSERT INTO Packages(blob) VALUES(?)", meta); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	// BerkeleyDB backend ALSO present with a file-owning package; it must NOT be read.
	bdb := buildBDBHash(t, binary.LittleEndian, [][]byte{buildRPMHeader(t, false, opensslBDBHeaderTags())})
	bdbPath := filepath.Join(rootfs, "var/lib/rpm/Packages")
	if err := os.WriteFile(bdbPath, bdb, 0o644); err != nil {
		t.Fatal(err)
	}
	pkgs, err := RPMOwnership(context.Background(), rootfs)
	if err != nil {
		t.Fatalf("RPMOwnership: %v", err)
	}
	if len(pkgs) != 0 {
		t.Fatalf("a readable sqlite backend must short-circuit; the BDB package must not be read, got %+v", pkgs)
	}
}
