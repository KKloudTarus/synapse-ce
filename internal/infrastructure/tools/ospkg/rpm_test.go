package ospkg

import (
	"context"
	"database/sql"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// rpmTagEntry is one header tag for the test builder.
type rpmTagEntry struct {
	tag, typ uint32
	str      string
	i32      uint32
}

// buildRPMHeader encodes tags into an RPM header blob in the exact on-disk layout parseRPMHeader reads:
// optional [magic(4)+reserved(4)], nindex(u32), hsize(u32), nindex×16-byte index entries, then the data store.
func buildRPMHeader(t *testing.T, withMagic bool, tags []rpmTagEntry) []byte {
	t.Helper()
	var data, index []byte
	for _, e := range tags {
		off := uint32(len(data))
		ent := make([]byte, 16)
		binary.BigEndian.PutUint32(ent[0:], e.tag)
		binary.BigEndian.PutUint32(ent[4:], e.typ)
		binary.BigEndian.PutUint32(ent[8:], off)
		binary.BigEndian.PutUint32(ent[12:], 1) // count
		index = append(index, ent...)
		if e.typ == rpmTypeInt32 {
			b := make([]byte, 4)
			binary.BigEndian.PutUint32(b, e.i32)
			data = append(data, b...)
		} else {
			data = append(data, []byte(e.str)...)
			data = append(data, 0) // NUL terminator
		}
	}
	var buf []byte
	if withMagic {
		buf = append(buf, rpmHeaderMagic[:]...)
		buf = append(buf, 0, 0, 0, 0)
	}
	intro := make([]byte, 8)
	binary.BigEndian.PutUint32(intro[0:], uint32(len(tags)))
	binary.BigEndian.PutUint32(intro[4:], uint32(len(data)))
	buf = append(buf, intro...)
	buf = append(buf, index...)
	buf = append(buf, data...)
	return buf
}

func bashHeader(t *testing.T, epoch uint32) []byte {
	tags := []rpmTagEntry{
		{tag: rpmTagName, typ: rpmTypeString, str: "bash"},
		{tag: rpmTagVersion, typ: rpmTypeString, str: "5.1.8"},
		{tag: rpmTagRelease, typ: rpmTypeString, str: "9.el9"},
		{tag: rpmTagEpoch, typ: rpmTypeInt32, i32: epoch},
		{tag: rpmTagArch, typ: rpmTypeString, str: "x86_64"},
	}
	return buildRPMHeader(t, true, tags)
}

func TestParseRPMHeader(t *testing.T) {
	name, evr, arch, ok := parseRPMHeader(bashHeader(t, 0))
	if !ok || name != "bash" || evr != "5.1.8-9.el9" || arch != "x86_64" {
		t.Errorf("epoch 0: got %q/%q/%q ok=%v; want bash/5.1.8-9.el9/x86_64", name, evr, arch, ok)
	}
	// A non-zero epoch prefixes the EVR (matching the rpm comparator's expected "[epoch:]version-release").
	if _, evr, _, ok := parseRPMHeader(bashHeader(t, 2)); !ok || evr != "2:5.1.8-9.el9" {
		t.Errorf("epoch 2: evr = %q ok=%v; want 2:5.1.8-9.el9", evr, ok)
	}
	// The blob also parses without the 8-byte magic lead (some stores omit it).
	if name, _, _, ok := parseRPMHeader(buildRPMHeader(t, false, []rpmTagEntry{{tag: rpmTagName, typ: rpmTypeString, str: "zlib"}, {tag: rpmTagVersion, typ: rpmTypeString, str: "1.2"}})); !ok || name != "zlib" {
		t.Errorf("no-magic header: name = %q ok=%v; want zlib", name, ok)
	}
}

func TestParseRPMHeaderRejectsMalformed(t *testing.T) {
	cases := map[string][]byte{
		"too short":        {0x8e, 0xad, 0xe8, 0x01},
		"huge nindex":      append(append([]byte{}, rpmHeaderMagic[:]...), 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0), // nindex 4B
		"data beyond blob": append(append([]byte{}, rpmHeaderMagic[:]...), 0, 0, 0, 0, 0, 0, 0, 1, 0x7f, 0xff, 0xff, 0xff), // hsize huge
		"empty":            {},
	}
	for name, blob := range cases {
		if _, _, _, ok := safeParseRPMHeader(blob); ok {
			t.Errorf("%s: must be rejected (no panic, ok=false)", name)
		}
	}
	// An in-range index whose string offset is out of the data store yields no name → rejected, never an OOB read.
	oob := buildRPMHeader(t, true, []rpmTagEntry{{tag: rpmTagName, typ: rpmTypeString, str: "x"}})
	// corrupt the name entry's offset (bytes at index 16 [after magic+intro=16] +8..+12) to a huge value
	binary.BigEndian.PutUint32(oob[16+8:16+12], 0xffffff)
	if _, _, _, ok := safeParseRPMHeader(oob); ok {
		t.Error("an out-of-range string offset must be rejected, not read OOB")
	}
}

// writeRPMRootfs builds a temp rootfs with the given os-release contents and a rpmdb.sqlite holding one bash
// header, written with the same driver the cataloger reads with.
func writeRPMRootfs(t *testing.T, osRelease string) string {
	t.Helper()
	rootfs := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootfs, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootfs, "etc/os-release"), []byte(osRelease), 0o644); err != nil {
		t.Fatal(err)
	}
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
	if _, err := db.Exec("INSERT INTO Packages(blob) VALUES(?)", bashHeader(t, 0)); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	return rootfs
}

func TestCatalogRPMSqlite(t *testing.T) {
	rootfs := writeRPMRootfs(t, "ID=rocky\nVERSION_ID=\"9.3\"\n")
	res, err := New().Catalog(context.Background(), rootfs)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	if len(res.Components) != 1 {
		t.Fatalf("want 1 rpm component, got %d: %+v", len(res.Components), res.Components)
	}
	c := res.Components[0]
	if c.Name != "bash" || c.Version != "5.1.8-9.el9" || c.PURL != "pkg:rpm/rocky/bash@5.1.8-9.el9?arch=x86_64&distro=rocky-9.3" {
		t.Errorf("rpm component = %+v; want bash / 5.1.8-9.el9 / rocky rpm PURL", c)
	}
	if !res.DistroResolved { // rocky is a matchable rpm distro
		t.Error("a Rocky Linux rpm DB must resolve its distro")
	}
}

// TestParseRPMHeaderReadsEachTagOnce locks the read-once guard that neutralizes the work-amplification vector:
// a crafted header can repeat an identity tag many times over a NUL-free data store, but each identity tag is
// read at most once (first wins), so rpmCStr runs a bounded number of times regardless of nindex.
func TestParseRPMHeaderReadsEachTagOnce(t *testing.T) {
	// Two NAME tags: read-once keeps the FIRST ("bash"); a regression to last-wins / re-scan picks "evil".
	tags := []rpmTagEntry{
		{tag: rpmTagName, typ: rpmTypeString, str: "bash"},
		{tag: rpmTagVersion, typ: rpmTypeString, str: "5.1.8"},
		{tag: rpmTagName, typ: rpmTypeString, str: "evil"},
	}
	name, _, _, ok := parseRPMHeader(buildRPMHeader(t, true, tags))
	if !ok || name != "bash" {
		t.Errorf("read-once: name = %q ok=%v; want the first NAME (bash), not a later duplicate", name, ok)
	}
}

// TestCatalogHonorsCancellation: a cancelled context aborts the catalog rather than reading the rootfs.
func TestCatalogHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New().Catalog(ctx, t.TempDir()); err == nil {
		t.Error("a cancelled context must abort Catalog with an error")
	}
}

// TestCatalogRPMHostileViewTerminates guards the property behind the ctx watchdog: a crafted Packages VIEW –
// here a valid seed row followed by an unbounded recursive CTE of oversized rows the server-side LENGTH filter
// rejects – must never hang the scan. This modernc version happens to terminate the view on its own (it does
// not spin inside a single step), so the watchdog is a driver-independent backstop rather than load-bearing
// here; the test still locks "a hostile Packages view returns within its deadline, never an unbounded hang"
// (with a 2s ctx: if a future driver spins, the DB-close watchdog aborts it well under the outer guard). The
// outer guard makes a true hang fail the test instead of stalling the suite; either an error or a best-effort
// success is acceptable, only a hang is not.
func TestCatalogRPMHostileViewTerminates(t *testing.T) {
	rootfs := t.TempDir()
	dbPath := filepath.Join(rootfs, "var/lib/rpm/rpmdb.sqlite")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE seed(blob BLOB)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO seed(blob) VALUES(?)", bashHeader(t, 0)); err != nil {
		t.Fatal(err)
	}
	// zeroblob keeps LENGTH O(1) with no materialization, so a skip is a pure CPU spin (no OOM even on a
	// regression); 13MB > rpmMaxBlobLen (12MB) so every CTE row fails the filter.
	if _, err := db.Exec(`CREATE VIEW Packages AS SELECT blob FROM seed UNION ALL ` +
		`SELECT zeroblob(13000000) AS blob FROM (WITH RECURSIVE r(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM r) SELECT x FROM r)`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resCh := make(chan error, 1)
	go func() { _, e := New().Catalog(ctx, rootfs); resCh <- e }()
	select {
	case <-resCh: // returned (error or best-effort success) – the scan was not hung
	case <-time.After(30 * time.Second):
		t.Fatal("Catalog hung on a hostile Packages view: the ctx deadline did not bound the sqlite read")
	}
}

// TestCatalogRPMUnresolvedMajor: a clean-but-major-less VERSION_ID (".3") still emits the rpm components (for
// inventory) but flags DistroResolved=false, so the cataloger never claims resolved while osDistroEcosystem
// would map that release to nothing (the silent-zero-match guard the resolved flag exists to prevent).
func TestCatalogRPMUnresolvedMajor(t *testing.T) {
	rootfs := writeRPMRootfs(t, "ID=rocky\nVERSION_ID=\".3\"\n")
	res, err := New().Catalog(context.Background(), rootfs)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	if len(res.Components) != 1 {
		t.Fatalf("want the rpm component still emitted for inventory, got %d", len(res.Components))
	}
	if res.DistroResolved {
		t.Error("a VERSION_ID with an empty major must NOT be flagged resolved (osDistroEcosystem maps it to nothing)")
	}
}
