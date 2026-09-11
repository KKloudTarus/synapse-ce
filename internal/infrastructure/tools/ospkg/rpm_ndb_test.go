package ospkg

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ndbHeaderBlob builds a lead-less RPM header import blob (the shape an ndb "BlbS" blob body carries) with
// NAME/VERSION and an optional ARCH tag, reusing the package's buildRPMHeader encoder.
func ndbHeaderBlob(t *testing.T, name, version, arch string) []byte {
	t.Helper()
	tags := []rpmTagEntry{
		{tag: rpmTagName, typ: rpmTypeString, str: name},
		{tag: rpmTagVersion, typ: rpmTypeString, str: version},
	}
	if arch != "" {
		tags = append(tags, rpmTagEntry{tag: rpmTagArch, typ: rpmTypeString, str: arch})
	}
	return buildRPMHeader(t, false, tags) // false: ndb blobs carry no 8e-ad-e8-01 lead
}

// ndbEntry is one package to place in a synthetic ndb at an explicit slot index (so tests can craft
// duplicate-index, cross-page, and unparseable cases the trimmed real fixture cannot).
type ndbEntry struct {
	slotIndex   int
	pkgIdx, gen uint32
	header      []byte
}

// buildNDB writes a valid ndb file: a "RpmP" header, slotNPages fixed 4096-byte slot pages, then a contiguous
// blob area holding each entry's "BlbS"-headed header blob padded to a 16-byte block. Entries are placed at the
// caller's slot indices; every other slot stays zero (unused).
func buildNDB(slotNPages uint32, entries []ndbEntry) []byte {
	slots := make([]byte, int(slotNPages)*ndbSlotPageSize)
	copy(slots[0:4], "RpmP")
	binary.LittleEndian.PutUint32(slots[4:8], 0)  // version
	binary.LittleEndian.PutUint32(slots[8:12], 1) // generation
	binary.LittleEndian.PutUint32(slots[12:16], slotNPages)
	var blobs []byte
	cur := int64(len(slots)) // first blob byte, right after the slot pages
	for _, e := range entries {
		body := make([]byte, ndbBlobHeaderSize+len(e.header))
		copy(body[0:4], "BlbS")
		binary.LittleEndian.PutUint32(body[4:8], e.pkgIdx)
		binary.LittleEndian.PutUint32(body[8:12], e.gen)
		binary.LittleEndian.PutUint32(body[12:16], uint32(len(e.header)))
		copy(body[ndbBlobHeaderSize:], e.header)
		if pad := len(body) % ndbBlkSize; pad != 0 { // round the region up to a whole 16-byte block
			body = append(body, make([]byte, ndbBlkSize-pad)...)
		}
		off := e.slotIndex * ndbSlotSize
		copy(slots[off:off+4], "Slot")
		binary.LittleEndian.PutUint32(slots[off+4:off+8], e.pkgIdx)
		binary.LittleEndian.PutUint32(slots[off+8:off+12], uint32(cur/ndbBlkSize))
		binary.LittleEndian.PutUint32(slots[off+12:off+16], uint32(int64(len(body))/ndbBlkSize))
		blobs = append(blobs, body...)
		cur += int64(len(body))
	}
	return append(slots, blobs...)
}

// writeNDB writes content to a temp Packages.db and returns the path.
func writeNDB(t *testing.T, content []byte) string {
	t.Helper()
	db := filepath.Join(t.TempDir(), "Packages.db")
	if err := os.WriteFile(db, content, 0o644); err != nil {
		t.Fatal(err)
	}
	return db
}

// opensuseLeapNDBPackages is the authoritative name+version set of every RPM header blob in the committed
// openSUSE Leap 15.6 ndb fixture (a trimmed slice of a real /usr/lib/sysimage/rpm/Packages.db: the first six
// real package blobs, with the remaining slot entries zeroed). It was cross-derived by an independent Python
// decode of the same blobs, so a version-level misparse on ANY package fails the test.
var opensuseLeapNDBPackages = []string{
	"boost-license1_66_0 1.66.0-150200.12.7.1",
	"cracklib-dict-small 2.9.11-150600.1.90",
	"crypto-policies 20230920.570ea89-150600.3.16.1",
	"libldap-data 2.4.46-150600.25.3.1",
	"libsemanage-conf 3.5-150600.1.48",
	"openSUSE-release-appliance-docker 15.6-lp156.417.4.1",
}

const opensuseNDBFixture = "opensuse-leap-15.6.rpmdb.ndb.gz"

// newOpenSUSERootfs materializes a rootfs that mirrors a real openSUSE Leap image: the ndb pkgdb lives at
// /usr/lib/sysimage/rpm/Packages.db and /var/lib/rpm is a relative symlink to that dir. It writes the
// os-release so the distro resolves.
func newOpenSUSERootfs(t *testing.T) string {
	t.Helper()
	rootfs := t.TempDir()
	inflateInto(t, opensuseNDBFixture, filepath.Join(rootfs, rpmNDBSysimagePath))
	if err := os.MkdirAll(filepath.Join(rootfs, "var/lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../usr/lib/sysimage/rpm", filepath.Join(rootfs, "var/lib/rpm")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(rootfs, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootfs, "etc/os-release"), []byte("ID=\"opensuse-leap\"\nVERSION_ID=\"15.6\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return rootfs
}

// TestCatalogRPMNDBFixture is the mandatory real-fixture validation: a genuine openSUSE Leap 15.6 ndb rpmdb
// (reached through the /var/lib/rpm -> /usr/lib/sysimage/rpm symlink, no sqlite/BerkeleyDB) must be cataloged
// through the owned ndb parser and resolved to the openSUSE Leap ecosystem end to end.
func TestCatalogRPMNDBFixture(t *testing.T) {
	rootfs := newOpenSUSERootfs(t)

	res, err := New().Catalog(context.Background(), rootfs)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	if !res.DistroResolved { // opensuse-leap keys openSUSE:<major.minor>, served by the owned Leap OVAL feed
		t.Error("an openSUSE Leap ndb rpm DB must resolve its distro")
	}

	got := make([]string, 0, len(res.Components))
	byName := map[string]struct{ purl, loc string }{}
	for _, c := range res.Components {
		got = append(got, c.Name+" "+c.Version)
		byName[c.Name] = struct{ purl, loc string }{c.PURL, c.Location}
	}
	sort.Strings(got)
	want := append([]string(nil), opensuseLeapNDBPackages...)
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("extracted package set mismatch:\n got: %v\nwant: %v", got, want)
	}

	// The distro qualifier must be the exact opensuse-leap-15.6 key osDistroEcosystem maps to openSUSE:15.6.
	c, ok := byName["libldap-data"]
	if !ok {
		t.Fatal("libldap-data not cataloged")
	}
	if !strings.HasPrefix(c.purl, "pkg:rpm/opensuse-leap/libldap-data@") || !strings.Contains(c.purl, "distro=opensuse-leap-15.6") {
		t.Errorf("libldap-data PURL = %q; want an opensuse-leap-15.6 rpm PURL", c.purl)
	}
	if c.loc != filepath.Join(rootfs, rpmNDBPath) {
		t.Errorf("libldap-data Location = %q; want the probed ndb DB path", c.loc)
	}
}

// TestRPMNDBParseDirect exercises the parser directly on the inflated fixture, asserting the exact package set
// with arch, independent of the cataloger's distro resolution.
func TestRPMNDBParseDirect(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "Packages.db")
	inflateInto(t, opensuseNDBFixture, db)

	comps, err := rpmNDBComponents(context.Background(), db, "opensuse-leap", "opensuse-leap-15.6")
	if err != nil {
		t.Fatalf("rpmNDBComponents: %v", err)
	}
	if len(comps) != len(opensuseLeapNDBPackages) {
		t.Fatalf("got %d packages, want %d", len(comps), len(opensuseLeapNDBPackages))
	}
	// Arch spot-checks: one x86_64 and one noarch, so a mis-read arch tag is caught.
	arch := map[string]string{}
	for _, c := range comps {
		if i := strings.Index(c.PURL, "arch="); i >= 0 {
			arch[c.Name] = c.PURL[i+len("arch="):]
		}
	}
	if got := arch["openSUSE-release-appliance-docker"]; !strings.HasPrefix(got, "x86_64") {
		t.Errorf("openSUSE-release-appliance-docker arch = %q, want x86_64", got)
	}
	if got := arch["boost-license1_66_0"]; !strings.HasPrefix(got, "noarch") {
		t.Errorf("boost-license1_66_0 arch = %q, want noarch", got)
	}
}

// TestRPMNDBHardening proves a malformed/hostile ndb file degrades to no components without panicking (the
// recover guard) and never fabricates a package. Every case must return (nil, nil).
func TestRPMNDBHardening(t *testing.T) {
	valid := func() []byte {
		dir := t.TempDir()
		db := filepath.Join(dir, "v.db")
		inflateInto(t, opensuseNDBFixture, db)
		b, err := os.ReadFile(db)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}()

	// A valid header (magic + version + generation) but slotNPages claiming far more slot pages than the file
	// holds: the slot area runs past EOF, so the parser must bail rather than read out of bounds.
	pastEOF := append([]byte(nil), valid[:16]...)
	pastEOF[12], pastEOF[13], pastEOF[14], pastEOF[15] = 0xff, 0xff, 0x00, 0x00 // slotNPages = 0xffff

	cases := map[string][]byte{
		"empty":            {},
		"tooShort":         {'R', 'p', 'm'},
		"wrongMagic":       append([]byte("XXXX"), valid[4:64]...),
		"headerOnly":       valid[:16],
		"zeroSlotPages":    append(append([]byte(nil), valid[:12]...), 0, 0, 0, 0),
		"slotAreaPastEOF":  pastEOF,
		"truncatedMidSlot": valid[:40], // header + a partial slot page, no complete blob area
		"garbage":          []byte(strings.Repeat("\x01\x02\x03\x04", 4096)),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			db := filepath.Join(dir, "h.db")
			if err := os.WriteFile(db, content, 0o644); err != nil {
				t.Fatal(err)
			}
			comps, err := rpmNDBComponents(context.Background(), db, "opensuse-leap", "opensuse-leap-15.6")
			if err != nil {
				t.Errorf("%s: err = %v, want nil (only a cancel returns an error)", name, err)
			}
			if len(comps) != 0 {
				t.Errorf("%s: got %d components, want 0 (a malformed DB must never fabricate a package)", name, len(comps))
			}
		})
	}
}

// TestRPMNDBRegularFileGuard: a non-regular DB path (a directory) yields nothing, never a follow out of the
// rootfs.
func TestRPMNDBRegularFileGuard(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "Packages.db"), 0o755); err != nil {
		t.Fatal(err)
	}
	comps, err := rpmNDBComponents(context.Background(), filepath.Join(dir, "Packages.db"), "opensuse-leap", "opensuse-leap-15.6")
	if err != nil || len(comps) != 0 {
		t.Errorf("directory path: got (%d comps, %v), want (0, nil)", len(comps), err)
	}
}

// TestRPMNDBCancellation: a cancelled context surfaces as an error, never a silently-truncated success.
func TestRPMNDBCancellation(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "Packages.db")
	inflateInto(t, opensuseNDBFixture, db)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := rpmNDBComponents(ctx, db, "opensuse-leap", "opensuse-leap-15.6"); err == nil {
		t.Error("a cancelled context must return an error, not a truncated success")
	}
}

// TestRPMNDBGenerationDedup: two live slots share one package index (an internally-inconsistent DB); the
// higher-generation blob (the most recent write, what librpm reads) wins, in either slot order, and exactly one
// component is emitted.
func TestRPMNDBGenerationDedup(t *testing.T) {
	older := ndbHeaderBlob(t, "foo", "1.0-1", "x86_64")
	newer := ndbHeaderBlob(t, "foo", "2.0-1", "x86_64")
	for _, tc := range []struct {
		name    string
		entries []ndbEntry
	}{
		{"olderFirst", []ndbEntry{{2, 7, 1, older}, {3, 7, 2, newer}}},
		{"newerFirst", []ndbEntry{{2, 7, 2, newer}, {3, 7, 1, older}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := writeNDB(t, buildNDB(1, tc.entries))
			comps, err := rpmNDBComponents(context.Background(), db, "opensuse-leap", "opensuse-leap-15.6")
			if err != nil {
				t.Fatal(err)
			}
			if len(comps) != 1 {
				t.Fatalf("got %d components, want 1 (duplicate package index must collapse)", len(comps))
			}
			if comps[0].Version != "2.0-1" {
				t.Errorf("version = %q, want 2.0-1 (the higher generation)", comps[0].Version)
			}
		})
	}
}

// TestRPMNDBSkipsUnparseableBlobKeepsRest: a live slot whose BlbS header and package-index cross-check are
// valid but whose RPM header blob is unparseable (nindex=0) is skipped, and the remaining slots are still
// processed (a skip, never an abort). Guards the safe-coverage-gap direction.
func TestRPMNDBSkipsUnparseableBlobKeepsRest(t *testing.T) {
	bad := make([]byte, 8) // nindex=0, hsize=0: a non-empty blob that safeParseRPMHeader rejects
	entries := []ndbEntry{
		{2, 1, 1, ndbHeaderBlob(t, "good", "1.0-1", "noarch")},
		{3, 2, 1, bad},
		{4, 3, 1, ndbHeaderBlob(t, "other", "2.0-1", "x86_64")},
	}
	db := writeNDB(t, buildNDB(1, entries))
	comps, err := rpmNDBComponents(context.Background(), db, "opensuse-leap", "opensuse-leap-15.6")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, c := range comps {
		got[c.Name] = true
	}
	if len(comps) != 2 || !got["good"] || !got["other"] {
		t.Errorf("got %d components %v, want exactly good+other (the unparseable middle slot skipped, not aborting the rest)", len(comps), got)
	}
}

// TestRPMNDBMultiPageSlotDirectory: a two-slot-page directory with a live slot in the SECOND page (index >= 256)
// is iterated correctly, so a DB with more packages than one 4096-byte slot page holds loses none.
func TestRPMNDBMultiPageSlotDirectory(t *testing.T) {
	entries := []ndbEntry{
		{2, 1, 1, ndbHeaderBlob(t, "first", "1.0-1", "x86_64")},    // first page
		{300, 2, 1, ndbHeaderBlob(t, "second", "2.0-1", "noarch")}, // second page (index >= 256)
	}
	db := writeNDB(t, buildNDB(2, entries))
	comps, err := rpmNDBComponents(context.Background(), db, "opensuse-leap", "opensuse-leap-15.6")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, c := range comps {
		got[c.Name] = c.Version
	}
	if len(comps) != 2 || got["first"] != "1.0-1" || got["second"] != "2.0-1" {
		t.Errorf("got %v, want first@1.0-1 + second@2.0-1 across two slot pages", got)
	}
}

// TestCatalogOpenSUSEMalformedVersionUnresolved: a garbled openSUSE VERSION_ID that carries no minor must NOT
// mark the distro resolved, because osDistroEcosystem keys openSUSE on major.minor. Packages are still
// cataloged (inventory), but DistroResolved is false so the pipeline warns rather than presenting a clean
// posture keyed to an ecosystem the feed never wrote.
func TestCatalogOpenSUSEMalformedVersionUnresolved(t *testing.T) {
	for _, ver := range []string{"15", "15."} {
		t.Run("VERSION_ID="+ver, func(t *testing.T) {
			rootfs := t.TempDir()
			inflateInto(t, opensuseNDBFixture, filepath.Join(rootfs, rpmNDBPath))
			if err := os.MkdirAll(filepath.Join(rootfs, "etc"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(rootfs, "etc/os-release"), []byte("ID=\"opensuse-leap\"\nVERSION_ID=\""+ver+"\"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			res, err := New().Catalog(context.Background(), rootfs)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Components) == 0 {
				t.Fatal("packages must still be cataloged for inventory")
			}
			if res.DistroResolved {
				t.Errorf("VERSION_ID=%q must NOT resolve (openSUSE keys on major.minor; a bare major derives a key the feed never wrote)", ver)
			}
		})
	}
}

// TestCatalogRPMNDBBackendPrecedence: when a rootfs carries BOTH a populated sqlite rpmdb AND an ndb DB, only
// the sqlite backend is read (tried first), so the ndb packages are not double-counted.
func TestCatalogRPMNDBBackendPrecedence(t *testing.T) {
	rootfs := writeRPMRootfs(t, "ID=rhel\nVERSION_ID=\"9.4\"\n") // seeds var/lib/rpm/rpmdb.sqlite with a single bash
	inflateInto(t, opensuseNDBFixture, filepath.Join(rootfs, rpmNDBPath))

	res, err := New().Catalog(context.Background(), rootfs)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	if len(res.Components) != 1 {
		t.Fatalf("got %d components, want 1 (only the sqlite bash; ndb must not be read once sqlite wins)", len(res.Components))
	}
	if res.Components[0].Name != "bash" {
		t.Errorf("component = %q, want bash from the sqlite backend", res.Components[0].Name)
	}
}
