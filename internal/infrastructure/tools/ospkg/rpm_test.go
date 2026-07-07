package ospkg

import (
	"context"
	"database/sql"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
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
		buf = append(buf, rpmHeaderMagic...)
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
		"huge nindex":      append(append([]byte{}, rpmHeaderMagic...), 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0), // nindex 4B
		"data beyond blob": append(append([]byte{}, rpmHeaderMagic...), 0, 0, 0, 0, 0, 0, 0, 1, 0x7f, 0xff, 0xff, 0xff), // hsize huge
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

func TestCatalogRPMSqlite(t *testing.T) {
	rootfs := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootfs, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootfs, "etc/os-release"), []byte("ID=rocky\nVERSION_ID=\"9.3\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Build a real rpmdb.sqlite (Packages table, one header blob) with the same driver the cataloger uses.
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
