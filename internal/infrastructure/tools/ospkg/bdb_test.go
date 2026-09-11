package ospkg

import (
	"compress/gzip"
	"context"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// buildBDBHash assembles a minimal but on-disk-faithful BerkeleyDB HASH database (4KB pages) holding one
// key/value pair per blob, each value an H_OFFPAGE reference to an overflow-page chain carrying the blob. It
// writes every field in `order`, so the same builder exercises both the little- and big-endian read paths.
func buildBDBHash(t *testing.T, order binary.ByteOrder, blobs [][]byte) []byte {
	t.Helper()
	const ps = 4096
	dataPerPage := ps - bdbPageHdrLen

	meta := make([]byte, ps)
	order.PutUint32(meta[bdbMagicOff:], uint32(bdbHashMagic))
	order.PutUint32(meta[bdbPageSzOff:], ps)
	meta[25] = bdbTypeHashMeta
	order.PutUint32(meta[8:], 0) // self page number (page 0)

	hash := make([]byte, ps)
	hash[25] = bdbTypeHash
	order.PutUint32(hash[8:], 1)                     // self page number (page 1)
	order.PutUint16(hash[20:], uint16(len(blobs)*2)) // key/value pairs

	var overflow [][]byte
	startPgno := make([]uint32, len(blobs))
	nextPage := uint32(2) // pages 0 and 1 are the meta and hash pages
	for bi, blob := range blobs {
		startPgno[bi] = nextPage
		for off := 0; off < len(blob); off += dataPerPage {
			end := off + dataPerPage
			if end > len(blob) {
				end = len(blob)
			}
			chunk := blob[off:end]
			pg := make([]byte, ps)
			pg[25] = bdbTypeOverflow
			order.PutUint16(pg[22:], uint16(len(chunk))) // OV_LEN
			thisPgno := nextPage
			order.PutUint32(pg[8:], thisPgno) // self page number
			nextPage++
			if end < len(blob) {
				order.PutUint32(pg[16:], nextPage) // next_pgno
			}
			copy(pg[bdbPageHdrLen:], chunk)
			overflow = append(overflow, pg)
		}
	}

	entryOff := bdbPageHdrLen + len(blobs)*2*2 // entries start after the inp offset array
	for i, blob := range blobs {
		keyOff := entryOff
		hash[keyOff] = 1                              // H_KEYDATA
		order.PutUint32(hash[keyOff+1:], uint32(i+1)) // fake install number
		entryOff += 5

		valOff := entryOff
		hash[valOff] = bdbItemOffPage // H_OFFPAGE
		order.PutUint32(hash[valOff+4:], startPgno[i])
		order.PutUint32(hash[valOff+8:], uint32(len(blob)))
		entryOff += bdbOffPageEntryLen
		if entryOff > ps {
			t.Fatalf("too many blobs (%d) for one hash page", len(blobs))
		}

		order.PutUint16(hash[bdbPageHdrLen+(i*2)*2:], uint16(keyOff))
		order.PutUint16(hash[bdbPageHdrLen+(i*2+1)*2:], uint16(valOff))
	}

	buf := make([]byte, 0, ps*(2+len(overflow)))
	buf = append(buf, meta...)
	buf = append(buf, hash...)
	for _, pg := range overflow {
		buf = append(buf, pg...)
	}
	order.PutUint32(buf[bdbLastPgOff:], uint32(2+len(overflow)-1)) // last_pgno, in the meta page
	return buf
}

// buildBDBHashInline assembles a HASH database whose values are stored INLINE as H_KEYDATA items on the hash
// page (no overflow chain), the shape BerkeleyDB uses for an item below ~pagesize/4. pageSize is configurable so
// a large-page DB (where a multi-KB real header stays inline) can be exercised. Items are packed ascending from
// just after the inp array, and each value item's extent is bounded by the next item's offset, so the parser's
// inp-offset extent logic is what recovers the exact inline bytes (the last item relies on the page-end bound).
func buildBDBHashInline(t *testing.T, order binary.ByteOrder, pageSize int, blobs [][]byte) []byte {
	t.Helper()
	meta := make([]byte, pageSize)
	order.PutUint32(meta[bdbMagicOff:], uint32(bdbHashMagic))
	order.PutUint32(meta[bdbPageSzOff:], uint32(pageSize))
	meta[25] = bdbTypeHashMeta
	order.PutUint32(meta[8:], 0)
	order.PutUint32(meta[bdbLastPgOff:], 1) // pages 0 (meta) and 1 (hash)

	hash := make([]byte, pageSize)
	hash[25] = bdbTypeHash
	order.PutUint32(hash[8:], 1)
	order.PutUint16(hash[20:], uint16(len(blobs)*2))

	off := bdbPageHdrLen + len(blobs)*2*2 // items begin after the inp offset array
	for i, blob := range blobs {
		keyOff := off
		hash[keyOff] = bdbItemKeyData
		order.PutUint32(hash[keyOff+1:], uint32(i+1)) // fake install number
		off += 5

		valOff := off
		if valOff+1+len(blob) > pageSize {
			t.Fatalf("inline blob %d (%d bytes) does not fit in a %d-byte page", i, len(blob), pageSize)
		}
		hash[valOff] = bdbItemKeyData // inline value item
		copy(hash[valOff+1:], blob)
		off += 1 + len(blob)

		order.PutUint16(hash[bdbPageHdrLen+(i*2)*2:], uint16(keyOff))
		order.PutUint16(hash[bdbPageHdrLen+(i*2+1)*2:], uint16(valOff))
	}
	buf := make([]byte, 0, pageSize*2)
	buf = append(buf, meta...)
	buf = append(buf, hash...)
	return buf
}

// loadGz decompresses a committed .gz fixture into memory.
func loadGz(t *testing.T, gzName string) []byte {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", gzName))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = zr.Close() }()
	b, err := io.ReadAll(zr) //nolint:gosec // trusted committed test fixture
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestParseBDBInlineValue proves the inline (H_KEYDATA) value path: a real 6.4KB UBI8 `basesystem` header and a
// synthetic header stored INLINE on an 8KB-page hash page (BerkeleyDB stores an item below ~pagesize/4 inline,
// and page size is configurable up to 64KiB) must both be extracted, in both byte orders. Regression for the
// blocker where only H_OFFPAGE values were read, missing inline headers.
func TestParseBDBInlineValue(t *testing.T) {
	basesystem := loadGz(t, "rpmheader-basesystem.el8.bin.gz") // real UBI8 header blob (6400 bytes)
	synth := buildRPMHeader(t, true, []rpmTagEntry{
		{tag: rpmTagName, typ: rpmTypeString, str: "zlib"},
		{tag: rpmTagVersion, typ: rpmTypeString, str: "1.2.11"},
		{tag: rpmTagRelease, typ: rpmTypeString, str: "5.el8"},
	})
	for _, order := range []struct {
		name string
		bo   binary.ByteOrder
	}{{"little-endian", binary.LittleEndian}, {"big-endian", binary.BigEndian}} {
		t.Run(order.name, func(t *testing.T) {
			// basesystem first, so its extent is bounded exactly by the next item; synth last (page-end bound).
			db := buildBDBHashInline(t, order.bo, 8192, [][]byte{basesystem, synth})
			comps, err := rpmBDBComponents(context.Background(), writeBDB(t, db), "rhel", "rhel-8.10")
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			got := map[string]string{}
			for _, c := range comps {
				got[c.Name] = c.Version
			}
			if got["basesystem"] != "11-5.el8" {
				t.Errorf("inline real header: basesystem = %q; want 11-5.el8", got["basesystem"])
			}
			if got["zlib"] != "1.2.11-5.el8" {
				t.Errorf("inline synthetic header: zlib = %q; want 1.2.11-5.el8", got["zlib"])
			}
			if len(comps) != 2 {
				t.Errorf("want 2 inline components, got %d", len(comps))
			}
		})
	}
}

// TestParseBDBMalformedChain proves an overflow chain is accepted only when WELL-FORMED: it must land on exactly
// tlen, no page's OV_LEN may exceed the remaining need, and the page completing tlen must terminate the chain
// (next_pgno==0). A non-terminating, overshooting, or under-delivering chain yields NO package (never a
// truncated/fabricated blob). Regression for the blocker where the last chunk was truncated to fit and success
// returned as soon as len==tlen regardless of next_pgno.
func TestParseBDBMalformedChain(t *testing.T) {
	const ps = 4096
	const ovOff = 2 * ps // page 2 is the single overflow page for this small blob
	blob := buildRPMHeader(t, false, []rpmTagEntry{
		{tag: rpmTagName, typ: rpmTypeString, str: "ok"},
		{tag: rpmTagVersion, typ: rpmTypeString, str: "1"},
	})
	control := buildBDBHash(t, binary.LittleEndian, [][]byte{blob})

	nonZeroTerm := append([]byte(nil), control...)
	binary.LittleEndian.PutUint32(nonZeroTerm[ovOff+16:], 1) // next_pgno != 0 on the page that completes tlen

	overshoot := append([]byte(nil), control...)
	binary.LittleEndian.PutUint16(overshoot[ovOff+22:], uint16(len(blob)+1)) // OV_LEN exceeds the remaining need

	under := append([]byte(nil), control...)
	binary.LittleEndian.PutUint16(under[ovOff+22:], uint16(len(blob)-1)) // OV_LEN too small, chain ends short

	cases := []struct {
		name   string
		data   []byte
		wantOK bool
	}{
		{"well-formed control", control, true},
		{"non-zero terminator", nonZeroTerm, false},
		{"oversized OV_LEN", overshoot, false},
		{"under-delivered", under, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			comps, err := rpmBDBComponents(context.Background(), writeBDB(t, c.data), "rhel", "rhel-8.10")
			if err != nil {
				t.Errorf("must not error, got %v", err)
			}
			if extracted := len(comps) > 0; extracted != c.wantOK {
				t.Errorf("extracted=%v want=%v (comps=%d)", extracted, c.wantOK, len(comps))
			}
		})
	}
}

func writeBDB(t *testing.T, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "Packages")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestParseBDBSynthetic round-trips synthetic headers through the on-disk format in BOTH byte orders, and
// covers a header large enough to span several overflow pages (the chain-reassembly path).
func TestParseBDBSynthetic(t *testing.T) {
	for _, order := range []struct {
		name string
		bo   binary.ByteOrder
	}{{"little-endian", binary.LittleEndian}, {"big-endian", binary.BigEndian}} {
		t.Run(order.name, func(t *testing.T) {
			small := buildRPMHeader(t, false, []rpmTagEntry{
				{tag: rpmTagName, typ: rpmTypeString, str: "zlib"},
				{tag: rpmTagVersion, typ: rpmTypeString, str: "1.2.11"},
				{tag: rpmTagRelease, typ: rpmTypeString, str: "5.el8"},
				{tag: rpmTagArch, typ: rpmTypeString, str: "x86_64"},
			})
			// A header whose data store forces a multi-overflow-page chain (> one 4KB page).
			big := buildRPMHeader(t, true, []rpmTagEntry{
				{tag: rpmTagName, typ: rpmTypeString, str: "bigpkg"},
				{tag: rpmTagVersion, typ: rpmTypeString, str: "9.9.9"},
				{tag: rpmTagArch, typ: rpmTypeString, str: "noarch"},
				{tag: 4444, typ: rpmTypeString, str: strings.Repeat("A", 9000)}, // padding tag, not read
			})
			db := buildBDBHash(t, order.bo, [][]byte{small, big})
			comps, err := rpmBDBComponents(context.Background(), writeBDB(t, db), "rhel", "rhel-8.10")
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			got := map[string]string{}
			for _, c := range comps {
				got[c.Name] = c.Version
			}
			if got["zlib"] != "1.2.11-5.el8" {
				t.Errorf("zlib version = %q; want 1.2.11-5.el8", got["zlib"])
			}
			if got["bigpkg"] != "9.9.9" {
				t.Errorf("bigpkg (multi-page overflow) version = %q; want 9.9.9", got["bigpkg"])
			}
			if len(comps) != 2 {
				t.Errorf("want 2 components, got %d", len(comps))
			}
		})
	}
}

// decompressFixture inflates a committed .gz fixture into `rel` within a fresh temp rootfs and returns the
// rootfs dir. The raw BerkeleyDB fixture is 2.2MB; committed gzipped it is ~407KB.
func decompressFixture(t *testing.T, gzName, rel string) string {
	t.Helper()
	rootfs := t.TempDir()
	inflateInto(t, gzName, filepath.Join(rootfs, rel))
	return rootfs
}

// inflateInto decompresses a committed .gz fixture to an absolute destination path (creating parent dirs).
func inflateInto(t *testing.T, gzName, dst string) {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", gzName))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = zr.Close() }()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := os.Create(dst)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, zr); err != nil { //nolint:gosec // trusted committed test fixture
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

// ubi8MicroPackages is the authoritative name+version set of every RPM header blob in the committed UBI8-micro
// fixture (19 real packages plus the 2 gpg-pubkey pseudo-packages), regenerated with `syft dir:<fixture>`.
var ubi8MicroPackages = []string{
	"basesystem 11-5.el8",
	"bash 4.4.20-6.el8_10",
	"coreutils-single 8.30-20.el8_10",
	"filesystem 3.8-6.el8",
	"glibc 2.28-251.el8_10.40",
	"glibc-common 2.28-251.el8_10.40",
	"glibc-minimal-langpack 2.28-251.el8_10.40",
	"gpg-pubkey d4082792-5b32db75",
	"gpg-pubkey fd431d51-4ae0493b",
	"libacl 2.4.0-1.el8_10",
	"libattr 2.6.0-1.el8_10",
	"libcap 2.48-6.el8_10.1",
	"libgcc 8.5.0-28.el8_10",
	"libselinux 2.9-11.el8_10",
	"libsepol 2.9-3.el8",
	"ncurses-base 6.1-10.20180224.el8",
	"ncurses-libs 6.1-10.20180224.el8",
	"pcre2 10.32-3.el8_6",
	"redhat-release 8.10-0.3.el8",
	"setup 2.12.2-9.el8",
	"tzdata 2026c-1.el8_10",
}

// TestCatalogRPMBerkeleyDBFixture is the mandatory real-fixture validation: a genuine UBI8-micro BerkeleyDB
// rpmdb (var/lib/rpm/Packages, no sqlite) must be cataloged through the owned bdb parser. It asserts the
// representative real packages by exact name+version, the exact count of real packages, and that the two
// gpg-pubkey pseudo-packages parse too (they are real RPM headers, so the parser emits them exactly as the
// sqlite backend does; excluding them would need a special-case and would diverge from the sqlite path).
func TestCatalogRPMBerkeleyDBFixture(t *testing.T) {
	rootfs := decompressFixture(t, "ubi8-micro.rpmdb.bdb.gz", rpmBDBPath)
	if err := os.MkdirAll(filepath.Join(rootfs, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootfs, "etc/os-release"), []byte("ID=rhel\nVERSION_ID=\"8.10\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := New().Catalog(context.Background(), rootfs)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	if !res.DistroResolved { // rhel is a matchable rpm distro (Red Hat CSAF feed)
		t.Error("a RHEL BerkeleyDB rpm DB must resolve its distro")
	}

	// Full lock: the exact name+version set of all 21 header blobs (19 real + 2 gpg-pubkey), so a version-level
	// misparse on ANY package fails, not only the representative few. The 2 gpg-pubkey entries are real RPM
	// headers and parse exactly as the sqlite backend emits them; excluding them would need a special-case that
	// diverges from the sqlite path.
	got := make([]string, 0, len(res.Components))
	byName := map[string]sbom.Component{}
	for _, c := range res.Components {
		got = append(got, c.Name+" "+c.Version)
		byName[c.Name] = c
	}
	sort.Strings(got)
	want := append([]string(nil), ubi8MicroPackages...)
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("extracted package set mismatch:\n got: %v\nwant: %v", got, want)
	}

	// Metadata (Location, arch, distro-qualified PURL) on representative packages, including a multi-overflow-page
	// header (filesystem is 1.14MB) and a noarch package.
	for _, name := range []string{"bash", "filesystem", "setup"} {
		c := byName[name]
		if c.Location != filepath.Join(rootfs, rpmBDBPath) {
			t.Errorf("%s Location = %q; want the Packages DB path", name, c.Location)
		}
		if !strings.HasPrefix(c.PURL, "pkg:rpm/rhel/"+name+"@") || !strings.Contains(c.PURL, "distro=rhel-8.10") {
			t.Errorf("%s PURL = %q; want a rhel-8.10 rpm PURL", name, c.PURL)
		}
	}
}

// TestCatalogRPMBackendPrecedence: when a rootfs carries BOTH a populated sqlite rpmdb AND a BerkeleyDB
// Packages file, only the sqlite backend is read (it is tried first and wins), so the BerkeleyDB packages are
// not double-counted. writeRPMRootfs seeds the sqlite DB with a single bash 5.1.8-9.el9 header; the bdb fixture
// holds bash 4.4.20-6.el8_10 and 20 others, none of which may appear.
func TestCatalogRPMBackendPrecedence(t *testing.T) {
	rootfs := writeRPMRootfs(t, "ID=rhel\nVERSION_ID=\"9.4\"\n") // seeds var/lib/rpm/rpmdb.sqlite with bash 5.1.8-9.el9
	inflateInto(t, "ubi8-micro.rpmdb.bdb.gz", filepath.Join(rootfs, rpmBDBPath))

	res, err := New().Catalog(context.Background(), rootfs)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	if len(res.Components) != 1 {
		got := make([]string, 0, len(res.Components))
		for _, c := range res.Components {
			got = append(got, c.Name+" "+c.Version)
		}
		sort.Strings(got)
		t.Fatalf("sqlite must win over bdb (no double-count): got %d components %v; want just the sqlite bash", len(res.Components), got)
	}
	if c := res.Components[0]; c.Name != "bash" || c.Version != "5.1.8-9.el9" {
		t.Errorf("emitted component = %s %s; want the sqlite bash 5.1.8-9.el9 (not the bdb bash 4.4.20-6.el8_10)", c.Name, c.Version)
	}
}

// TestCatalogRPMBerkeleyDBArch checks the arch qualifier is carried through for a noarch and an x86_64 package.
func TestCatalogRPMBerkeleyDBArch(t *testing.T) {
	rootfs := decompressFixture(t, "ubi8-micro.rpmdb.bdb.gz", rpmBDBPath)
	res, err := New().Catalog(context.Background(), rootfs)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	arch := map[string]string{}
	for _, c := range res.Components {
		if strings.Contains(c.PURL, "arch=noarch") {
			arch[c.Name] = "noarch"
		} else if strings.Contains(c.PURL, "arch=x86_64") {
			arch[c.Name] = "x86_64"
		}
	}
	if arch["setup"] != "noarch" { // setup is noarch
		t.Errorf("setup arch qualifier = %q; want noarch", arch["setup"])
	}
	if arch["bash"] != "x86_64" { // bash is x86_64
		t.Errorf("bash arch qualifier = %q; want x86_64", arch["bash"])
	}
}

// TestParseBDBMalformed feeds hostile/garbled databases and asserts the parser never panics and degrades to no
// components (never a fabricated blob), with no error (an error is reserved for context cancellation).
func TestParseBDBMalformed(t *testing.T) {
	const ps = 4096
	// A valid single-package DB we then corrupt in specific ways.
	base := buildBDBHash(t, binary.LittleEndian, [][]byte{buildRPMHeader(t, false, []rpmTagEntry{
		{tag: rpmTagName, typ: rpmTypeString, str: "ok"},
		{tag: rpmTagVersion, typ: rpmTypeString, str: "1"},
	})})

	// tlen far beyond the per-blob cap.
	hugeTlen := append([]byte(nil), base...)
	// value entry sits right after the 2-entry inp array on the hash page (page 1). Its tlen is at valOff+8.
	valOff := bdbPageHdrLen + 1*2*2 + 5 // = 26 + 4 + 5 = 35
	binary.LittleEndian.PutUint32(hugeTlen[ps+valOff+8:], rpmMaxBlobLen+1)

	// Overflow chain that cycles (page 2 -> page 2) yet never delivers tlen: the step guard must terminate it.
	cyclic := append([]byte(nil), base...)
	binary.LittleEndian.PutUint32(cyclic[ps+valOff+8:], 1_000_000) // tlen the short cyclic chain cannot satisfy
	binary.LittleEndian.PutUint16(cyclic[2*ps+22:], 10)            // OV_LEN = 10 on the overflow page
	binary.LittleEndian.PutUint32(cyclic[2*ps+16:], 2)             // next_pgno -> itself

	// OFFPAGE pointing to a page beyond EOF.
	oob := append([]byte(nil), base...)
	binary.LittleEndian.PutUint32(oob[ps+valOff+4:], 9999) // overflow pgno past the file

	// last_pgno claims a huge page count the small file cannot back.
	lyingLast := append([]byte(nil), base...)
	binary.LittleEndian.PutUint32(lyingLast[bdbLastPgOff:], 0xffffffff)

	metaOnlyBadMagic := make([]byte, ps)
	metaOnlyBadMagic[25] = bdbTypeHashMeta // valid type, wrong (zero) magic

	oddEntries := append([]byte(nil), base...)
	binary.LittleEndian.PutUint16(oddEntries[ps+20:], 3) // odd entry count -> malformed page, skipped

	cases := map[string][]byte{
		"empty":            {},
		"tiny":             make([]byte, 100), // < min page size
		"bad magic":        metaOnlyBadMagic,
		"huge tlen":        hugeTlen,
		"cyclic overflow":  cyclic,
		"offpage past eof": oob,
		"lying last_pgno":  lyingLast,
		"odd entries":      oddEntries,
		"random garbage":   bytesRepeat(0xAB, ps*2),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			comps, err := rpmBDBComponents(context.Background(), writeBDB(t, data), "rhel", "rhel-8.10")
			if err != nil {
				t.Errorf("malformed input must not error, got %v", err)
			}
			if name == "lying last_pgno" {
				// Bounded by file size, this case still reads the one real page and may emit the valid "ok"
				// package; it must never emit more than that.
				if len(comps) > 1 {
					t.Errorf("case %q emitted %d components; want at most the one real package", name, len(comps))
				}
				return
			}
			// Every other corruption removes the one valid package: the parser must emit nothing (no panic, no
			// fabricated blob), a strictly stronger assertion than "no component named ok".
			if len(comps) != 0 {
				t.Errorf("case %q must emit no components, got %d: %+v", name, len(comps), comps)
			}
		})
	}
}

// TestParseBDBTruncatedFixture asserts graceful degradation on a partially-pulled image: truncating the real
// fixture at several points must never panic or error, and must yield only well-formed components (a package
// whose overflow chain is cut short fails the exact-length check and is dropped, never emitted as a fabricated
// or partial blob). The count is bounded by the full 21.
func TestParseBDBTruncatedFixture(t *testing.T) {
	rootfs := decompressFixture(t, "ubi8-micro.rpmdb.bdb.gz", rpmBDBPath)
	raw, err := os.ReadFile(filepath.Join(rootfs, rpmBDBPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, cut := range []int{60, 4096, 5000, 100_000, len(raw) - 1, len(raw)} {
		if cut < 0 || cut > len(raw) {
			continue
		}
		p := writeBDB(t, raw[:cut])
		comps, err := rpmBDBComponents(context.Background(), p, "rhel", "rhel-8.10")
		if err != nil {
			t.Errorf("cut=%d: must not error, got %v", cut, err)
		}
		if len(comps) > 21 {
			t.Errorf("cut=%d: emitted %d components, more than the full fixture's 21", cut, len(comps))
		}
		for _, c := range comps { // every emitted component must be well-formed, never a fabricated fragment
			if c.Name == "" || c.Version == "" {
				t.Errorf("cut=%d: emitted a malformed component %+v", cut, c)
			}
		}
	}
}

// TestParseBDBNonRegularFile asserts the regular-file guard: a directory (or absent path) at the DB location
// yields no components and no panic, never a symlink follow out of the rootfs.
func TestParseBDBNonRegularFile(t *testing.T) {
	dir := t.TempDir()
	comps, err := rpmBDBComponents(context.Background(), dir, "rhel", "rhel-8.10") // a directory, not a file
	if err != nil || comps != nil {
		t.Errorf("a directory DB path must yield (nil,nil), got comps=%d err=%v", len(comps), err)
	}
	comps, err = rpmBDBComponents(context.Background(), filepath.Join(dir, "absent"), "rhel", "rhel-8.10")
	if err != nil || comps != nil {
		t.Errorf("an absent DB path must yield (nil,nil), got comps=%d err=%v", len(comps), err)
	}
}

// TestParseBDBCancellation: a cancelled context on a real BerkeleyDB read surfaces as an error (so a timed-out
// read is a failure, never a silently-truncated success).
func TestParseBDBCancellation(t *testing.T) {
	rootfs := decompressFixture(t, "ubi8-micro.rpmdb.bdb.gz", rpmBDBPath)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := rpmBDBComponents(ctx, filepath.Join(rootfs, rpmBDBPath), "rhel", "rhel-8.10"); err == nil {
		t.Error("a cancelled context must abort the BerkeleyDB read with an error")
	}
}

// buildBDBAmplificationBomb crafts a hostile HASH database designed to force superlinear work: npages small
// (512-byte) pages, every hash page packed with valuesPerPage H_OFFPAGE value entries that all point at a
// single self-looping overflow page declaring a 12MB length it never delivers. Without an aggregate read
// budget this is O(npages * valuesPerPage * npages) page reads; with it, O(npages).
func buildBDBAmplificationBomb(t *testing.T, npages, valuesPerPage int) []byte {
	t.Helper()
	const ps = 512
	order := binary.LittleEndian
	buf := make([]byte, npages*ps)

	order.PutUint32(buf[bdbMagicOff:], uint32(bdbHashMagic))
	order.PutUint32(buf[bdbPageSzOff:], ps)
	buf[25] = bdbTypeHashMeta
	order.PutUint32(buf[bdbLastPgOff:], uint32(npages-1))

	// The last page is a valid overflow page whose next_pgno points at itself (a cycle).
	ov := (npages - 1) * ps
	buf[ov+25] = bdbTypeOverflow
	order.PutUint32(buf[ov+8:], uint32(npages-1))  // self page number
	order.PutUint16(buf[ov+22:], 1)                // OV_LEN = 1 byte per read
	order.PutUint32(buf[ov+16:], uint32(npages-1)) // next_pgno -> self

	entries := valuesPerPage * 2
	keyOff := ps - 20 // shared 1-byte HKEYDATA
	valOff := ps - 14 // shared 12-byte HOFFPAGE (fits within [valOff, valOff+12) < ps)
	if bdbPageHdrLen+entries*2 > keyOff {
		t.Fatalf("valuesPerPage %d too large for a %d-byte page", valuesPerPage, ps)
	}
	for p := 1; p <= npages-2; p++ {
		base := p * ps
		buf[base+25] = bdbTypeHash
		order.PutUint32(buf[base+8:], uint32(p)) // self page number
		order.PutUint16(buf[base+20:], uint16(entries))
		buf[base+keyOff] = 1              // H_KEYDATA
		buf[base+valOff] = bdbItemOffPage // H_OFFPAGE
		order.PutUint32(buf[base+valOff+4:], uint32(npages-1))
		order.PutUint32(buf[base+valOff+8:], rpmMaxBlobLen) // tlen the cyclic chain never satisfies
		for i := 0; i < entries; i++ {
			off := valOff
			if i%2 == 0 {
				off = keyOff
			}
			order.PutUint16(buf[base+bdbPageHdrLen+i*2:], uint16(off))
		}
	}
	return buf
}

// TestParseBDBAmplificationBombTerminates locks the aggregate overflow-read budget: a crafted DB with many
// value entries all referencing one self-looping overflow chain must terminate quickly and emit nothing,
// rather than doing O(pages^2) page reads (the DoS a broken chain would otherwise drive past the byte/package
// budgets, since a failed extraction never reaches them).
func TestParseBDBAmplificationBombTerminates(t *testing.T) {
	db := buildBDBAmplificationBomb(t, 4096, 100) // ~2MB file; unbudgeted this is ~1.6e9 reads
	p := writeBDB(t, db)
	type result struct {
		n   int
		err error
	}
	ch := make(chan result, 1)
	go func() {
		comps, err := rpmBDBComponents(context.Background(), p, "rhel", "rhel-8.10")
		ch <- result{len(comps), err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Errorf("unexpected error: %v", r.err)
		}
		if r.n != 0 {
			t.Errorf("hostile amplification bomb yielded %d components, want 0", r.n)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("rpmBDBComponents did not terminate on an overflow-amplification bomb within 30s: the aggregate read budget is not bounding the walk")
	}
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
