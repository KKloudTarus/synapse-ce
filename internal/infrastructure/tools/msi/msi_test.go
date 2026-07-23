package msi

import (
	"encoding/binary"
	"testing"
)

func TestDecodeStreamName(t *testing.T) {
	// Plain ASCII / literal names pass through unchanged (chars below the coded range).
	if got := decodeStreamName("cab1.cab"); got != "cab1.cab" {
		t.Errorf("literal name = %q, want cab1.cab", got)
	}
	// The \x05SummaryInformation stream: a \x05 prefix (literal, below the coded range) + literal name.
	if got := decodeStreamName("\x05SummaryInformation"); got != "\x05SummaryInformation" {
		t.Errorf("summary name = %q", got)
	}
	// A real MSI-mangled table name from a WiX installer: U+4840 (table sentinel) + coded pairs → "Property".
	mangled := string([]rune{0x4840, 0x4559, 0x44F2, 0x4568, 0x4737})
	if got := decodeStreamName(mangled); got != "Property" {
		t.Errorf("mangled Property = %q, want Property", got)
	}
	// "_Validation": U+4840 sentinel + U+3FFF ("_V") + ...
	val := string([]rune{0x4840, 0x3FFF, 0x43E4, 0x41EC, 0x45E4, 0x44AC, 0x4831})
	if got := decodeStreamName(val); got != "_Validation" {
		t.Errorf("mangled _Validation = %q, want _Validation", got)
	}
}

func TestLoadStringTable(t *testing.T) {
	// Two strings "GitHub CLI" (10) and "2.62.0" (6): pool = header + two length/refcount entries.
	data := []byte("GitHub CLI2.62.0")
	pool := make([]byte, 4) // header entry (codepage) — skipped
	pool = appendPoolEntry(pool, 10, 1)
	pool = appendPoolEntry(pool, 6, 1)
	strs, err := loadStringTable(pool, data)
	if err != nil {
		t.Fatal(err)
	}
	// Index 0 = empty, 1 = first string, 2 = second.
	if len(strs) != 3 || strs[0] != "" || strs[1] != "GitHub CLI" || strs[2] != "2.62.0" {
		t.Fatalf("strings = %#v", strs)
	}
}

func TestLoadStringTableOverrunIsError(t *testing.T) {
	pool := append(make([]byte, 4), appendPoolEntry(nil, 99, 1)...) // claims 99 bytes
	if _, err := loadStringTable(pool, []byte("short")); err == nil {
		t.Fatal("expected error when a string overruns _StringData")
	}
}

func TestParsePropertyTable(t *testing.T) {
	// strings: 1=ProductName 2=GitHub CLI 3=ProductVersion 4=2.62.0
	strs := []string{"", "ProductName", "GitHub CLI", "ProductVersion", "2.62.0"}
	// Column-major, 2-byte refs, 2 rows: [nameRefs...][valueRefs...]
	stream := make([]byte, 0, 8)
	stream = appendU16(stream, 1) // row0 name -> ProductName
	stream = appendU16(stream, 3) // row1 name -> ProductVersion
	stream = appendU16(stream, 2) // row0 value -> GitHub CLI
	stream = appendU16(stream, 4) // row1 value -> 2.62.0
	props := parsePropertyTable(stream, strs)
	if props["ProductName"] != "GitHub CLI" || props["ProductVersion"] != "2.62.0" {
		t.Fatalf("props = %#v", props)
	}
}

// TestParseSyntheticMSI builds a minimal-but-valid compound file (plain-ASCII stream names, which the
// demangler passes through unchanged) carrying the three MSI tables Parse needs, then round-trips it — this
// exercises the CFBF reader (header/FAT/directory/streams) end to end without shipping a real installer.
func TestParseSyntheticMSI(t *testing.T) {
	want := Info{ProductName: "Widget", ProductVersion: "3.1.4", Manufacturer: "Acme Corp"}
	data := buildTestMSI(t, []kv{
		{"ProductName", want.ProductName},
		{"ProductVersion", want.ProductVersion},
		{"Manufacturer", want.Manufacturer},
	})
	got, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got != want {
		t.Fatalf("Parse = %+v, want %+v", got, want)
	}
}

func TestParseRejectsNonMSI(t *testing.T) {
	if _, err := Parse([]byte("this is not a compound file")); err == nil {
		t.Fatal("expected error for non-CFBF input")
	}
}

// TestOpenCFBFRejectsHostileHeader covers the header-count / mini-sector-size guards that stop a tiny
// crafted file from forcing a multi-GiB allocation or an unbounded DIFAT loop (security-audit findings).
func TestOpenCFBFRejectsHostileHeader(t *testing.T) {
	base := func() []byte {
		b := make([]byte, 512)
		copy(b[0:8], cfbfSignature)
		binary.LittleEndian.PutUint16(b[26:28], 3)      // major
		binary.LittleEndian.PutUint16(b[28:30], 0xFFFE) // byte order
		binary.LittleEndian.PutUint16(b[30:32], 9)      // sector shift -> 512
		binary.LittleEndian.PutUint16(b[32:34], 6)      // mini sector shift -> 64
		return b
	}
	cases := map[string]func([]byte){
		"huge numFATSect":   func(b []byte) { binary.LittleEndian.PutUint32(b[44:48], 0x00200000) },
		"huge numDIFATSect": func(b []byte) { binary.LittleEndian.PutUint32(b[72:76], 0xFFFFFFFF) },
		"bad miniShift":     func(b []byte) { binary.LittleEndian.PutUint16(b[32:34], 63) },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			b := base()
			mut(b)
			if _, err := openCFBF(b); err == nil {
				t.Fatal("expected error for hostile header")
			}
		})
	}
}

// --- test helpers (byte encoders + a tiny CFBF/MSI writer) ---

type kv struct{ k, v string }

func appendU16(b []byte, v uint16) []byte { return binary.LittleEndian.AppendUint16(b, v) }

func appendPoolEntry(b []byte, size, refcount uint16) []byte {
	b = appendU16(b, size)
	return appendU16(b, refcount)
}

// buildTestMSI writes a 512-byte-sector compound file with mini-stream cutoff 0 (so every stream uses the
// regular FAT chain — no mini FAT needed) containing _StringData, _StringPool and Property.
func buildTestMSI(t *testing.T, props []kv) []byte {
	t.Helper()

	// Intern strings (index 0 = empty).
	index := map[string]int{"": 0}
	var order []string
	intern := func(s string) int {
		if i, ok := index[s]; ok {
			return i
		}
		i := len(order) + 1
		index[s] = i
		order = append(order, s)
		return i
	}
	type row struct{ nameRef, valRef int }
	var rows []row
	for _, p := range props {
		rows = append(rows, row{intern(p.k), intern(p.v)})
	}

	var strData []byte
	strPool := make([]byte, 4) // header entry (codepage) — skipped by the reader
	for _, s := range order {
		strData = append(strData, s...)
		strPool = appendPoolEntry(strPool, uint16(len(s)), 1)
	}

	propStream := make([]byte, 0, len(rows)*4)
	for _, r := range rows {
		propStream = appendU16(propStream, uint16(r.nameRef))
	}
	for _, r := range rows {
		propStream = appendU16(propStream, uint16(r.valRef))
	}

	streams := []struct {
		name string
		data []byte
	}{
		{"_StringData", strData},
		{"_StringPool", strPool},
		{"Property", propStream},
	}

	const sectorSize = 512
	nSect := func(n int) int {
		if n == 0 {
			return 0
		}
		return (n + sectorSize - 1) / sectorSize
	}

	// Sector layout: 0=FAT, 1=directory, 2.. = stream data.
	fat := make([]uint32, sectorSize/4) // one FAT sector = 128 entries
	for i := range fat {
		fat[i] = freeSect
	}
	fat[0] = fatSect
	fat[1] = endOfChain // directory is one sector

	type placed struct{ start uint32 }
	placedAt := make([]placed, len(streams))
	next := uint32(2)
	for i, s := range streams {
		ns := nSect(len(s.data))
		if ns == 0 {
			placedAt[i] = placed{endOfChain}
			continue
		}
		placedAt[i] = placed{next}
		for j := 0; j < ns; j++ {
			if j == ns-1 {
				fat[next] = endOfChain
			} else {
				fat[next] = next + 1
			}
			next++
		}
	}
	totalSectors := int(next)

	// Assemble the file: header (512) + each sector (512).
	buf := make([]byte, sectorSize*(1+totalSectors))

	// Header.
	copy(buf[0:8], cfbfSignature)
	binary.LittleEndian.PutUint16(buf[26:28], 3)      // major version (512-byte sectors)
	binary.LittleEndian.PutUint16(buf[28:30], 0xFFFE) // byte order
	binary.LittleEndian.PutUint16(buf[30:32], 9)      // sector shift -> 512
	binary.LittleEndian.PutUint16(buf[32:34], 6)      // mini sector shift -> 64
	binary.LittleEndian.PutUint32(buf[44:48], 1)      // number of FAT sectors
	binary.LittleEndian.PutUint32(buf[48:52], 1)      // first directory sector
	binary.LittleEndian.PutUint32(buf[56:60], 0)      // mini stream cutoff (0 -> all streams use the FAT)
	binary.LittleEndian.PutUint32(buf[60:64], endOfChain)
	binary.LittleEndian.PutUint32(buf[64:68], 0)          // number of mini FAT sectors
	binary.LittleEndian.PutUint32(buf[68:72], endOfChain) // first DIFAT sector
	binary.LittleEndian.PutUint32(buf[72:76], 0)          // number of DIFAT sectors
	binary.LittleEndian.PutUint32(buf[76:80], 0)          // DIFAT[0] -> FAT is at sector 0
	for i := 1; i < 109; i++ {
		binary.LittleEndian.PutUint32(buf[76+i*4:80+i*4], freeSect)
	}

	sectorOff := func(n int) int { return sectorSize * (n + 1) } // header precedes sector 0

	// Sector 0: FAT.
	for i, v := range fat {
		binary.LittleEndian.PutUint32(buf[sectorOff(0)+i*4:], v)
	}

	// Sector 1: directory (root + one entry per stream).
	writeDirEntry(buf[sectorOff(1):], 0, "Root Entry", objRootStore, endOfChain, 0)
	for i, s := range streams {
		writeDirEntry(buf[sectorOff(1)+(i+1)*dirEntryLen:], 0, s.name, objStream, placedAt[i].start, uint64(len(s.data)))
	}

	// Stream data sectors.
	for i, s := range streams {
		if placedAt[i].start == endOfChain {
			continue
		}
		copy(buf[sectorOff(int(placedAt[i].start)):], s.data)
	}
	return buf
}

func writeDirEntry(dst []byte, _ int, name string, objType byte, start uint32, size uint64) {
	// UTF-16LE name + trailing null; name length in bytes at [64:66].
	u := utf16Encode(name)
	for i, c := range u {
		binary.LittleEndian.PutUint16(dst[i*2:], c)
	}
	binary.LittleEndian.PutUint16(dst[64:66], uint16((len(u)+1)*2))
	dst[66] = objType
	binary.LittleEndian.PutUint32(dst[116:120], start)
	binary.LittleEndian.PutUint64(dst[120:128], size)
}

func utf16Encode(s string) []uint16 {
	var u []uint16
	for _, r := range s {
		u = append(u, uint16(r))
	}
	return u
}
