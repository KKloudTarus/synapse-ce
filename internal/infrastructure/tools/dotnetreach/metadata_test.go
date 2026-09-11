package dotnetreach

import (
	"encoding/binary"
	"testing"
)

// stringsHeap builds a #Strings heap (index 0 is the empty string) and returns it plus the offset of each
// added string.
func stringsHeap(items ...string) ([]byte, map[string]uint32) {
	heap := []byte{0}
	off := map[string]uint32{}
	for _, s := range items {
		off[s] = uint32(len(heap))
		heap = append(heap, []byte(s)...)
		heap = append(heap, 0)
	}
	return heap, off
}

// buildTablesStream builds a #~ stream with small-heap indexes (2 bytes) for the given present tables and
// row counts, appending the raw table bytes. present is a slice of {tableID, count}; rowBytes is the
// concatenated row data for the tables, in ascending table-id order.
func buildTablesStream(valid uint64, counts map[int]uint32, rowBytes []byte) []byte {
	b := make([]byte, 24)
	b[4] = 2 // major
	b[6] = 0 // HeapSizes: all small (2-byte indexes)
	b[7] = 1 // reserved
	binary.LittleEndian.PutUint64(b[8:], valid)
	for id := 0; id < 64; id++ {
		if valid&(uint64(1)<<uint(id)) == 0 {
			continue
		}
		var c [4]byte
		binary.LittleEndian.PutUint32(c[:], counts[id])
		b = append(b, c[:]...)
	}
	return append(b, rowBytes...)
}

// assembleMetadata wraps a #~ tables stream and a #Strings heap in an ECMA-335 metadata root.
func assembleMetadata(tables, strHeap []byte) []byte {
	version := []byte("v4.0.30319\x00\x00") // length 12 (multiple of 4)
	// Header up to stream headers.
	head := make([]byte, 16)
	binary.LittleEndian.PutUint32(head[0:], 0x424A5342) // BSJB
	binary.LittleEndian.PutUint32(head[12:], uint32(len(version)))
	head = append(head, version...)
	flags := make([]byte, 4)
	binary.LittleEndian.PutUint16(flags[2:], 2) // 2 streams
	head = append(head, flags...)

	// Two stream headers: "#~" (name padded to 4) then "#Strings" (name padded to 12).
	streamHdrLen := (4 + 4 + 4) + (4 + 4 + 12)
	tablesOff := uint32(len(head) + streamHdrLen)
	stringsOff := tablesOff + uint32(len(tables))

	hdr := make([]byte, 0, streamHdrLen)
	put := func(off, size uint32, name string, pad int) {
		var o, s [4]byte
		binary.LittleEndian.PutUint32(o[:], off)
		binary.LittleEndian.PutUint32(s[:], size)
		hdr = append(hdr, o[:]...)
		hdr = append(hdr, s[:]...)
		nb := make([]byte, pad)
		copy(nb, name)
		hdr = append(hdr, nb...)
	}
	put(tablesOff, uint32(len(tables)), "#~", 4)
	put(stringsOff, uint32(len(strHeap)), "#Strings", 12)

	md := append(head, hdr...)
	md = append(md, tables...)
	md = append(md, strHeap...)
	return md
}

func TestMetadataNamespacesExtractsTypeDefNamespaces(t *testing.T) {
	heap, off := stringsHeap("System.Text.Json", "Amazon.S3", "MyType", "Client")
	// One Module row (10 bytes: Generation u16 + Name str2 + 3*Guid2) all zero.
	moduleRow := make([]byte, 2+2+3*2)
	// Two TypeDef rows (14 bytes: Flags u32 + Name str2 + Namespace str2 + Extends 2 + Field 2 + Method 2).
	typeDef := func(nameOff, nsOff uint32) []byte {
		row := make([]byte, 14)
		binary.LittleEndian.PutUint16(row[4:], uint16(nameOff))
		binary.LittleEndian.PutUint16(row[6:], uint16(nsOff))
		return row
	}
	rowBytes := append([]byte{}, moduleRow...)
	rowBytes = append(rowBytes, typeDef(off["MyType"], off["System.Text.Json"])...)
	rowBytes = append(rowBytes, typeDef(off["Client"], off["Amazon.S3"])...)

	valid := uint64(1)<<0x00 | uint64(1)<<0x02 // Module + TypeDef
	tables := buildTablesStream(valid, map[int]uint32{0x00: 1, 0x02: 2}, rowBytes)
	md := assembleMetadata(tables, heap)

	got, complete, err := metadataNamespaces(md)
	if err != nil {
		t.Fatal(err)
	}
	if !complete {
		t.Fatal("no ExportedType rows, so the reading must be complete")
	}
	want := map[string]bool{"system.text.json": true, "amazon.s3": true}
	for _, ns := range got {
		delete(want, ns)
	}
	if len(want) != 0 {
		t.Errorf("missing namespaces %v; got %v", want, got)
	}
}

func TestMetadataNamespacesFailsClosedOnTypeForwarders(t *testing.T) {
	heap, _ := stringsHeap("Whatever")
	valid := uint64(1)<<0x00 | uint64(1)<<0x02 | uint64(1)<<0x27 // + ExportedType
	tables := buildTablesStream(valid, map[int]uint32{0x00: 1, 0x02: 0, 0x27: 3}, nil)
	md := assembleMetadata(tables, heap)

	_, complete, err := metadataNamespaces(md)
	if err != nil {
		t.Fatal(err)
	}
	if complete {
		t.Error("an ExportedType (type-forwarder) table with rows must make the reading incomplete")
	}
}

func TestExportedNamespacesRejectsNonPE(t *testing.T) {
	if _, _, err := ExportedNamespaces([]byte("this is not a PE file at all")); err == nil {
		t.Error("a non-PE input must error")
	}
}

// buildPE wraps CLI metadata in a minimal debug/pe-parseable PE32+ image: a .text section at RVA 0x2000
// holding a 72-byte CLI header (whose MetaData field points just past it) followed by the metadata, and a
// CLR-runtime data-directory (index 14) pointing at the CLI header.
func buildPE(metadata []byte) []byte {
	const (
		peOff     = 0x80
		optSize   = 240
		secVA     = 0x2000
		secRawPtr = 0x400
	)
	cli := make([]byte, 72)
	binary.LittleEndian.PutUint32(cli[0:], 72)                     // cb
	binary.LittleEndian.PutUint32(cli[8:], secVA+72)               // MetaData RVA (just past CLI header)
	binary.LittleEndian.PutUint32(cli[12:], uint32(len(metadata))) // MetaData size
	section := append(cli, metadata...)

	buf := make([]byte, secRawPtr+len(section))
	copy(buf[0:], "MZ")
	binary.LittleEndian.PutUint32(buf[0x3C:], peOff) // e_lfanew
	copy(buf[peOff:], "PE\x00\x00")

	coff := peOff + 4
	binary.LittleEndian.PutUint16(buf[coff:], 0x8664)     // Machine amd64
	binary.LittleEndian.PutUint16(buf[coff+2:], 1)        // NumberOfSections
	binary.LittleEndian.PutUint16(buf[coff+16:], optSize) // SizeOfOptionalHeader
	binary.LittleEndian.PutUint16(buf[coff+18:], 0x2022)  // Characteristics

	opt := coff + 20
	binary.LittleEndian.PutUint16(buf[opt:], 0x20b)           // PE32+ magic
	binary.LittleEndian.PutUint32(buf[opt+36:], 0x200)        // FileAlignment
	binary.LittleEndian.PutUint32(buf[opt+32:], 0x2000)       // SectionAlignment
	binary.LittleEndian.PutUint32(buf[opt+60:], secRawPtr)    // SizeOfHeaders
	binary.LittleEndian.PutUint32(buf[opt+56:], secVA+0x2000) // SizeOfImage
	binary.LittleEndian.PutUint32(buf[opt+108:], 16)          // NumberOfRvaAndSizes
	binary.LittleEndian.PutUint32(buf[opt+224:], secVA)       // DataDirectory[14].RVA (CLR runtime header)
	binary.LittleEndian.PutUint32(buf[opt+228:], 72)          // DataDirectory[14].Size

	sec := opt + optSize
	copy(buf[sec:], ".text")
	binary.LittleEndian.PutUint32(buf[sec+8:], uint32(len(section)))  // VirtualSize
	binary.LittleEndian.PutUint32(buf[sec+12:], secVA)                // VirtualAddress
	binary.LittleEndian.PutUint32(buf[sec+16:], uint32(len(section))) // SizeOfRawData
	binary.LittleEndian.PutUint32(buf[sec+20:], secRawPtr)            // PointerToRawData

	copy(buf[secRawPtr:], section)
	return buf
}

func TestExportedNamespacesEndToEndPE(t *testing.T) {
	heap, off := stringsHeap("Amazon.S3", "Client")
	moduleRow := make([]byte, 2+2+3*2)
	row := make([]byte, 14)
	binary.LittleEndian.PutUint16(row[4:], uint16(off["Client"]))
	binary.LittleEndian.PutUint16(row[6:], uint16(off["Amazon.S3"]))
	tables := buildTablesStream(uint64(1)<<0x00|uint64(1)<<0x02, map[int]uint32{0x00: 1, 0x02: 1}, append(moduleRow, row...))
	md := assembleMetadata(tables, heap)

	got, complete, err := ExportedNamespaces(buildPE(md))
	if err != nil {
		t.Fatal(err)
	}
	if !complete {
		t.Fatal("want complete")
	}
	if len(got) != 1 || got[0] != "amazon.s3" {
		t.Fatalf("want [amazon.s3], got %v", got)
	}
}

func TestMetadataNamespacesFailsClosedOnBadStringIndex(t *testing.T) {
	heap, _ := stringsHeap("Amazon.S3")
	moduleRow := make([]byte, 2+2+3*2)
	row := make([]byte, 14)
	binary.LittleEndian.PutUint16(row[4:], 1)     // Name -> valid
	binary.LittleEndian.PutUint16(row[6:], 60000) // Namespace -> far past the heap
	tables := buildTablesStream(uint64(1)<<0x00|uint64(1)<<0x02, map[int]uint32{0x00: 1, 0x02: 1}, append(moduleRow, row...))
	md := assembleMetadata(tables, heap)

	if _, _, err := metadataNamespaces(md); err == nil {
		t.Error("a TypeDef namespace index past the #Strings heap must fail closed, not drop the namespace")
	}
}

func TestMetadataNamespacesFailsClosedOnEditStream(t *testing.T) {
	// A metadata blob whose only tables stream is "#-" (uncompressed/edit) must report incomplete.
	heap, _ := stringsHeap("Amazon.S3")
	version := []byte("v4.0.30319\x00\x00")
	head := make([]byte, 16)
	binary.LittleEndian.PutUint32(head[0:], 0x424A5342)
	binary.LittleEndian.PutUint32(head[12:], uint32(len(version)))
	head = append(head, version...)
	flags := make([]byte, 4)
	binary.LittleEndian.PutUint16(flags[2:], 2)
	head = append(head, flags...)
	tables := buildTablesStream(uint64(1)<<0x00, map[int]uint32{0x00: 1}, make([]byte, 10))
	streamHdrLen := (4 + 4 + 4) + (4 + 4 + 12)
	tablesOff := uint32(len(head) + streamHdrLen)
	stringsOff := tablesOff + uint32(len(tables))
	hdr := make([]byte, 0)
	put := func(off, size uint32, name string, pad int) {
		var o, s [4]byte
		binary.LittleEndian.PutUint32(o[:], off)
		binary.LittleEndian.PutUint32(s[:], size)
		nb := make([]byte, pad)
		copy(nb, name)
		hdr = append(append(append(hdr, o[:]...), s[:]...), nb...)
	}
	put(tablesOff, uint32(len(tables)), "#-", 4)
	put(stringsOff, uint32(len(heap)), "#Strings", 12)
	md := append(append(append(head, hdr...), tables...), heap...)

	_, complete, err := metadataNamespaces(md)
	if err != nil {
		t.Fatal(err)
	}
	if complete {
		t.Error("#- (edit/uncompressed) metadata must be reported incomplete, never a partial namespace set")
	}
}

func TestMetadataNamespacesFailsClosedWhenEditStreamCoexistsWithTables(t *testing.T) {
	// A hostile metadata root carrying BOTH #~ and #- must fail closed, not trust the #~.
	heap, off := stringsHeap("Amazon.S3")
	moduleRow := make([]byte, 2+2+3*2)
	row := make([]byte, 14)
	binary.LittleEndian.PutUint16(row[6:], uint16(off["Amazon.S3"]))
	tables := buildTablesStream(uint64(1)<<0x00|uint64(1)<<0x02, map[int]uint32{0x00: 1, 0x02: 1}, append(moduleRow, row...))

	version := []byte("v4.0.30319\x00\x00")
	head := make([]byte, 16)
	binary.LittleEndian.PutUint32(head[0:], 0x424A5342)
	binary.LittleEndian.PutUint32(head[12:], uint32(len(version)))
	head = append(head, version...)
	flags := make([]byte, 4)
	binary.LittleEndian.PutUint16(flags[2:], 3) // 3 streams: #~, #-, #Strings
	head = append(head, flags...)
	streamHdrLen := (4 + 4 + 4) + (4 + 4 + 4) + (4 + 4 + 12)
	tildeOff := uint32(len(head) + streamHdrLen)
	dashOff := tildeOff + uint32(len(tables))
	stringsOff := dashOff // #- has zero payload here
	hdr := make([]byte, 0)
	put := func(off, size uint32, name string, pad int) {
		var o, s [4]byte
		binary.LittleEndian.PutUint32(o[:], off)
		binary.LittleEndian.PutUint32(s[:], size)
		nb := make([]byte, pad)
		copy(nb, name)
		hdr = append(append(append(hdr, o[:]...), s[:]...), nb...)
	}
	put(tildeOff, uint32(len(tables)), "#~", 4)
	put(dashOff, 0, "#-", 4)
	put(stringsOff, uint32(len(heap)), "#Strings", 12)
	md := append(append(append(head, hdr...), tables...), heap...)

	_, complete, err := metadataNamespaces(md)
	if err != nil {
		t.Fatal(err)
	}
	if complete {
		t.Error("metadata carrying both #~ and #- must fail closed")
	}
}

func TestMetadataNamespacesFailsClosedOnPublicGlobalType(t *testing.T) {
	heap, off := stringsHeap("Amazon.S3", "GlobalType")
	moduleRow := make([]byte, 2+2+3*2)
	// Row 0: a PUBLIC type in the GLOBAL namespace (namespace idx 0, Flags visibility Public=1).
	pubGlobal := make([]byte, 14)
	binary.LittleEndian.PutUint32(pubGlobal[0:], 0x1) // TypeAttributes.Public
	binary.LittleEndian.PutUint16(pubGlobal[4:], uint16(off["GlobalType"]))
	// Namespace idx stays 0 (global).
	tables := buildTablesStream(uint64(1)<<0x00|uint64(1)<<0x02, map[int]uint32{0x00: 1, 0x02: 1}, append(moduleRow, pubGlobal...))
	md := assembleMetadata(tables, heap)
	_ = off["Amazon.S3"]

	_, complete, err := metadataNamespaces(md)
	if err != nil {
		t.Fatal(err)
	}
	if complete {
		t.Error("a public global-namespace type is referenceable without a namespace, so the reading must be incomplete")
	}
}

func TestMetadataNamespacesIgnoresNonPublicGlobalType(t *testing.T) {
	heap, off := stringsHeap("Amazon.S3", "PrivateImpl")
	moduleTableRow := make([]byte, 2+2+3*2) // the Module TABLE row (not a TypeDef)
	// TypeDef row 0: a NON-public global-namespace type (like <Module>/<PrivateImplementationDetails>) must
	// be ignored, not fail closed.
	nonPublicGlobal := make([]byte, 14)
	binary.LittleEndian.PutUint32(nonPublicGlobal[0:], 0x0) // NotPublic
	binary.LittleEndian.PutUint16(nonPublicGlobal[4:], uint16(off["PrivateImpl"]))
	// TypeDef row 1: a public type in Amazon.S3.
	realType := make([]byte, 14)
	binary.LittleEndian.PutUint32(realType[0:], 0x1) // public
	binary.LittleEndian.PutUint16(realType[6:], uint16(off["Amazon.S3"]))
	rowBytes := append(append(moduleTableRow, nonPublicGlobal...), realType...)
	tables := buildTablesStream(uint64(1)<<0x00|uint64(1)<<0x02, map[int]uint32{0x00: 1, 0x02: 2}, rowBytes)
	md := assembleMetadata(tables, heap)

	got, complete, err := metadataNamespaces(md)
	if err != nil || !complete {
		t.Fatalf("a non-public global type must not fail closed; complete=%v err=%v", complete, err)
	}
	if len(got) != 1 || got[0] != "amazon.s3" {
		t.Errorf("want [amazon.s3]; got %v", got)
	}
}
