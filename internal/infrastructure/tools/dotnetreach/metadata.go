package dotnetreach

import (
	"bytes"
	"debug/pe"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// maxAssemblyBytes bounds an assembly we will read into memory (a hostile or corrupt .dll).
const maxAssemblyBytes = 96 << 20

// maxMetadataRows caps how many rows of any metadata table we iterate, so a corrupt count field cannot make
// the reader loop for a very long time.
const maxMetadataRows = 8 << 20

// ExportedNamespaces returns the set of namespaces a .NET assembly defines, read from its ECMA-335 metadata.
// complete is false when the assembly defines type forwarders (an ExportedType table with rows) whose
// targets this reader does not follow, so the caller must fail closed: a package whose namespaces are only
// partially known must never be concluded unreachable. It reads bytes only and never executes the assembly.
func ExportedNamespaces(assembly []byte) (namespaces []string, complete bool, err error) {
	if len(assembly) == 0 {
		return nil, false, fmt.Errorf("%w: empty assembly", shared.ErrValidation)
	}
	if len(assembly) > maxAssemblyBytes {
		return nil, false, fmt.Errorf("%w: assembly exceeds %d bytes", shared.ErrValidation, maxAssemblyBytes)
	}
	metadata, err := locateMetadata(assembly)
	if err != nil {
		return nil, false, err
	}
	return metadataNamespaces(metadata)
}

// locateMetadata walks the PE structure to the ECMA-335 metadata root: the CLR runtime header (data
// directory entry 14) gives the CLI header, whose MetaData RVA/size point at the metadata root. It returns
// the metadata bytes (from the root to the end of its section) so downstream offsets, which are relative to
// the root, index cleanly.
func locateMetadata(assembly []byte) ([]byte, error) {
	f, err := pe.NewFile(bytes.NewReader(assembly))
	if err != nil {
		return nil, fmt.Errorf("%w: not a PE image: %v", shared.ErrValidation, err)
	}
	defer func() { _ = f.Close() }()

	var clrRVA, clrSize uint32
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) <= 14 {
			return nil, fmt.Errorf("%w: PE has no CLR data directory", shared.ErrValidation)
		}
		clrRVA, clrSize = oh.DataDirectory[14].VirtualAddress, oh.DataDirectory[14].Size
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) <= 14 {
			return nil, fmt.Errorf("%w: PE has no CLR data directory", shared.ErrValidation)
		}
		clrRVA, clrSize = oh.DataDirectory[14].VirtualAddress, oh.DataDirectory[14].Size
	default:
		return nil, fmt.Errorf("%w: unknown PE optional header", shared.ErrValidation)
	}
	if clrRVA == 0 || clrSize < 72 {
		return nil, fmt.Errorf("%w: not a managed assembly (no CLI header)", shared.ErrValidation)
	}

	cliHeader, err := readRVA(assembly, f.Sections, clrRVA, 16)
	if err != nil {
		return nil, err
	}
	// CLI header (II.25.3.3): MetaData directory (RVA, size) is at offset 8.
	metaRVA, ok := le32(cliHeader, 8)
	if !ok {
		return nil, fmt.Errorf("%w: truncated CLI header", shared.ErrValidation)
	}
	metaSize, _ := le32(cliHeader, 12)
	if metaRVA == 0 {
		return nil, fmt.Errorf("%w: managed assembly has no metadata", shared.ErrValidation)
	}
	// Read from the metadata root to the end of its containing section so root-relative offsets resolve.
	metadata, err := readRVAToSectionEnd(assembly, f.Sections, metaRVA)
	if err != nil {
		return nil, err
	}
	if metaSize > 0 && uint32(len(metadata)) > metaSize {
		metadata = metadata[:metaSize]
	}
	return metadata, nil
}

// metadataNamespaces parses the metadata root (II.24.2.1), finds the #~ tables stream and #Strings heap, and
// returns the namespaces of every TypeDef. complete is false when the ExportedType table has rows, which are
// type forwarders this reader does not resolve.
func metadataNamespaces(md []byte) ([]string, bool, error) {
	if sig, ok := le32(md, 0); !ok || sig != 0x424A5342 { // "BSJB"
		return nil, false, fmt.Errorf("%w: bad metadata signature", shared.ErrValidation)
	}
	verLen, ok := le32(md, 12)
	if !ok || verLen > uint32(len(md)) {
		return nil, false, fmt.Errorf("%w: bad metadata version length", shared.ErrValidation)
	}
	// After the version string (padded to 4): Flags (u16), Streams (u16), then stream headers.
	pos := 16 + int(align4(verLen))
	streamsCount, ok := le16(md, pos+2)
	if !ok {
		return nil, false, fmt.Errorf("%w: truncated metadata header", shared.ErrValidation)
	}
	pos += 4

	var tablesOff, tablesSize, stringsOff, stringsSize uint32
	haveTables, haveStrings, haveEditTables := false, false, false
	for i := 0; i < int(streamsCount); i++ {
		off, ok1 := le32(md, pos)
		size, ok2 := le32(md, pos+4)
		if !ok1 || !ok2 {
			return nil, false, fmt.Errorf("%w: truncated stream header", shared.ErrValidation)
		}
		name, next, ok := streamName(md, pos+8)
		if !ok {
			return nil, false, fmt.Errorf("%w: truncated stream name", shared.ErrValidation)
		}
		switch name {
		case "#~":
			tablesOff, tablesSize, haveTables = off, size, true
		case "#-":
			// Uncompressed / edit-and-continue metadata uses pointer tables (FieldPtr, MethodPtr, ...) that
			// change how TypeDef's list columns are sized. This reader only understands the optimized #~
			// layout, so it must fail closed rather than mis-size rows and read the wrong namespaces.
			haveEditTables = true
		case "#Strings":
			stringsOff, stringsSize, haveStrings = off, size, true
		}
		pos = next
	}
	if haveEditTables {
		// #- (uncompressed / edit) metadata is unsupported. Fail closed whenever it is present at all, even
		// beside a #~ stream: no genuine assembly carries both, so a mix is hostile and must never be parsed
		// as if the #~ were authoritative.
		return nil, false, nil
	}
	if !haveTables || !haveStrings {
		return nil, false, fmt.Errorf("%w: assembly missing #~ or #Strings stream", shared.ErrValidation)
	}
	tables := boundedSlice(md, tablesOff, tablesSize)
	strHeap := boundedSlice(md, stringsOff, stringsSize)
	if tables == nil || strHeap == nil {
		return nil, false, fmt.Errorf("%w: stream bounds out of range", shared.ErrValidation)
	}
	return typeDefNamespaces(tables, strHeap)
}

// typeDefNamespaces parses the #~ tables-stream header (II.24.2.6), computes the row widths of the tables
// preceding TypeDef, and reads the Namespace string of every TypeDef row. It fails closed (complete=false)
// when the ExportedType table has rows.
func typeDefNamespaces(tables, strHeap []byte) ([]string, bool, error) {
	// #~ header: Reserved(u32), Major(u8), Minor(u8), HeapSizes(u8), Reserved(u8), Valid(u64), Sorted(u64).
	heapSizes, ok := readByte(tables, 6)
	if !ok {
		return nil, false, fmt.Errorf("%w: truncated tables header", shared.ErrValidation)
	}
	valid, ok := le64(tables, 8)
	if !ok {
		return nil, false, fmt.Errorf("%w: truncated tables header", shared.ErrValidation)
	}
	strIdx := 2
	if heapSizes&0x01 != 0 {
		strIdx = 4
	}
	guidIdx := 2
	if heapSizes&0x02 != 0 {
		guidIdx = 4
	}

	// Row counts: one u32 per present table (bit set in Valid), in ascending table-id order.
	rows := [64]uint32{}
	pos := 24
	for id := 0; id < 64; id++ {
		if valid&(uint64(1)<<uint(id)) == 0 {
			continue
		}
		count, ok := le32(tables, pos)
		if !ok {
			return nil, false, fmt.Errorf("%w: truncated row-count array", shared.ErrValidation)
		}
		if count > maxMetadataRows {
			return nil, false, fmt.Errorf("%w: implausible table row count", shared.ErrValidation)
		}
		rows[id] = count
		pos += 4
	}

	const (
		tblModule       = 0x00
		tblTypeRef      = 0x01
		tblTypeDef      = 0x02
		tblField        = 0x04
		tblMethodDef    = 0x06
		tblModuleRef    = 0x1A
		tblTypeSpec     = 0x1B
		tblAssemblyRef  = 0x23
		tblExportedType = 0x27
	)

	// A type forwarder (ExportedType row) means a namespace this assembly appears to provide is actually
	// defined elsewhere; we do not resolve those, so their presence makes the reading incomplete.
	if rows[tblExportedType] > 0 {
		return nil, false, nil
	}

	simpleIdx := func(table int) int {
		if rows[table] >= (1 << 16) {
			return 4
		}
		return 2
	}
	// Coded index (II.24.2.6): 2 bytes unless the largest referenced table needs more than 16-tagBits bits.
	codedIdx := func(tables []int, tagBits int) int {
		var max uint32
		for _, t := range tables {
			if rows[t] > max {
				max = rows[t]
			}
		}
		if uint64(max) >= (uint64(1) << uint(16-tagBits)) {
			return 4
		}
		return 2
	}
	resolutionScope := codedIdx([]int{tblModule, tblModuleRef, tblAssemblyRef, tblTypeRef}, 2)
	typeDefOrRef := codedIdx([]int{tblTypeDef, tblTypeRef, tblTypeSpec}, 2)

	moduleRow := 2 + strIdx + 3*guidIdx
	typeRefRow := resolutionScope + 2*strIdx
	// TypeDef: Flags(u32), Name(str), Namespace(str), Extends(TypeDefOrRef), FieldList(Field), MethodList(MethodDef).
	typeDefRow := 4 + strIdx + strIdx + typeDefOrRef + simpleIdx(tblField) + simpleIdx(tblMethodDef)

	// TypeDef starts after the Module and TypeRef tables (the only present tables with a lower id).
	start64 := int64(pos) + int64(rows[tblModule])*int64(moduleRow) + int64(rows[tblTypeRef])*int64(typeRefRow)
	if start64 > int64(len(tables)) {
		return nil, false, fmt.Errorf("%w: TypeDef table offset out of range", shared.ErrValidation)
	}
	start := int(start64)
	nsOffsetInRow := 4 + strIdx // Flags then Name precede Namespace

	set := map[string]bool{}
	for r := uint32(0); r < rows[tblTypeDef]; r++ {
		rowStart := int64(start) + int64(r)*int64(typeDefRow)
		if rowStart+int64(nsOffsetInRow) > int64(len(tables)) {
			return nil, false, fmt.Errorf("%w: TypeDef row out of range", shared.ErrValidation)
		}
		flags, ok := le32(tables, int(rowStart)) // TypeAttributes: bits 0-2 are the visibility mask
		if !ok {
			return nil, false, fmt.Errorf("%w: TypeDef row out of range", shared.ErrValidation)
		}
		idx, ok := heapIndex(tables, int(rowStart)+nsOffsetInRow, strIdx)
		if !ok {
			return nil, false, fmt.Errorf("%w: TypeDef row out of range", shared.ErrValidation)
		}
		if idx == 0 {
			// A type in the GLOBAL namespace. If it is PUBLIC it can be referenced with no namespace at all,
			// so namespace matching cannot prove the package unreferenced: fail closed. Non-public
			// global types (the `<Module>` pseudo-type, `<PrivateImplementationDetails>`, compiler helpers)
			// are not part of the consumable API and are ignored.
			if flags&0x7 == 0x1 { // TypeAttributes.Public (top-level)
				return nil, false, nil
			}
			continue
		}
		ns, ok := heapString(strHeap, idx)
		if !ok {
			// A nonzero namespace index that does not resolve means we would silently drop a namespace this
			// type provides; fail closed rather than return a partial set.
			return nil, false, fmt.Errorf("%w: TypeDef namespace string out of range", shared.ErrValidation)
		}
		if ns != "" {
			set[strings.ToLower(ns)] = true
		}
	}
	out := make([]string, 0, len(set))
	for ns := range set {
		out = append(out, ns)
	}
	sort.Strings(out)
	return out, true, nil
}

// --- bounded byte-reading helpers ---

func le16(b []byte, off int) (uint16, bool) {
	if off < 0 || off+2 > len(b) {
		return 0, false
	}
	return uint16(b[off]) | uint16(b[off+1])<<8, true
}

func le32(b []byte, off int) (uint32, bool) {
	if off < 0 || off+4 > len(b) {
		return 0, false
	}
	return uint32(b[off]) | uint32(b[off+1])<<8 | uint32(b[off+2])<<16 | uint32(b[off+3])<<24, true
}

func le64(b []byte, off int) (uint64, bool) {
	lo, ok1 := le32(b, off)
	hi, ok2 := le32(b, off+4)
	if !ok1 || !ok2 {
		return 0, false
	}
	return uint64(lo) | uint64(hi)<<32, true
}

func readByte(b []byte, off int) (byte, bool) {
	if off < 0 || off >= len(b) {
		return 0, false
	}
	return b[off], true
}

// heapIndex reads a 2- or 4-byte heap index.
func heapIndex(b []byte, off, size int) (uint32, bool) {
	if size == 4 {
		return le32(b, off)
	}
	v, ok := le16(b, off)
	return uint32(v), ok
}

// heapString reads a null-terminated UTF-8 string at idx in the #Strings heap.
func heapString(heap []byte, idx uint32) (string, bool) {
	if int(idx) >= len(heap) {
		return "", false
	}
	rest := heap[idx:]
	end := bytes.IndexByte(rest, 0)
	if end < 0 {
		return "", false
	}
	return string(rest[:end]), true
}

// streamName reads a null-terminated stream name padded to the next 4-byte boundary and returns the position
// after it.
func streamName(md []byte, off int) (string, int, bool) {
	if off < 0 || off > len(md) {
		return "", 0, false
	}
	rest := md[off:]
	end := bytes.IndexByte(rest, 0)
	if end < 0 {
		return "", 0, false
	}
	name := string(rest[:end])
	consumed := align4(uint32(end + 1))
	return name, off + int(consumed), true
}

// boundedSlice returns exactly md[off:off+size], or nil when that range is out of bounds. It validates
// rather than clamps (a clamped-to-end slice would silently accept a malformed stream size), computing in
// int64 so off+size cannot overflow.
func boundedSlice(md []byte, off, size uint32) []byte {
	o, s := int64(off), int64(size)
	end := o + s
	if end > int64(len(md)) {
		return nil
	}
	return md[o:end]
}

func align4(n uint32) uint32 { return (n + 3) &^ 3 }

// readRVA maps a virtual address to file bytes and returns at least n bytes starting there.
func readRVA(assembly []byte, sections []*pe.Section, rva, n uint32) ([]byte, error) {
	b, err := readRVAToSectionEnd(assembly, sections, rva)
	if err != nil {
		return nil, err
	}
	if uint32(len(b)) < n {
		return nil, fmt.Errorf("%w: RVA region too small", shared.ErrValidation)
	}
	return b, nil
}

// readRVAToSectionEnd returns the file bytes from rva to the end of its containing section's raw data. All
// arithmetic is in int64 so crafted section values cannot wrap and map the wrong bytes.
func readRVAToSectionEnd(assembly []byte, sections []*pe.Section, rva uint32) ([]byte, error) {
	r := int64(rva)
	for _, s := range sections {
		va := int64(s.VirtualAddress)
		if r < va || r >= va+int64(s.VirtualSize) {
			continue
		}
		delta := r - va
		if delta >= int64(s.Size) { // beyond the raw (on-disk) data of the section
			return nil, fmt.Errorf("%w: RVA past section raw data", shared.ErrValidation)
		}
		fileStart := int64(s.Offset) + delta
		fileEnd := int64(s.Offset) + int64(s.Size)
		if fileStart > fileEnd || fileEnd > int64(len(assembly)) {
			return nil, fmt.Errorf("%w: section bounds out of range", shared.ErrValidation)
		}
		return assembly[fileStart:fileEnd], nil
	}
	return nil, fmt.Errorf("%w: RVA not in any section", shared.ErrValidation)
}
