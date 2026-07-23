package msi

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// Info is the identity recovered from an MSI's Property table (the authoritative source). Fields are empty
// when the installer does not set the corresponding property.
type Info struct {
	ProductName    string
	ProductVersion string
	Manufacturer   string
	ProductCode    string // {GUID}
	UpgradeCode    string // {GUID}
}

// mangleAlphabet is the 64-symbol set MSI uses to encode table/stream names into the compound-file
// directory (each directory name is otherwise limited to a small set of chars).
const mangleAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._"

// maxStrings caps the interned string-table size (a 3-byte string ref addresses at most 16M strings; this
// ceiling is well above any real MSI yet bounds a zero-length-entry amplification attack).
const maxStrings = 4_000_000

// Parse reads an MSI (.msi) file and returns the product Info from its Property table. It never resolves or
// executes anything — it only decodes the compound-file bytes. A non-MSI / corrupt input returns an error.
func Parse(data []byte) (Info, error) {
	c, err := openCFBF(data)
	if err != nil {
		return Info{}, fmt.Errorf("msi: open compound file: %w", err)
	}

	// Resolve the MSI table streams by their DECODED (demangled) names.
	var strData, strPool, prop []byte
	for i := range c.dir {
		e := c.dir[i]
		if e.objType != objStream {
			continue
		}
		switch decodeStreamName(e.name) {
		case "_StringData":
			if strData, err = c.stream(e); err != nil {
				return Info{}, fmt.Errorf("read _StringData: %w", err)
			}
		case "_StringPool":
			if strPool, err = c.stream(e); err != nil {
				return Info{}, fmt.Errorf("read _StringPool: %w", err)
			}
		case "Property":
			if prop, err = c.stream(e); err != nil {
				return Info{}, fmt.Errorf("read Property: %w", err)
			}
		}
	}
	if strPool == nil || strData == nil {
		return Info{}, fmt.Errorf("msi: string table not found (not a valid MSI database)")
	}
	if prop == nil {
		return Info{}, fmt.Errorf("msi: Property table not found")
	}

	strings, err := loadStringTable(strPool, strData)
	if err != nil {
		return Info{}, err
	}
	props := parsePropertyTable(prop, strings)

	return Info{
		ProductName:    props["ProductName"],
		ProductVersion: props["ProductVersion"],
		Manufacturer:   props["Manufacturer"],
		ProductCode:    props["ProductCode"],
		UpgradeCode:    props["UpgradeCode"],
	}, nil
}

// decodeStreamName demangles an MSI compound-file stream/table name (MS-CFB names are limited, so MSI packs
// table names using mangleAlphabet). Characters outside the coded range (e.g. the \x05SummaryInformation
// prefix, or already-literal names) pass through unchanged.
func decodeStreamName(in string) string {
	var out []rune
	for _, ch := range in {
		switch {
		case ch == 0x4840: // "this is a table" sentinel prefix — carries no character
			continue
		case ch >= 0x3800 && ch < 0x4800: // two packed symbols
			ch -= 0x3800
			out = append(out, rune(mangleAlphabet[ch&0x3f]))
			out = append(out, rune(mangleAlphabet[(ch>>6)&0x3f]))
		case ch >= 0x4800 && ch < 0x4840: // one packed symbol
			out = append(out, rune(mangleAlphabet[(ch-0x4800)&0x3f]))
		default:
			out = append(out, ch)
		}
	}
	return string(out)
}

// loadStringTable rebuilds the interned string table from _StringPool (per-string length+refcount entries)
// and _StringData (the concatenated string bytes). String index 0 is the empty string; index i (1-based)
// is the i-th string. A zero-size entry with a non-zero refcount is a >64 KiB "long string" spanning two
// pool entries. All slices are bounds-checked (a corrupt pool/data yields an error, never a panic).
func loadStringTable(pool, data []byte) ([]string, error) {
	strs := []string{""} // index 0 = empty
	offset := 0
	// The first 4-byte pool entry is a header (codepage); real strings start at the second entry.
	for pos := 4; pos+4 <= len(pool); pos += 4 {
		if len(strs) > maxStrings { // cap the interned-string count (defends against a zero-length-entry flood)
			return nil, fmt.Errorf("msi: string table exceeds %d entries", maxStrings)
		}
		size := int(binary.LittleEndian.Uint16(pool[pos : pos+2]))
		refcount := binary.LittleEndian.Uint16(pool[pos+2 : pos+4])
		length := size
		if size == 0 && refcount != 0 {
			// long string: total length = (refcount << 16) | (next entry's size field)
			pos += 4
			if pos+4 > len(pool) {
				break
			}
			low := int(binary.LittleEndian.Uint16(pool[pos : pos+2]))
			length = int(refcount)<<16 | low
		}
		if length < 0 || offset+length > len(data) {
			return nil, fmt.Errorf("msi: string table overruns _StringData (offset %d + %d > %d)", offset, length, len(data))
		}
		strs = append(strs, string(data[offset:offset+length]))
		offset += length
	}
	return strs, nil
}

// parsePropertyTable decodes the MSI Property table stream into a name→value map. The table has two string
// columns (Property, Value); MSI stores rows COLUMN-major, each cell a 2-byte (or 3-byte, when the pool has
// >0xFFFF strings) index into the string table. Out-of-range indices are skipped defensively.
func parsePropertyTable(stream []byte, strs []string) map[string]string {
	refSize := 2
	if len(strs) > 0xFFFF {
		refSize = 3
	}
	rowBytes := 2 * refSize
	if rowBytes == 0 || len(stream) < rowBytes {
		return map[string]string{}
	}
	rows := len(stream) / rowBytes
	ref := func(base, row int) int {
		off := base + row*refSize
		if off+refSize > len(stream) {
			return 0
		}
		if refSize == 3 {
			return int(stream[off]) | int(stream[off+1])<<8 | int(stream[off+2])<<16
		}
		return int(binary.LittleEndian.Uint16(stream[off : off+2]))
	}
	get := func(i int) string {
		if i >= 0 && i < len(strs) {
			return strs[i]
		}
		return ""
	}
	out := make(map[string]string, rows)
	valBase := rows * refSize // column-major: all Property refs, then all Value refs
	for r := 0; r < rows; r++ {
		name := get(ref(0, r))
		if name == "" {
			continue
		}
		out[name] = get(ref(valBase, r))
	}
	return out
}

// utf16Decode converts a UTF-16 code-unit sequence (BMP + surrogate pairs) to runes.
func utf16Decode(u []uint16) []rune { return utf16.Decode(u) }
