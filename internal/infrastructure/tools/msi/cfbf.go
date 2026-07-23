// Package msi parses a Windows Installer (.msi) file — a pure-Go, dependency-free reader for the OLE2
// Compound File Binary Format (MS-CFB) container plus the MSI table layout on top of it — to recover the
// installed product's identity (name, version, manufacturer, product code) for cataloging. It resolves no
// external resources and never executes the installer; it only reads bytes, with hard bounds throughout so
// a crafted/corrupt file degrades to an error rather than exhausting memory or looping.
package msi

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Bounds (defense-in-depth against a hostile/corrupt compound file).
const (
	maxSectors    = 1 << 22 // 4M sectors (≥16 GiB at 4 KiB) — a sane ceiling for a scanned artifact
	maxDirEntries = 1 << 20 // directory-entry cap
	maxStreamSize = 64 << 20 // per-stream read cap (a real MSI table stream is far smaller)
)

const (
	dirEntryLen  = 128
	freeSect     = 0xFFFFFFFF
	endOfChain   = 0xFFFFFFFE
	fatSect      = 0xFFFFFFFD
	objStream    = 2
	objRootStore = 5
)

var cfbfSignature = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}

// dirEntry is one compound-file directory entry (a storage, stream, or the root).
type dirEntry struct {
	name       string // decoded UTF-16 name (MSI-mangled for MSI tables; decoded separately)
	objType    byte
	startSect  uint32
	size       uint64
}

// cfbf is a parsed compound file with random access to its streams by directory index.
type cfbf struct {
	data       []byte
	sectorSize int
	miniShift  uint
	miniSize   int
	miniCutoff uint32
	fat        []uint32
	miniFAT    []uint32
	dir        []dirEntry
	miniStream []byte // the root entry's stream (container of mini-sectors)
}

// openCFBF parses the compound-file structure (header, FAT/DIFAT, directory, mini FAT + mini stream).
func openCFBF(data []byte) (*cfbf, error) {
	if len(data) < 512 || !hasPrefix(data, cfbfSignature) {
		return nil, errors.New("not an OLE2 compound file (bad signature)")
	}
	major := binary.LittleEndian.Uint16(data[26:28])
	if binary.LittleEndian.Uint16(data[28:30]) != 0xFFFE {
		return nil, errors.New("cfbf: unexpected byte order")
	}
	sectorShift := binary.LittleEndian.Uint16(data[30:32])
	sectorSize := 1 << sectorShift
	if (major == 3 && sectorSize != 512) || (major == 4 && sectorSize != 4096) || (sectorSize != 512 && sectorSize != 4096) {
		return nil, fmt.Errorf("cfbf: bad sector size %d for major %d", sectorSize, major)
	}
	c := &cfbf{
		data:       data,
		sectorSize: sectorSize,
		miniShift:  uint(binary.LittleEndian.Uint16(data[32:34])),
		miniCutoff: binary.LittleEndian.Uint32(data[56:60]),
	}
	c.miniSize = 1 << c.miniShift
	if c.miniSize != 64 { // MS-CFB fixes the mini-sector shift at 6 (64-byte mini sectors)
		return nil, fmt.Errorf("cfbf: unexpected mini sector size %d", c.miniSize)
	}

	numFATSect := binary.LittleEndian.Uint32(data[44:48])
	firstDirSect := binary.LittleEndian.Uint32(data[48:52])
	firstMiniFATSect := binary.LittleEndian.Uint32(data[60:64])
	numMiniFATSect := binary.LittleEndian.Uint32(data[64:68])
	firstDIFATSect := binary.LittleEndian.Uint32(data[68:72])
	numDIFATSect := binary.LittleEndian.Uint32(data[72:76])
	// Header-declared sector counts are attacker-controlled; cap them before they drive any allocation or
	// loop bound (a crafted count could otherwise force a multi-GiB make / billions of iterations).
	if numFATSect > maxSectors || numDIFATSect > maxSectors || numMiniFATSect > maxSectors {
		return nil, fmt.Errorf("cfbf: sector count exceeds cap (fat=%d difat=%d minifat=%d)", numFATSect, numDIFATSect, numMiniFATSect)
	}

	// DIFAT: 109 entries in the header, then chained DIFAT sectors (last u32 of each is the next).
	difat := make([]uint32, 0, 109)
	for i := 0; i < 109; i++ {
		difat = append(difat, binary.LittleEndian.Uint32(data[76+i*4:80+i*4]))
	}
	sect := firstDIFATSect
	for n, seen := uint32(0), 0; n < numDIFATSect && sect != endOfChain && sect != freeSect; n++ {
		if seen++; seen > maxSectors {
			return nil, errors.New("cfbf: DIFAT chain too long / cyclic")
		}
		buf, err := c.readSector(sect)
		if err != nil {
			return nil, err
		}
		perSect := sectorSize/4 - 1
		for i := 0; i < perSect; i++ {
			difat = append(difat, binary.LittleEndian.Uint32(buf[i*4:i*4+4]))
		}
		if len(difat) > maxSectors { // total FAT-sector pointers cannot exceed the sector cap
			return nil, errors.New("cfbf: DIFAT too large")
		}
		sect = binary.LittleEndian.Uint32(buf[perSect*4:])
	}

	// FAT: concatenate the FAT sectors listed in the DIFAT. No capacity hint from the (untrusted) header —
	// growth is bounded by readSector failing past EOF and by the DIFAT cap above.
	c.fat = make([]uint32, 0)
	for i, fs := 0, 0; i < len(difat) && fs < int(numFATSect); i++ {
		if difat[i] == freeSect {
			continue
		}
		buf, err := c.readSector(difat[i])
		if err != nil {
			return nil, err
		}
		for j := 0; j < sectorSize/4; j++ {
			c.fat = append(c.fat, binary.LittleEndian.Uint32(buf[j*4:j*4+4]))
		}
		fs++
	}

	// Directory entries (chained via FAT from the first directory sector).
	dirBytes, err := c.readChain(firstDirSect, 0)
	if err != nil {
		return nil, err
	}
	if err := c.parseDir(dirBytes); err != nil {
		return nil, err
	}

	// Mini FAT + mini stream (the root entry's stream is the mini-sector container).
	if numMiniFATSect > 0 && firstMiniFATSect != endOfChain {
		mfBytes, err := c.readChain(firstMiniFATSect, 0)
		if err != nil {
			return nil, err
		}
		c.miniFAT = make([]uint32, len(mfBytes)/4)
		for i := range c.miniFAT {
			c.miniFAT[i] = binary.LittleEndian.Uint32(mfBytes[i*4 : i*4+4])
		}
	}
	if len(c.dir) > 0 && c.dir[0].objType == objRootStore && c.dir[0].size > 0 {
		ms, err := c.readChain(c.dir[0].startSect, c.dir[0].size)
		if err != nil {
			return nil, err
		}
		c.miniStream = ms
	}
	return c, nil
}

func (c *cfbf) readSector(n uint32) ([]byte, error) {
	if n > maxSectors {
		return nil, fmt.Errorf("cfbf: sector %d exceeds cap", n)
	}
	off := (int(n) + 1) * c.sectorSize // header (or its padded first-sector region) precedes sector 0
	if off < 0 || off+c.sectorSize > len(c.data) {
		return nil, fmt.Errorf("cfbf: sector %d out of range", n)
	}
	return c.data[off : off+c.sectorSize], nil
}

// readChain reads a FAT sector chain starting at start. If limit>0 the result is truncated to limit bytes.
func (c *cfbf) readChain(start uint32, limit uint64) ([]byte, error) {
	var out []byte
	seen := 0
	for s := start; s != endOfChain && s != freeSect; {
		if seen++; seen > maxSectors {
			return nil, errors.New("cfbf: FAT chain too long / cyclic")
		}
		buf, err := c.readSector(s)
		if err != nil {
			return nil, err
		}
		out = append(out, buf...)
		if uint64(len(out)) > maxStreamSize {
			return nil, errors.New("cfbf: stream exceeds cap")
		}
		if int(s) >= len(c.fat) {
			return nil, fmt.Errorf("cfbf: FAT index %d out of range", s)
		}
		s = c.fat[s]
	}
	if limit > 0 && uint64(len(out)) > limit {
		out = out[:limit]
	}
	return out, nil
}

// readMiniChain reads a mini-FAT chain from the mini stream (for streams below the cutoff).
func (c *cfbf) readMiniChain(start uint32, size uint64) ([]byte, error) {
	var out []byte
	seen := 0
	for s := start; s != endOfChain && s != freeSect; {
		if seen++; seen > maxSectors {
			return nil, errors.New("cfbf: mini chain too long / cyclic")
		}
		off := int(s) * c.miniSize
		if off < 0 || off+c.miniSize > len(c.miniStream) {
			return nil, fmt.Errorf("cfbf: mini sector %d out of range", s)
		}
		out = append(out, c.miniStream[off:off+c.miniSize]...)
		if uint64(len(out)) > maxStreamSize {
			return nil, errors.New("cfbf: mini stream exceeds cap")
		}
		if int(s) >= len(c.miniFAT) {
			return nil, fmt.Errorf("cfbf: mini FAT index %d out of range", s)
		}
		s = c.miniFAT[s]
	}
	if size > 0 && uint64(len(out)) > size {
		out = out[:size]
	}
	return out, nil
}

func (c *cfbf) parseDir(b []byte) error {
	n := len(b) / dirEntryLen
	if n > maxDirEntries {
		return errors.New("cfbf: too many directory entries")
	}
	for i := 0; i < n; i++ {
		e := b[i*dirEntryLen : (i+1)*dirEntryLen]
		nameLen := int(binary.LittleEndian.Uint16(e[64:66]))
		objType := e[66]
		if objType == 0 { // unallocated
			continue
		}
		name := ""
		if nameLen >= 2 && nameLen <= 64 {
			name = utf16LEString(e[0 : nameLen-2]) // strip the trailing UTF-16 null
		}
		c.dir = append(c.dir, dirEntry{
			name:      name,
			objType:   objType,
			startSect: binary.LittleEndian.Uint32(e[116:120]),
			size:      binary.LittleEndian.Uint64(e[120:128]),
		})
	}
	return nil
}

// stream returns the bytes of the stream directory entry (regular FAT chain if size >= cutoff, else mini).
func (c *cfbf) stream(e dirEntry) ([]byte, error) {
	if e.objType != objStream {
		return nil, fmt.Errorf("cfbf: %q is not a stream", e.name)
	}
	if e.size >= uint64(c.miniCutoff) {
		return c.readChain(e.startSect, e.size)
	}
	return c.readMiniChain(e.startSect, e.size)
}

func hasPrefix(b, prefix []byte) bool {
	if len(b) < len(prefix) {
		return false
	}
	for i := range prefix {
		if b[i] != prefix[i] {
			return false
		}
	}
	return true
}

// utf16LEString decodes little-endian UTF-16 bytes to a Go string (BMP + surrogate pairs).
func utf16LEString(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u = append(u, binary.LittleEndian.Uint16(b[i:i+2]))
	}
	return string(utf16Decode(u))
}
