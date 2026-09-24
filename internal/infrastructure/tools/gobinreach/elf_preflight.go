package gobinreach

import (
	"debug/elf"
	"encoding/binary"
	"os"
)

const (
	maxELFSections         = 4096
	maxELFProgramHeaders   = 4096
	maxELFSectionNameBytes = 4 << 20
)

// preflightELF bounds the section-name table before debug/elf.NewFile reads and decompresses it.
// Unusual ELF layouts provide no coverage; only a bounded, ordinary section table enters the parser.
func preflightELF(file *os.File, fileSize int64) bool {
	if fileSize < 52 || fileSize > maxBinaryBytes {
		return false
	}
	var header [64]byte
	read, _ := file.ReadAt(header[:], 0)
	if read < 52 || string(header[:4]) != "\x7fELF" {
		return false
	}
	var order binary.ByteOrder
	switch header[5] {
	case byte(elf.ELFDATA2LSB):
		order = binary.LittleEndian
	case byte(elf.ELFDATA2MSB):
		order = binary.BigEndian
	default:
		return false
	}
	var sectionOffset uint64
	var programOffset uint64
	var sectionEntrySize, sectionCount, sectionNames, programEntrySize, programCount uint16
	var expectedEntrySize, expectedProgramEntrySize uint16
	var sectionFlagsOffset, sectionFileOffset, sectionSizeOffset int
	switch header[4] {
	case byte(elf.ELFCLASS32):
		programOffset = uint64(order.Uint32(header[28:]))
		programEntrySize = order.Uint16(header[42:])
		sectionOffset = uint64(order.Uint32(header[32:]))
		sectionEntrySize = order.Uint16(header[46:])
		sectionCount = order.Uint16(header[48:])
		sectionNames = order.Uint16(header[50:])
		programCount = order.Uint16(header[44:])
		expectedEntrySize = 40
		expectedProgramEntrySize = 32
		sectionFlagsOffset, sectionFileOffset, sectionSizeOffset = 8, 16, 20
	case byte(elf.ELFCLASS64):
		if read < 64 {
			return false
		}
		programOffset = order.Uint64(header[32:])
		programEntrySize = order.Uint16(header[54:])
		sectionOffset = order.Uint64(header[40:])
		sectionEntrySize = order.Uint16(header[58:])
		sectionCount = order.Uint16(header[60:])
		sectionNames = order.Uint16(header[62:])
		programCount = order.Uint16(header[56:])
		expectedEntrySize = 64
		expectedProgramEntrySize = 56
		sectionFlagsOffset, sectionFileOffset, sectionSizeOffset = 8, 24, 32
	default:
		return false
	}
	if sectionCount == 0 || sectionCount > maxELFSections || sectionNames == 0 || sectionNames >= sectionCount ||
		sectionEntrySize != expectedEntrySize || programCount > maxELFProgramHeaders ||
		programCount > 0 && programEntrySize != expectedProgramEntrySize {
		return false
	}
	size := uint64(fileSize)
	if sectionOffset > size || uint64(sectionCount) > (size-sectionOffset)/uint64(sectionEntrySize) {
		return false
	}
	if programCount > 0 && (programOffset > size || uint64(programCount) > (size-programOffset)/uint64(programEntrySize)) {
		return false
	}
	nameHeaderOffset := sectionOffset + uint64(sectionNames)*uint64(sectionEntrySize)
	var sectionHeader [64]byte
	if _, err := file.ReadAt(sectionHeader[:expectedEntrySize], int64(nameHeaderOffset)); err != nil {
		return false
	}
	if order.Uint32(sectionHeader[4:8]) != uint32(elf.SHT_STRTAB) {
		return false
	}
	var flags, nameOffset, nameSize uint64
	if expectedEntrySize == 64 {
		flags = order.Uint64(sectionHeader[sectionFlagsOffset:])
		nameOffset = order.Uint64(sectionHeader[sectionFileOffset:])
		nameSize = order.Uint64(sectionHeader[sectionSizeOffset:])
	} else {
		flags = uint64(order.Uint32(sectionHeader[sectionFlagsOffset:]))
		nameOffset = uint64(order.Uint32(sectionHeader[sectionFileOffset:]))
		nameSize = uint64(order.Uint32(sectionHeader[sectionSizeOffset:]))
	}
	return flags&uint64(elf.SHF_COMPRESSED) == 0 && nameSize > 0 && nameSize <= maxELFSectionNameBytes &&
		nameOffset <= size && nameSize <= size-nameOffset
}
