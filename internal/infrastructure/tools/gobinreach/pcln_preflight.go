package gobinreach

import (
	"bytes"
	"encoding/binary"
)

// boundedPCLNFunctions rejects impossible or oversized function tables before debug/gosym allocates them.
// All supported Go PCLNTAB versions store the function count in the first pointer-sized word after the header.
func boundedPCLNFunctions(data []byte) bool {
	if len(data) < 16 || data[4] != 0 || data[5] != 0 || data[6] == 0 {
		return false
	}
	var order binary.ByteOrder
	magic := binary.LittleEndian.Uint32(data)
	if !knownPCLNMagic(magic) {
		magic = binary.BigEndian.Uint32(data)
		if !knownPCLNMagic(magic) {
			return false
		}
		order = binary.BigEndian
	} else {
		order = binary.LittleEndian
	}
	var count uint64
	switch data[7] {
	case 4:
		count = uint64(order.Uint32(data[8:]))
	case 8:
		count = order.Uint64(data[8:])
	default:
		return false
	}
	return count > 0 && count <= maxEntryCallFunctions
}

func knownPCLNMagic(magic uint32) bool {
	switch magic {
	case 0xfffffffb, 0xfffffffa, 0xfffffff0, 0xfffffff1:
		return true
	default:
		return false
	}
}

// boundedPCLNFunctionNames checks every function name before debug/gosym copies and interns it.
// A short PCLNTAB can point many function records into one long string at different offsets;
// the section-size cap alone does not bound those allocations.
func boundedPCLNFunctionNames(data []byte) bool {
	if !boundedPCLNFunctions(data) {
		return false
	}
	var order binary.ByteOrder = binary.LittleEndian
	magic := order.Uint32(data)
	if !knownPCLNMagic(magic) {
		order = binary.BigEndian
		magic = order.Uint32(data)
	}
	// Go 1.2 uses an arbitrary file-name offset table. gosym can copy overlapping
	// long strings from it before function parsing, so that format has no coverage.
	if magic == 0xfffffffb {
		return false
	}
	ptrSize := uint64(data[7])
	readWord := func(offset uint64) (uint64, bool) {
		if offset > uint64(len(data)) || ptrSize > uint64(len(data))-offset {
			return 0, false
		}
		if ptrSize == 4 {
			return uint64(order.Uint32(data[offset:])), true
		}
		return order.Uint64(data[offset:]), true
	}
	count, _ := readWord(8)
	fileCount, ok := readWord(8 + ptrSize)
	if !ok || fileCount > maxEntryCallFiles {
		return false
	}
	var namesOffset, funcdataOffset, functabOffset, fieldSize, nameFieldOffset uint64
	switch magic {
	case 0xfffffffa: // Go 1.16: word 2 names, word 6 funcdata/functab.
		var ok bool
		namesOffset, ok = readWord(8 + 2*ptrSize)
		if !ok {
			return false
		}
		funcdataOffset, ok = readWord(8 + 6*ptrSize)
		if !ok {
			return false
		}
		functabOffset = funcdataOffset
		fieldSize = ptrSize
		nameFieldOffset = ptrSize
	case 0xfffffff0, 0xfffffff1: // Go 1.18+: word 3 names, word 7 funcdata/functab.
		var ok bool
		namesOffset, ok = readWord(8 + 3*ptrSize)
		if !ok {
			return false
		}
		funcdataOffset, ok = readWord(8 + 7*ptrSize)
		if !ok {
			return false
		}
		functabOffset = funcdataOffset
		fieldSize = 4
		nameFieldOffset = 4
	default:
		return false
	}
	length := uint64(len(data))
	if namesOffset >= length || functabOffset >= length {
		return false
	}
	availableFields := (length - functabOffset) / fieldSize
	if availableFields == 0 || count > (availableFields-1)/2 {
		return false
	}
	remainingNameBytes := maxDecodedFunctionNames
	for index := uint64(0); index < count; index++ {
		tableOffset := functabOffset + (2*index+1)*fieldSize
		functionOffset := uint64(0)
		if fieldSize == 4 {
			functionOffset = uint64(order.Uint32(data[tableOffset:]))
		} else {
			functionOffset = order.Uint64(data[tableOffset:])
		}
		if funcdataOffset > length || functionOffset > length-funcdataOffset {
			return false
		}
		functionDataOffset := funcdataOffset + functionOffset
		if functionDataOffset > length || nameFieldOffset+4 > length-functionDataOffset {
			return false
		}
		nameOffset := uint64(order.Uint32(data[functionDataOffset+nameFieldOffset:]))
		if nameOffset > length-namesOffset-1 {
			return false
		}
		start := namesOffset + nameOffset
		end := start + maxEntryCallFunctionName + 1
		if end > length {
			end = length
		}
		nameLength := bytes.IndexByte(data[start:end], 0)
		if nameLength <= 0 || nameLength > remainingNameBytes {
			return false
		}
		remainingNameBytes -= nameLength
	}
	return true
}
