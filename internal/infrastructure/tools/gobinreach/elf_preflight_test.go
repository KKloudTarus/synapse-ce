package gobinreach

import (
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestPreflightELFRejectsCompressedAndOversizedSectionNames(t *testing.T) {
	image := make([]byte, 256)
	copy(image, "\x7fELF")
	image[4], image[5], image[6] = byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), 1
	binary.LittleEndian.PutUint64(image[40:], 64) // section table
	binary.LittleEndian.PutUint16(image[58:], 64) // section header size
	binary.LittleEndian.PutUint16(image[60:], 2)  // section count
	binary.LittleEndian.PutUint16(image[62:], 1)  // section-name table index
	binary.LittleEndian.PutUint32(image[132:], 3) // SHT_STRTAB
	binary.LittleEndian.PutUint64(image[152:], 192)
	binary.LittleEndian.PutUint64(image[160:], 8)
	copy(image[192:], "\x00.shstr\x00")
	path := filepath.Join(t.TempDir(), "candidate")
	check := func(want bool) {
		t.Helper()
		if err := os.WriteFile(path, image, 0o600); err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = file.Close() }()
		if got := preflightELF(file, int64(len(image))); got != want {
			t.Fatalf("preflight = %v, want %v", got, want)
		}
	}
	check(true)
	binary.LittleEndian.PutUint16(image[58:], 65535)
	check(false)
	binary.LittleEndian.PutUint16(image[58:], 64)
	binary.LittleEndian.PutUint16(image[56:], 1)
	binary.LittleEndian.PutUint16(image[54:], 65535)
	check(false)
	binary.LittleEndian.PutUint16(image[54:], 56)
	binary.LittleEndian.PutUint64(image[32:], 240)
	check(false)
	binary.LittleEndian.PutUint16(image[56:], 0)
	binary.LittleEndian.PutUint64(image[136:], uint64(elf.SHF_COMPRESSED))
	check(false)
	binary.LittleEndian.PutUint64(image[136:], 0)
	binary.LittleEndian.PutUint64(image[160:], maxELFSectionNameBytes+1)
	check(false)
}
