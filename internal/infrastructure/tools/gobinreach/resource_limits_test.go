package gobinreach

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestPCLNFunctionBudgetRejectsForgedCount(t *testing.T) {
	data := make([]byte, 16)
	binary.LittleEndian.PutUint32(data, 0xfffffff1)
	data[6], data[7] = 1, 8
	binary.LittleEndian.PutUint64(data[8:], maxEntryCallFunctions)
	if !boundedPCLNFunctions(data) {
		t.Fatal("bounded Go function count was rejected")
	}
	binary.LittleEndian.PutUint64(data[8:], maxEntryCallFunctions+1)
	if boundedPCLNFunctions(data) {
		t.Fatal("oversized Go function count was accepted")
	}
}

func TestInlinePCDataRespectsSharedWorkBudget(t *testing.T) {
	// One range followed by a terminator requires two decoded steps.
	data := []byte{2, 1, 0}
	remaining := 1
	if _, _, ok := inlinePCDataRanges(context.Background(), data, 0, 1, &remaining); ok {
		t.Fatal("PCData decode exceeded its shared work budget")
	}
	remaining = 2
	ranges, maximum, ok := inlinePCDataRanges(context.Background(), data, 0, 1, &remaining)
	if !ok || len(ranges) != 1 || maximum != 0 || remaining != 0 {
		t.Fatalf("bounded PCData decode = %v, %d, %v, remaining %d", ranges, maximum, ok, remaining)
	}
}

func TestPCLNTABNameBudgetRejectsReusedLongNames(t *testing.T) {
	build := func(count int) ([]byte, map[uint64]pclntabFunction) {
		const headerBytes = 72
		const functionHeaderBytes = 44
		name := strings.Repeat("x", maxEntryCallFunctionName)
		funcTabOffset := headerBytes + len(name) + 1
		funcTabOffset = (funcTabOffset + 7) &^ 7
		functionDataOffset := funcTabOffset + count*8 + 4
		data := make([]byte, functionDataOffset+count*functionHeaderBytes+8)
		binary.LittleEndian.PutUint32(data, 0xfffffff1)
		data[6], data[7] = 1, 8
		binary.LittleEndian.PutUint64(data[8:], uint64(count))
		binary.LittleEndian.PutUint64(data[8+3*8:], headerBytes)
		binary.LittleEndian.PutUint64(data[8+6*8:], headerBytes)
		binary.LittleEndian.PutUint64(data[8+7*8:], uint64(funcTabOffset))
		copy(data[headerBytes:], name)
		functions := make(map[uint64]pclntabFunction, count)
		for index := 0; index < count; index++ {
			entryOffset := uint32(index + 1)
			tableOffset := funcTabOffset + index*8
			dataOffset := functionDataOffset + index*functionHeaderBytes
			binary.LittleEndian.PutUint32(data[tableOffset:], entryOffset)
			binary.LittleEndian.PutUint32(data[tableOffset+4:], uint32(dataOffset-funcTabOffset))
			binary.LittleEndian.PutUint32(data[dataOffset:], entryOffset)
			entry := uint64(entryOffset)
			functions[entry] = pclntabFunction{name: name, entry: entry, end: entry + 1}
		}
		return data, functions
	}
	allowed, functions := build(maxDecodedFunctionNames / maxEntryCallFunctionName)
	if !boundedPCLNFunctionNames(allowed) {
		t.Fatal("preflight rejected names at the decoded-byte budget")
	}
	tooManyFiles := bytes.Clone(allowed)
	binary.LittleEndian.PutUint64(tooManyFiles[16:], maxEntryCallFiles+1)
	if boundedPCLNFunctionNames(tooManyFiles) {
		t.Fatal("preflight accepted excessive file-table work")
	}
	oldFormat := bytes.Clone(allowed)
	binary.LittleEndian.PutUint32(oldFormat, 0xfffffffb)
	if boundedPCLNFunctionNames(oldFormat) {
		t.Fatal("preflight accepted old-format offset file table")
	}
	if _, ok := pclntabInlinePaths(context.Background(), allowed, 0, functions, nil); !ok {
		t.Fatal("names at the shared decoded-byte budget were rejected")
	}
	allowed[72+maxEntryCallFunctionName] = 'x'
	if boundedPCLNFunctionNames(allowed) {
		t.Fatal("preflight accepted an overlong function name before gosym")
	}
	oversized, functions := build(maxDecodedFunctionNames/maxEntryCallFunctionName + 1)
	if boundedPCLNFunctionNames(oversized) {
		t.Fatal("preflight accepted reused long names beyond the decoded-byte budget")
	}
	if _, ok := pclntabInlinePaths(context.Background(), oversized, 0, functions, nil); ok {
		t.Fatal("reused long names exceeded the shared decoded-byte budget")
	}
}

func TestBoundedWalkStopsBeforeOversizedDirectoryCallback(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"b", "a", "c"} {
		if err := os.WriteFile(filepath.Join(root, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var visited []string
	visit := func(path string) error {
		visited = append(visited, filepath.Base(path))
		return nil
	}
	if err := walkBoundedRegularFiles(context.Background(), root, 3, visit); err != nil || len(visited) != 0 {
		t.Fatalf("oversized directory callback = %v, %v; want no coverage", visited, err)
	}
	if err := walkBoundedRegularFiles(context.Background(), root, 4, visit); err != nil || !slices.Equal(visited, []string{"a", "b", "c"}) {
		t.Fatalf("bounded sorted walk = %v, %v", visited, err)
	}
}

func TestBuildInfoReaderStopsAtTotalReadBudget(t *testing.T) {
	reader := &budgetReaderAt{source: bytes.NewReader([]byte("abcdef")), remaining: 3}
	data := make([]byte, 2)
	if read, err := reader.ReadAt(data, 0); read != 2 || err != nil {
		t.Fatalf("first read = %d, %v", read, err)
	}
	if read, err := reader.ReadAt(data, 2); read != 0 || err != io.ErrUnexpectedEOF {
		t.Fatalf("over-budget read = %d, %v", read, err)
	}
}

func TestProcessImageNeedsExecutableTextLoad(t *testing.T) {
	image := &elf.File{
		FileHeader: elf.FileHeader{Type: elf.ET_EXEC},
		Sections: []*elf.Section{
			{SectionHeader: elf.SectionHeader{Name: ".text", Flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, Addr: 0x2000, Offset: 0x1000, Size: 16}},
			{SectionHeader: elf.SectionHeader{Name: ".gopclntab", Flags: elf.SHF_ALLOC, Addr: 0x3000, Offset: 0x2000, Size: 8}},
		},
	}
	if linuxAMD64ProcessImage(image) {
		t.Fatal("ELF without a load segment was accepted as a process image")
	}
	image.Progs = []*elf.Prog{
		{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Flags: elf.PF_R, Off: 0x1000, Vaddr: 0x2000, Filesz: 16, Memsz: 16}},
		{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Flags: elf.PF_R, Off: 0x2000, Vaddr: 0x3000, Filesz: 8, Memsz: 8}},
	}
	if linuxAMD64ProcessImage(image) {
		t.Fatal("non-executable load segment was accepted")
	}
	image.Progs[0].Flags |= elf.PF_X
	if !linuxAMD64ProcessImage(image) {
		t.Fatal("executable load segment was rejected")
	}
	image.Progs[0].Filesz = 8
	if linuxAMD64ProcessImage(image) {
		t.Fatal("zero-fill tail was accepted as executable text")
	}
	image.Progs[0].Filesz = 16
	image.Sections[0].Offset = 0x1001
	if linuxAMD64ProcessImage(image) {
		t.Fatal("section outside the load segment file mapping was accepted")
	}
	image.Sections[0].Offset = 0x1000
	image.Sections[0].Flags |= elf.SHF_COMPRESSED
	if linuxAMD64ProcessImage(image) {
		t.Fatal("compressed text was accepted as mapped instructions")
	}
	image.Sections[0].Flags &^= elf.SHF_COMPRESSED
	image.Progs = image.Progs[:1]
	if linuxAMD64ProcessImage(image) {
		t.Fatal("unmapped Go function metadata was accepted")
	}
}

func TestEntryCallAnalyzerAdmissionHonorsCancellation(t *testing.T) {
	analyzer := NewEntryCallAnalyzer()
	analyzer.active <- struct{}{}
	defer func() { <-analyzer.active }()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := analyzer.Analyze(ctx, t.TempDir(), []string{
		encodedGoSubject(t, "pkg:golang/example.invalid/library@v1.0.0", "example.invalid/library/pkg.Target"),
	})
	if err != context.DeadlineExceeded {
		t.Fatalf("contended analysis = %v, want context deadline exceeded", err)
	}
}
