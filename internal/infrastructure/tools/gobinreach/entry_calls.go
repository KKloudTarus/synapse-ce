package gobinreach

import (
	"bytes"
	"context"
	"debug/elf"
	"debug/gosym"
	"encoding/binary"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/symbolcanon"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachability"
)

const (
	maxEntryCallFunctions    = 200_000
	maxFunctionCodeBytes     = 16 << 20
	maxEntryCallWalk         = 200_000
	maxEntryCallPCData       = 64
	maxEntryCallInlineCalls  = 65_536
	maxEntryCallPCDataSteps  = 1_000_000
	maxEntryCallFunctionName = 4_096
)

// EntryCallAnalyzer proves positive Go-binary reachability from main.main over direct Linux/amd64 calls.
// It intentionally answers only paths it can decode from .gopclntab function ranges. Unsupported binaries,
// malformed metadata, undecodable instructions, indirect calls, and unresolved direct targets contribute no
// result; this is a raise-only capability, so uncertainty can only forgo a raise and can never mint a negative.
type EntryCallAnalyzer struct{}

// NewEntryCallAnalyzer returns the bounded direct-call Go-binary analyzer.
func NewEntryCallAnalyzer() *EntryCallAnalyzer { return &EntryCallAnalyzer{} }

// Analyze reports only affected symbols reached from main.main by an observed chain of x86-64 direct calls.
// A target that has no proven path is omitted rather than reported unreachable.
func (a *EntryCallAnalyzer) Analyze(ctx context.Context, dir string, subjects []string) (*reachability.Analysis, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: Go-binary entry-call analysis requires a context", shared.ErrValidation)
	}
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("%w: Go-binary entry-call analysis requires a target directory", shared.ErrValidation)
	}

	wanted := make(map[string]symbolcanon.Symbol, len(subjects))
	ordered := make([]string, 0, len(subjects))
	for _, subject := range subjects {
		if strings.TrimSpace(subject) == "" {
			continue
		}
		if _, exists := wanted[subject]; exists {
			continue
		}
		canonical := symbolcanon.Canonicalize(symbolcanon.Go, subject)
		if len(canonical.Segments) < 2 {
			continue // a bare leaf cannot safely identify a Go affected symbol
		}
		wanted[subject] = canonical
		ordered = append(ordered, subject)
	}
	if len(wanted) == 0 {
		return &reachability.Analysis{}, nil
	}

	paths := map[string][]string{}
	entrypoints := map[string]bool{}
	files := 0
	walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable paths are no coverage for this binary, never a negative
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() {
			if path != dir && skipDir[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if files++; files > maxFilesWalked {
			return fs.SkipAll
		}
		if !d.Type().IsRegular() {
			return nil
		}
		proven, root, ok := entryCallPathsFromLinuxAMD64ELF(path, wanted)
		if !ok {
			return nil
		}
		entrypoints[root] = true
		for subject, path := range proven {
			if _, exists := paths[subject]; !exists {
				paths[subject] = path
			}
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}

	results := make([]reachability.Result, 0, len(paths))
	for _, subject := range ordered {
		if path, ok := paths[subject]; ok {
			results = append(results, reachability.Result{Symbol: subject, Reachable: true, Path: path})
		}
	}
	entries := make([]string, 0, len(entrypoints))
	for entry := range entrypoints {
		entries = append(entries, entry)
	}
	sort.Strings(entries)
	return &reachability.Analysis{Results: results, Entrypoints: entries}, nil
}

type pclntabFunction struct {
	name        string
	entry       uint64
	end         uint64
	inlinePaths [][]string
}

type inlineCall struct {
	name   string
	parent int
}

type pcDataRange struct {
	end   uint64
	value int
}

// entryCallPathsFromLinuxAMD64ELF reads the Linux/amd64 form only. The recover boundary protects the scanner
// from malformed executable metadata and the debug/gosym parser; either failure is simply no coverage.
func entryCallPathsFromLinuxAMD64ELF(path string, wanted map[string]symbolcanon.Symbol) (proven map[string][]string, root string, ok bool) {
	defer func() {
		if recover() != nil {
			proven, root, ok = nil, "", false
		}
	}()

	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 4 || info.Size() > maxBinaryBytes {
		return nil, "", false
	}
	executable, err := elf.Open(path)
	if err != nil {
		return nil, "", false
	}
	defer func() { _ = executable.Close() }()
	if executable.Class != elf.ELFCLASS64 || executable.Machine != elf.EM_X86_64 || executable.Data != elf.ELFDATA2LSB ||
		(executable.Type != elf.ET_EXEC && executable.Type != elf.ET_DYN) {
		return nil, "", false
	}
	textSection := executable.Section(".text")
	pclntabSection := executable.Section(".gopclntab")
	if textSection == nil || pclntabSection == nil || textSection.Flags&elf.SHF_EXECINSTR == 0 {
		return nil, "", false
	}
	text, err := textSection.Data()
	if err != nil || len(text) == 0 || len(text) > maxBinaryBytes {
		return nil, "", false
	}
	pclntab, err := pclntabSection.Data()
	if err != nil || len(pclntab) == 0 || len(pclntab) > maxBinaryBytes {
		return nil, "", false
	}
	table, err := gosym.NewTable(nil, gosym.NewLineTable(pclntab, textSection.Addr))
	if err != nil || table == nil || len(table.Funcs) == 0 || len(table.Funcs) > maxEntryCallFunctions {
		return nil, "", false
	}

	functions := make(map[uint64]pclntabFunction, len(table.Funcs))
	textEnd := textSection.Addr + uint64(len(text))
	for _, function := range table.Funcs {
		name := strings.TrimSpace(function.Name)
		if name == "" || function.Entry < textSection.Addr || function.End <= function.Entry || function.End > textEnd {
			return nil, "", false
		}
		if _, duplicate := functions[function.Entry]; duplicate {
			return nil, "", false
		}
		functions[function.Entry] = pclntabFunction{name: name, entry: function.Entry, end: function.End}
	}
	inlinePaths, inlineOK := pclntabInlinePaths(pclntab, textSection.Addr, functions)
	if !inlineOK {
		return nil, "", false
	}
	for entry, paths := range inlinePaths {
		function := functions[entry]
		function.inlinePaths = paths
		functions[entry] = function
	}
	start, found := functionsByName(functions, "main.main")
	if !found {
		return nil, "", false
	}
	paths, complete := walkDirectCalls(text, textSection.Addr, functions, start, wanted)
	if !complete && len(paths) == 0 {
		return nil, "", false
	}
	return paths, start.name, true
}

func functionsByName(functions map[uint64]pclntabFunction, name string) (pclntabFunction, bool) {
	for _, function := range functions {
		if function.name == name {
			return function, true
		}
	}
	return pclntabFunction{}, false
}

// pclntabInlinePaths decodes the Go 1.20+ inlining metadata that accompanies a physical PCLNTAB function.
// An inlined function has no independently callable machine-code range, but its linker-recorded inline tree is
// still a concrete may-call proof inside its reached physical parent. Other PCLNTAB formats or any malformed
// offset are deliberately no coverage rather than a guessed edge.
func pclntabInlinePaths(data []byte, textStart uint64, functions map[uint64]pclntabFunction) (map[uint64][][]string, bool) {
	const (
		go120PCLNMagic      = 0xfffffff1
		pclnHeaderBytes     = 8 + 8*8
		functionHeaderBytes = 44
		pcdataInlineIndex   = 2
		funcdataInlineIndex = 3
		inlineCallBytes     = 16
	)
	if len(data) < pclnHeaderBytes || binary.LittleEndian.Uint32(data) != go120PCLNMagic ||
		data[4] != 0 || data[5] != 0 || data[6] != 1 || data[7] != 8 {
		return nil, false
	}
	word := func(index int) (uint64, bool) {
		offset := 8 + index*8
		if offset < 0 || offset+8 > len(data) {
			return 0, false
		}
		return binary.LittleEndian.Uint64(data[offset:]), true
	}
	nfunc, ok := word(0)
	if !ok || nfunc == 0 || nfunc > maxEntryCallFunctions || int(nfunc) != len(functions) {
		return nil, false
	}
	funcNameOffset, ok := word(3)
	if !ok || funcNameOffset >= uint64(len(data)) {
		return nil, false
	}
	pctabOffset, ok := word(6)
	if !ok || pctabOffset >= uint64(len(data)) {
		return nil, false
	}
	funcTabOffset, ok := word(7)
	if !ok || funcTabOffset >= uint64(len(data)) || nfunc > (uint64(len(data))-funcTabOffset-4)/8 {
		return nil, false
	}

	type functionMetadata struct {
		function    pclntabFunction
		dataOffset  uint64
		npcdata     uint32
		nfuncdata   uint8
		functionLen uint64
	}
	metadata := make([]functionMetadata, 0, nfunc)
	maximumEnd := uint64(0)
	for index := uint64(0); index < nfunc; index++ {
		tableOffset := funcTabOffset + index*8
		entryOffset := binary.LittleEndian.Uint32(data[tableOffset:])
		functionOffset := binary.LittleEndian.Uint32(data[tableOffset+4:])
		entry := textStart + uint64(entryOffset)
		function, found := functions[entry]
		if !found || functionOffset > uint32(len(data)-int(funcTabOffset)) {
			return nil, false
		}
		dataOffset := funcTabOffset + uint64(functionOffset)
		if dataOffset > uint64(len(data)-functionHeaderBytes) || binary.LittleEndian.Uint32(data[dataOffset:]) != entryOffset {
			return nil, false
		}
		nameOffset := int64(int32(binary.LittleEndian.Uint32(data[dataOffset+4:])))
		name, valid := pclntabFunctionName(data, funcNameOffset, nameOffset)
		if !valid || name != function.name {
			return nil, false
		}
		npcdata := binary.LittleEndian.Uint32(data[dataOffset+28:])
		nfuncdata := data[dataOffset+43]
		if npcdata > maxEntryCallPCData || nfuncdata > maxEntryCallPCData ||
			uint64(npcdata)+uint64(nfuncdata) > (uint64(len(data))-dataOffset-functionHeaderBytes)/4 {
			return nil, false
		}
		end := dataOffset + functionHeaderBytes + uint64(npcdata)*4 + uint64(nfuncdata)*4
		if end > maximumEnd {
			maximumEnd = end
		}
		metadata = append(metadata, functionMetadata{
			function: function, dataOffset: dataOffset, npcdata: npcdata, nfuncdata: nfuncdata,
			functionLen: function.end - function.entry,
		})
	}
	goFuncOffset := (maximumEnd + 7) &^ uint64(7)
	if goFuncOffset > uint64(len(data)) {
		return nil, false
	}

	out := make(map[uint64][][]string)
	for _, item := range metadata {
		if item.nfuncdata <= funcdataInlineIndex {
			continue
		}
		funcdataOffset := item.dataOffset + functionHeaderBytes + uint64(item.npcdata+funcdataInlineIndex)*4
		inlineOffset := binary.LittleEndian.Uint32(data[funcdataOffset:])
		if inlineOffset == ^uint32(0) {
			continue
		}
		if item.npcdata <= pcdataInlineIndex {
			return nil, false
		}
		pcdataOffset := binary.LittleEndian.Uint32(data[item.dataOffset+functionHeaderBytes+pcdataInlineIndex*4:])
		if pcdataOffset == 0 || pctabOffset+uint64(pcdataOffset) >= uint64(len(data)) {
			return nil, false
		}
		ranges, maximumIndex, valid := inlinePCDataRanges(data, pctabOffset+uint64(pcdataOffset), item.functionLen)
		if !valid || maximumIndex < 0 || maximumIndex >= maxEntryCallInlineCalls {
			return nil, false
		}
		count := maximumIndex + 1
		inlineStart := goFuncOffset + uint64(inlineOffset)
		if inlineStart < goFuncOffset || inlineStart > uint64(len(data)) || uint64(count) > (uint64(len(data))-inlineStart)/inlineCallBytes {
			return nil, false
		}
		calls := make([]inlineCall, count)
		for index := range calls {
			offset := inlineStart + uint64(index*inlineCallBytes)
			if data[offset+1] != 0 || data[offset+2] != 0 || data[offset+3] != 0 {
				return nil, false
			}
			nameOffset := int64(int32(binary.LittleEndian.Uint32(data[offset+4:])))
			name, valid := pclntabFunctionName(data, funcNameOffset, nameOffset)
			if !valid {
				return nil, false
			}
			parentPC := int64(int32(binary.LittleEndian.Uint32(data[offset+8:])))
			if parentPC < 0 || uint64(parentPC) >= item.functionLen {
				return nil, false
			}
			parent, valid := inlineParentIndex(ranges, uint64(parentPC), count)
			if !valid {
				return nil, false
			}
			calls[index] = inlineCall{name: name, parent: parent}
		}
		paths := make([][]string, 0, len(calls))
		for index := range calls {
			path, valid := inlineCallPath(calls, index, map[int]bool{})
			if !valid {
				return nil, false
			}
			paths = append(paths, path)
		}
		out[item.function.entry] = paths
	}
	return out, true
}

func pclntabFunctionName(data []byte, functionNameOffset uint64, nameOffset int64) (string, bool) {
	if nameOffset < 0 || functionNameOffset+uint64(nameOffset) >= uint64(len(data)) {
		return "", false
	}
	start := functionNameOffset + uint64(nameOffset)
	remaining := data[start:]
	end := bytes.IndexByte(remaining, 0)
	if end <= 0 || end > maxEntryCallFunctionName {
		return "", false
	}
	return string(remaining[:end]), true
}

func inlinePCDataRanges(data []byte, offset, functionLen uint64) ([]pcDataRange, int, bool) {
	if offset >= uint64(len(data)) || functionLen == 0 {
		return nil, 0, false
	}
	cursor := offset
	pc := uint64(0)
	value := -1
	maximum := -1
	first := true
	var ranges []pcDataRange
	for steps := 0; steps < maxEntryCallPCDataSteps; steps++ {
		delta, next, valid := pclntabVarint(data, cursor)
		if !valid {
			return nil, 0, false
		}
		if delta == 0 && !first {
			if len(ranges) == 0 {
				return nil, 0, false
			}
			return ranges, maximum, true
		}
		cursor = next
		valueDelta := int(delta >> 1)
		if delta&1 != 0 {
			valueDelta = -valueDelta - 1
		}
		value += valueDelta
		if value < -1 {
			return nil, 0, false
		}
		pcDelta, next, valid := pclntabVarint(data, cursor)
		if !valid || uint64(pcDelta) > functionLen-pc {
			return nil, 0, false
		}
		cursor = next
		pc += uint64(pcDelta)
		if pc == 0 {
			return nil, 0, false
		}
		ranges = append(ranges, pcDataRange{end: pc, value: value})
		if value > maximum {
			maximum = value
		}
		first = false
	}
	return nil, 0, false
}

func pclntabVarint(data []byte, offset uint64) (uint32, uint64, bool) {
	var value uint32
	for shift := uint(0); shift < 32; shift += 7 {
		if offset >= uint64(len(data)) {
			return 0, 0, false
		}
		part := data[offset]
		offset++
		value |= uint32(part&0x7f) << shift
		if part&0x80 == 0 {
			return value, offset, true
		}
	}
	return 0, 0, false
}

func inlineParentIndex(ranges []pcDataRange, pc uint64, count int) (int, bool) {
	for _, item := range ranges {
		if pc < item.end {
			if item.value < -1 || item.value >= count {
				return 0, false
			}
			return item.value, true
		}
	}
	return 0, false
}

func inlineCallPath(calls []inlineCall, index int, seen map[int]bool) ([]string, bool) {
	if index < 0 || index >= len(calls) || seen[index] {
		return nil, false
	}
	seen[index] = true
	call := calls[index]
	if call.parent == -1 {
		return []string{call.name}, true
	}
	parent, valid := inlineCallPath(calls, call.parent, seen)
	if !valid {
		return nil, false
	}
	return append(parent, call.name), true
}

// walkDirectCalls preserves only edges whose source instruction and target function entry were both observed.
// It stops an undecodable branch, but retains an already decoded path to a queried symbol: that positive is
// independent of coverage elsewhere. The complete return value is therefore useful only for deciding whether a
// binary with no positive evidence provided any usable coverage at all.
func walkDirectCalls(text []byte, textAddress uint64, functions map[uint64]pclntabFunction, start pclntabFunction, wanted map[string]symbolcanon.Symbol) (map[string][]string, bool) {
	paths := map[string][]string{}
	complete := true

	// Keep paths separate from the visited set so identical call chains are stable and no mutable slice is shared.
	functionPaths := map[uint64][]string{start.entry: {start.name}}
	queue := []pclntabFunction{start}
	seen := map[uint64]bool{start.entry: true}
	for len(queue) > 0 {
		if len(seen) > maxEntryCallWalk {
			return paths, false
		}
		current := queue[0]
		queue = queue[1:]
		path := functionPaths[current.entry]
		for subject, wantedSymbol := range wanted {
			if _, found := paths[subject]; found {
				continue
			}
			if symbolcanon.TailMatch(wantedSymbol, symbolcanon.Canonicalize(symbolcanon.Go, current.name), 2) {
				paths[subject] = append([]string(nil), path...)
			}
		}
		// Linker-recorded inline frames are executable code inside the reached physical parent. They carry their
		// logical source call chain even when optimization eliminated a standalone function range, so retain that
		// precise metadata rather than treating an optimized-away function as absent.
		for _, inlinePath := range current.inlinePaths {
			logicalPath := append(append([]string(nil), path...), inlinePath...)
			for index, name := range inlinePath {
				for subject, wantedSymbol := range wanted {
					if _, found := paths[subject]; found {
						continue
					}
					if symbolcanon.TailMatch(wantedSymbol, symbolcanon.Canonicalize(symbolcanon.Go, name), 2) {
						paths[subject] = append([]string(nil), logicalPath[:len(path)+index+1]...)
					}
				}
			}
		}

		codeStart := current.entry - textAddress
		codeEnd := current.end - textAddress
		if codeEnd <= codeStart || codeEnd-codeStart > maxFunctionCodeBytes || codeEnd > uint64(len(text)) {
			complete = false
			continue
		}
		targets, decoded := directCallTargets(text[codeStart:codeEnd], current.entry)
		if !decoded {
			complete = false
		}
		for _, target := range targets {
			callee, exists := functions[target]
			if !exists || seen[target] {
				continue
			}
			seen[target] = true
			functionPaths[target] = append(append([]string(nil), path...), callee.name)
			queue = append(queue, callee)
		}
	}
	return paths, complete
}

// directCallTargets decodes an x86-64 function linearly and returns only E8 rel32 calls that begin on a decoded
// instruction boundary. It supports the compact instruction forms emitted by the Go Linux/amd64 compiler; an
// unfamiliar form stops this function at the last safe boundary instead of scanning arbitrary bytes for 0xe8.
func directCallTargets(code []byte, address uint64) ([]uint64, bool) {
	var targets []uint64
	for offset := 0; offset < len(code); {
		size, target, direct, ok := decodeAMD64Instruction(code[offset:], address+uint64(offset))
		if !ok || size <= 0 || size > len(code)-offset {
			return targets, false
		}
		if direct {
			targets = append(targets, target)
		}
		offset += size
	}
	return targets, true
}

func decodeAMD64Instruction(code []byte, address uint64) (size int, target uint64, direct bool, ok bool) {
	index := 0
	operand16 := false
	for index < len(code) {
		switch code[index] {
		case 0x66:
			operand16 = true
			index++
		case 0x67:
			return 0, 0, false, false // address-size override is outside the deliberately narrow capability
		case 0xf0, 0xf2, 0xf3, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65:
			index++
		case 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f:
			index++
		default:
			goto opcode
		}
		if index >= 15 {
			return 0, 0, false, false
		}
	}
	return 0, 0, false, false

opcode:
	if index >= len(code) {
		return 0, 0, false, false
	}
	rexW := index > 0 && code[index-1]&0xf8 == 0x48
	opcode := code[index]
	index++
	operandBytes := 4
	if operand16 {
		operandBytes = 2
	}
	finish := func(next int) (int, uint64, bool, bool) {
		if next <= 0 || next > len(code) || next > 15 {
			return 0, 0, false, false
		}
		return next, 0, false, true
	}
	immediate := func(n int) (int, bool) {
		if n < 0 || index+n > len(code) {
			return 0, false
		}
		return index + n, true
	}
	modRM := func(immediateBytes int) (int, byte, bool) {
		next, reg, valid := consumeAMD64ModRM(code, index)
		if !valid || immediateBytes < 0 || next+immediateBytes > len(code) {
			return 0, 0, false
		}
		return next + immediateBytes, reg, true
	}

	switch {
	case opcode == 0xe8:
		if index+4 > len(code) {
			return 0, 0, false, false
		}
		displacement := int64(int32(binary.LittleEndian.Uint32(code[index : index+4])))
		next := index + 4
		if next > 15 {
			return 0, 0, false, false
		}
		return next, uint64(int64(address) + int64(next) + displacement), true, true
	case opcode == 0xe9:
		next, valid := immediate(4)
		if !valid {
			return 0, 0, false, false
		}
		return finish(next)
	case opcode == 0xeb || opcode >= 0x70 && opcode <= 0x7f || opcode >= 0xe0 && opcode <= 0xe3 || opcode == 0x6a || opcode == 0xa8 || opcode == 0xcd:
		next, valid := immediate(1)
		if !valid {
			return 0, 0, false, false
		}
		return finish(next)
	case opcode == 0x68:
		next, valid := immediate(operandBytes)
		if !valid {
			return 0, 0, false, false
		}
		return finish(next)
	case opcode >= 0xb0 && opcode <= 0xb7:
		next, valid := immediate(1)
		if !valid {
			return 0, 0, false, false
		}
		return finish(next)
	case opcode >= 0xb8 && opcode <= 0xbf:
		bytes := operandBytes
		if rexW {
			bytes = 8
		}
		next, valid := immediate(bytes)
		if !valid {
			return 0, 0, false, false
		}
		return finish(next)
	case opcode >= 0x50 && opcode <= 0x5f || opcode == 0x90 || opcode == 0x98 || opcode == 0x99 || opcode == 0x9b ||
		opcode == 0x9c || opcode == 0x9d || opcode == 0xc3 || opcode == 0xcb || opcode == 0xcc || opcode == 0xce || opcode == 0xcf ||
		opcode == 0xf4 || opcode == 0xf5 || opcode >= 0xf8 && opcode <= 0xfd || opcode >= 0xa4 && opcode <= 0xa7 || opcode >= 0xaa && opcode <= 0xaf:
		return finish(index)
	case opcode == 0xc2 || opcode == 0xca:
		next, valid := immediate(2)
		if !valid {
			return 0, 0, false, false
		}
		return finish(next)
	case opcode == 0xc8:
		next, valid := immediate(3)
		if !valid {
			return 0, 0, false, false
		}
		return finish(next)
	case opcode >= 0xa0 && opcode <= 0xa3:
		bytes := 8
		if operand16 {
			bytes = 4
		}
		next, valid := immediate(bytes)
		if !valid {
			return 0, 0, false, false
		}
		return finish(next)
	case accumulatorImmediateOpcode(opcode):
		bytes := operandBytes
		if opcode&1 == 0 {
			bytes = 1
		}
		next, valid := immediate(bytes)
		if !valid {
			return 0, 0, false, false
		}
		return finish(next)
	case opcode == 0x0f:
		return decodeAMD64Extended(code, index, address, operandBytes)
	case opcode == 0x69:
		next, _, valid := modRM(operandBytes)
		if !valid {
			return 0, 0, false, false
		}
		return finish(next)
	case opcode == 0x6b || opcode == 0x80 || opcode == 0x82 || opcode == 0x83 || opcode == 0xc0 || opcode == 0xc1 || opcode == 0xc6:
		next, _, valid := modRM(1)
		if !valid {
			return 0, 0, false, false
		}
		return finish(next)
	case opcode == 0x81 || opcode == 0xc7:
		next, _, valid := modRM(operandBytes)
		if !valid {
			return 0, 0, false, false
		}
		return finish(next)
	case opcode == 0xf6 || opcode == 0xf7:
		next, reg, valid := modRM(0)
		if !valid {
			return 0, 0, false, false
		}
		if reg == 0 {
			bytes := 1
			if opcode == 0xf7 {
				bytes = operandBytes
			}
			next += bytes
		}
		return finish(next)
	case opcode == 0xfe || opcode == 0xff || opcode >= 0xd8 && opcode <= 0xdf || oneByteModRMOpcode(opcode):
		next, _, valid := modRM(0)
		if !valid {
			return 0, 0, false, false
		}
		return finish(next)
	}
	return 0, 0, false, false
}

func decodeAMD64Extended(code []byte, index int, address uint64, operandBytes int) (int, uint64, bool, bool) {
	if index >= len(code) {
		return 0, 0, false, false
	}
	opcode := code[index]
	index++
	finish := func(next int) (int, uint64, bool, bool) {
		if next <= 0 || next > len(code) || next > 15 {
			return 0, 0, false, false
		}
		return next, 0, false, true
	}
	if opcode >= 0x80 && opcode <= 0x8f {
		if index+4 > len(code) {
			return 0, 0, false, false
		}
		return finish(index + 4)
	}
	switch opcode {
	case 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0e, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x37, 0x77,
		0xa0, 0xa1, 0xa2, 0xa8, 0xa9, 0xaa:
		return finish(index)
	case 0x38:
		if index >= len(code) {
			return 0, 0, false, false
		}
		index++
		next, _, valid := consumeAMD64ModRM(code, index)
		if !valid {
			return 0, 0, false, false
		}
		return finish(next)
	case 0x3a:
		if index >= len(code) {
			return 0, 0, false, false
		}
		index++
		next, _, valid := consumeAMD64ModRM(code, index)
		if !valid || next+1 > len(code) {
			return 0, 0, false, false
		}
		return finish(next + 1)
	}
	immediate := 0
	switch opcode {
	case 0x0f, 0x70, 0x71, 0x72, 0x73, 0xa4, 0xac, 0xba, 0xc2, 0xc4, 0xc5, 0xc6:
		immediate = 1
	}
	next, _, valid := consumeAMD64ModRM(code, index)
	if !valid || next+immediate > len(code) {
		return 0, 0, false, false
	}
	return finish(next + immediate)
}

func consumeAMD64ModRM(code []byte, index int) (next int, reg byte, ok bool) {
	if index >= len(code) {
		return 0, 0, false
	}
	modRM := code[index]
	index++
	mod := modRM >> 6
	reg = (modRM >> 3) & 7
	rm := modRM & 7
	if mod == 3 {
		return index, reg, true
	}
	if rm == 4 {
		if index >= len(code) {
			return 0, 0, false
		}
		sib := code[index]
		index++
		if mod == 0 && sib&7 == 5 {
			if index+4 > len(code) {
				return 0, 0, false
			}
			index += 4
		}
	} else if mod == 0 && rm == 5 {
		if index+4 > len(code) {
			return 0, 0, false
		}
		index += 4
	}
	switch mod {
	case 1:
		if index+1 > len(code) {
			return 0, 0, false
		}
		index++
	case 2:
		if index+4 > len(code) {
			return 0, 0, false
		}
		index += 4
	}
	return index, reg, true
}

func accumulatorImmediateOpcode(opcode byte) bool {
	switch opcode & 0xf8 {
	case 0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38:
		return opcode&7 == 4 || opcode&7 == 5
	}
	return false
}

func oneByteModRMOpcode(opcode byte) bool {
	switch {
	case opcode <= 0x03 || opcode >= 0x08 && opcode <= 0x0b || opcode >= 0x10 && opcode <= 0x13 ||
		opcode >= 0x18 && opcode <= 0x1b || opcode >= 0x20 && opcode <= 0x23 || opcode >= 0x28 && opcode <= 0x2b ||
		opcode >= 0x30 && opcode <= 0x33 || opcode >= 0x38 && opcode <= 0x3b:
		return true
	}
	switch opcode {
	case 0x62, 0x63, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
		0xc4, 0xc5, 0xd0, 0xd1, 0xd2, 0xd3:
		return true
	}
	return false
}

var _ interface {
	Analyze(context.Context, string, []string) (*reachability.Analysis, error)
} = (*EntryCallAnalyzer)(nil)
