package gobinreach

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"debug/elf"
	"debug/gosym"
	"encoding/binary"
	"fmt"
	"os"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/gobinsubject"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachability"
)

const (
	maxEntryCallFunctions    = 200_000
	maxEntryCallFiles        = 200_000
	maxFunctionCodeBytes     = 16 << 20
	maxEntryCallWalk         = 200_000
	maxEntryCallPCData       = 64
	maxEntryCallInlineCalls  = 65_536
	maxEntryCallPCDataSteps  = 1_000_000
	maxTotalInlineCalls      = 200_000
	maxTotalPCDataSteps      = 1_000_000
	maxEntryCallFunctionName = 4_096
	maxDecodedFunctionNames  = 16 << 20
	maxEntryCallSubjects     = 4_096
	maxWitnessDepth          = 2_048
	maxWitnessFrames         = 65_536
)

// EntryCallAnalyzer proves positive Go-binary reachability from main.main over direct Linux/amd64 calls.
// It intentionally answers only paths it can decode from .gopclntab function ranges. Unsupported binaries,
// malformed metadata, undecodable instructions, indirect calls, and unresolved direct targets contribute no
// result; this is a raise-only capability, so uncertainty can only forgo a raise and can never mint a negative.
type EntryCallAnalyzer struct {
	active chan struct{}
}

// NewEntryCallAnalyzer returns the bounded direct-call Go-binary analyzer.
func NewEntryCallAnalyzer() *EntryCallAnalyzer {
	return &EntryCallAnalyzer{active: make(chan struct{}, 1)}
}

// Analyze reports only affected symbols reached from main.main by an observed chain of x86-64 direct calls.
// A target that has no proven path is omitted rather than reported unreachable.
func (a *EntryCallAnalyzer) Analyze(ctx context.Context, dir string, subjects []string) (*reachability.Analysis, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: Go-binary entry-call analysis requires a context", shared.ErrValidation)
	}
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("%w: Go-binary entry-call analysis requires a target directory", shared.ErrValidation)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if a == nil || a.active == nil {
		return nil, fmt.Errorf("%w: Go-binary entry-call analyzer is not initialized", shared.ErrValidation)
	}
	// One analysis at a time bounds peak binary parsing memory for the shared service instance.
	select {
	case a.active <- struct{}{}:
		defer func() { <-a.active }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if len(subjects) > maxEntryCallSubjects {
		return &reachability.Analysis{}, nil
	}

	wanted := make(map[string]wantedSubject, len(subjects))
	ordered := make([]string, 0, len(subjects))
	for _, subject := range subjects {
		if strings.TrimSpace(subject) == "" {
			continue
		}
		if _, exists := wanted[subject]; exists {
			continue
		}
		purl, symbol, valid := gobinsubject.Parse(subject)
		key, keyValid := goSymbolKeyFor(symbol)
		if !valid || !keyValid {
			continue // an ambiguous or bare leaf cannot safely identify a Go affected symbol
		}
		wanted[subject] = wantedSubject{purl: purl, symbol: key}
		ordered = append(ordered, subject)
	}
	if len(wanted) == 0 {
		return &reachability.Analysis{}, nil
	}

	paths := map[string][]string{}
	entrypoints := map[string]bool{}
	walkErr := walkBoundedRegularFiles(ctx, dir, maxWalkEntries, func(path string) error {
		proven, root, ok := entryCallPathsFromLinuxAMD64ELF(ctx, path, wanted)
		if err := ctx.Err(); err != nil {
			return err
		}
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
	name          string
	entry         uint64
	end           uint64
	inlineCalls   []inlineCall
	inlineMatches map[string]int
}

type inlineCall struct {
	name   string
	parent int
}

type inlineMetadata struct {
	calls   []inlineCall
	matches map[string]int
}

// goSymbolKey is the exact Go function identity used for raise-only matching. It deliberately retains the
// punctuation that separates a module path from its package and function. Generic instantiations and pointer
// receiver spelling are normalized because those differ between an advisory and PCLNTAB without changing the
// function identity. No vendor, semantic-import-version, dot, or slash rewriting is permitted.
type goSymbolKey string

type wantedSubject struct {
	purl   gobinsubject.PURL
	symbol goSymbolKey
}

type pcDataRange struct {
	end   uint64
	value int
}

func inlineWantedIndex(wanted map[string]goSymbolKey) map[goSymbolKey][]string {
	indexed := make(map[goSymbolKey][]string, len(wanted))
	for subject, key := range wanted {
		indexed[key] = append(indexed[key], subject)
	}
	return indexed
}

// boundSubjectsForBinary returns only queries whose exact PURL module and version are attributable to this
// opened image's own build info. The longest owning module path wins for nested modules. A replacement, devel
// version, conflict, absent build info, or any other ambiguity returns no subject for that proposed positive.
func boundSubjectsForBinary(info *debug.BuildInfo, wanted map[string]wantedSubject) map[string]goSymbolKey {
	if info == nil {
		return nil
	}
	modules, ok := indexBuildModules(info)
	if !ok {
		return nil
	}
	bound := make(map[string]goSymbolKey, len(wanted))
	for subject, query := range wanted {
		owner, ok := modules.owner(string(query.symbol))
		if !ok || !goModuleOwnsSymbol(owner.Path, string(query.symbol)) ||
			owner.Path != query.purl.Module || owner.Version != query.purl.Version {
			continue
		}
		bound[subject] = query.symbol
	}
	if len(bound) == 0 {
		return nil
	}
	return bound
}

type buildModuleIndex map[string]indexedBuildModule

type indexedBuildModule struct {
	module   debug.Module
	conflict bool
}

// indexBuildModules reads an image's build metadata once, even when many affected symbols are queried.
func indexBuildModules(info *debug.BuildInfo) (buildModuleIndex, bool) {
	modules := make(buildModuleIndex, len(info.Deps)+1)
	add := func(module debug.Module) {
		if module.Path == "" {
			return
		}
		if existing, found := modules[module.Path]; found {
			if existing.module.Version != module.Version || existing.module.Replace != nil || module.Replace != nil {
				existing.conflict = true
				modules[module.Path] = existing
			}
			return
		}
		modules[module.Path] = indexedBuildModule{module: module}
	}
	add(info.Main)
	for _, dependency := range info.Deps {
		if dependency == nil {
			return nil, false
		}
		add(*dependency)
	}
	return modules, true
}

// owner selects the longest module prefix at a Go package boundary. A root free function can have the
// same spelling as a method from a shorter loaded module, so such overlap provides no coverage.
func (modules buildModuleIndex) owner(symbol string) (debug.Module, bool) {
	var candidate indexedBuildModule
	candidateFound := false
	rootCandidate := false
	for end := len(symbol) - 1; end > 0; end-- {
		if symbol[end] != '/' && symbol[end] != '.' {
			continue
		}
		entry, exists := modules[symbol[:end]]
		if !exists {
			continue
		}
		if !candidateFound {
			candidate = entry
			candidateFound = true
			rootCandidate = symbol[end] == '.'
			if !rootCandidate {
				break
			}
			continue
		}
		if rootCandidate {
			return debug.Module{}, false
		}
	}
	module := candidate.module
	if !candidateFound || candidate.conflict || module.Replace != nil || module.Version == "" || module.Version == "(devel)" {
		return debug.Module{}, false
	}
	return module, true
}

func goModuleOwnsSymbol(module, symbol string) bool {
	return module != "" && gobinsubject.OwnsSymbol(module, symbol)
}

func goSymbolKeyFor(raw string) (goSymbolKey, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, " \t\r\n") {
		return "", false
	}
	withoutGenerics, valid := stripGoGenericArguments(raw)
	if !valid {
		return "", false
	}
	var key strings.Builder
	key.Grow(len(withoutGenerics))
	for index := 0; index < len(withoutGenerics); index++ {
		switch withoutGenerics[index] {
		case '(':
			if index+3 >= len(withoutGenerics) || withoutGenerics[index+1] != '*' {
				return "", false
			}
			end := strings.IndexByte(withoutGenerics[index+2:], ')')
			if end <= 0 {
				return "", false
			}
			end += index + 2
			if strings.ContainsAny(withoutGenerics[index+2:end], "()") {
				return "", false
			}
			key.WriteString(withoutGenerics[index+2 : end])
			index = end
		case ')':
			return "", false
		default:
			key.WriteByte(withoutGenerics[index])
		}
	}
	result := key.String()
	if strings.Count(result, ".") < 1 {
		return "", false
	}
	return goSymbolKey(result), true
}

func stripGoGenericArguments(raw string) (string, bool) {
	var key strings.Builder
	key.Grow(len(raw))
	depth := 0
	for index := 0; index < len(raw); index++ {
		switch raw[index] {
		case '[':
			depth++
		case ']':
			if depth == 0 {
				return "", false
			}
			depth--
		default:
			if depth == 0 {
				key.WriteByte(raw[index])
			}
		}
	}
	if depth != 0 {
		return "", false
	}
	return key.String(), true
}

// entryCallPathsFromLinuxAMD64ELF reads the Linux/amd64 form only. The recover boundary protects the scanner
// from malformed executable metadata and the debug/gosym parser; either failure is simply no coverage.
func entryCallPathsFromLinuxAMD64ELF(ctx context.Context, path string, wanted map[string]wantedSubject) (proven map[string][]string, root string, ok bool) {
	defer func() {
		if recover() != nil {
			proven, root, ok = nil, "", false
		}
	}()
	if ctx.Err() != nil {
		return nil, "", false
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, "", false
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !preflightELF(file, info.Size()) {
		return nil, "", false
	}
	if ctx.Err() != nil {
		return nil, "", false
	}
	executable, err := elf.NewFile(file)
	if err != nil {
		return nil, "", false
	}
	defer func() { _ = executable.Close() }()
	if executable.Class != elf.ELFCLASS64 || executable.Machine != elf.EM_X86_64 || executable.Data != elf.ELFDATA2LSB ||
		!linuxAMD64ProcessImage(executable) {
		return nil, "", false
	}
	binaryInfo, err := buildinfo.Read(&budgetReaderAt{source: file, remaining: maxBuildInfoReadBytes})
	if err != nil || ctx.Err() != nil {
		return nil, "", false
	}
	bound := boundSubjectsForBinary(binaryInfo, wanted)
	if len(bound) == 0 {
		return nil, "", false
	}
	textSection := executable.Section(".text")
	pclntabSection := executable.Section(".gopclntab")
	if textSection == nil || pclntabSection == nil ||
		textSection.Flags&(elf.SHF_ALLOC|elf.SHF_EXECINSTR) != elf.SHF_ALLOC|elf.SHF_EXECINSTR ||
		textSection.Flags&elf.SHF_COMPRESSED != 0 ||
		pclntabSection.Flags&elf.SHF_ALLOC == 0 || pclntabSection.Flags&elf.SHF_COMPRESSED != 0 ||
		textSection.Size == 0 || textSection.Size > maxTextBytes ||
		pclntabSection.Size == 0 || pclntabSection.Size > maxPCLNBytes {
		return nil, "", false
	}
	text, err := textSection.Data()
	if err != nil || len(text) == 0 || len(text) > maxTextBytes || ctx.Err() != nil {
		return nil, "", false
	}
	pclntab, err := pclntabSection.Data()
	if err != nil || len(pclntab) < 4 || len(pclntab) > maxPCLNBytes ||
		binary.LittleEndian.Uint32(pclntab) != 0xfffffff1 ||
		!boundedPCLNFunctionNames(pclntab) || ctx.Err() != nil {
		return nil, "", false
	}
	table, err := gosym.NewTable(nil, gosym.NewLineTable(pclntab, textSection.Addr))
	if err != nil || table == nil || len(table.Funcs) == 0 || len(table.Funcs) > maxEntryCallFunctions || ctx.Err() != nil {
		return nil, "", false
	}

	functions := make(map[uint64]pclntabFunction, len(table.Funcs))
	textEnd := textSection.Addr + uint64(len(text))
	for _, function := range table.Funcs {
		if ctx.Err() != nil {
			return nil, "", false
		}
		name := strings.TrimSpace(function.Name)
		if name == "" || function.Entry < textSection.Addr || function.End <= function.Entry || function.End > textEnd {
			return nil, "", false
		}
		if _, duplicate := functions[function.Entry]; duplicate {
			return nil, "", false
		}
		functions[function.Entry] = pclntabFunction{name: name, entry: function.Entry, end: function.End}
	}
	inlineMetadata, inlineOK := pclntabInlinePaths(ctx, pclntab, textSection.Addr, functions, bound)
	if !inlineOK || ctx.Err() != nil {
		return nil, "", false
	}
	for entry, metadata := range inlineMetadata {
		function := functions[entry]
		function.inlineCalls = metadata.calls
		function.inlineMatches = metadata.matches
		functions[entry] = function
	}
	start, found := functionsByName(ctx, functions, "main.main")
	if !found || ctx.Err() != nil {
		return nil, "", false
	}
	paths, complete := walkDirectCalls(ctx, text, textSection.Addr, functions, start, inlineWantedIndex(bound))
	if !complete && len(paths) == 0 {
		return nil, "", false
	}
	if ctx.Err() != nil {
		return nil, "", false
	}
	return paths, start.name, true
}

// linuxAMD64ProcessImage accepts an executable or a PIE image with code and Go metadata in load segments.
// ET_DYN plugins and shared libraries have no PT_INTERP; ambiguous static PIE forms provide no coverage.
func linuxAMD64ProcessImage(executable *elf.File) bool {
	if executable.Type != elf.ET_EXEC && executable.Type != elf.ET_DYN {
		return false
	}
	text := executable.Section(".text")
	pclntab := executable.Section(".gopclntab")
	if text == nil || text.Size == 0 || text.Size > maxTextBytes ||
		text.Flags&(elf.SHF_ALLOC|elf.SHF_EXECINSTR) != elf.SHF_ALLOC|elf.SHF_EXECINSTR ||
		text.Flags&elf.SHF_COMPRESSED != 0 ||
		pclntab == nil || pclntab.Size == 0 || pclntab.Size > maxPCLNBytes ||
		pclntab.Flags&elf.SHF_ALLOC == 0 || pclntab.Flags&elf.SHF_COMPRESSED != 0 ||
		!elfSectionMapped(executable, text, true) || !elfSectionMapped(executable, pclntab, false) {
		return false
	}
	interpreter := false
	for _, program := range executable.Progs {
		if program.Type == elf.PT_INTERP {
			interpreter = true
		}
	}
	return executable.Type == elf.ET_EXEC || interpreter
}

func elfSectionMapped(executable *elf.File, section *elf.Section, executableLoad bool) bool {
	for _, program := range executable.Progs {
		if program.Type != elf.PT_LOAD || executableLoad && program.Flags&elf.PF_X == 0 ||
			section.Addr < program.Vaddr || section.Offset < program.Off {
			continue
		}
		virtualOffset := section.Addr - program.Vaddr
		fileOffset := section.Offset - program.Off
		if virtualOffset == fileOffset && virtualOffset <= program.Filesz &&
			section.Size <= program.Filesz-virtualOffset &&
			virtualOffset <= program.Memsz && section.Size <= program.Memsz-virtualOffset {
			return true
		}
	}
	return false
}

func functionsByName(ctx context.Context, functions map[uint64]pclntabFunction, name string) (pclntabFunction, bool) {
	for _, function := range functions {
		if ctx.Err() != nil {
			return pclntabFunction{}, false
		}
		if function.name == name {
			return function, true
		}
	}
	return pclntabFunction{}, false
}

// pclntabInlinePaths decodes the Go 1.20+ inlining metadata that accompanies a physical PCLNTAB function.
// An inlined function has no independently callable machine-code range, but its linker-recorded inline tree is
// still a concrete may-call proof inside its reached physical parent. Its bounded call records use binary parent
// lookups, and an ancestor chain is rebuilt only for a requested matching symbol. Other PCLNTAB formats or any
// malformed offset are deliberately no coverage rather than a guessed edge.
func pclntabInlinePaths(ctx context.Context, data []byte, textStart uint64, functions map[uint64]pclntabFunction, wanted map[string]goSymbolKey) (map[uint64]inlineMetadata, bool) {
	if ctx.Err() != nil {
		return nil, false
	}
	wantedIndex := inlineWantedIndex(wanted)
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
	remainingNameBytes := maxDecodedFunctionNames
	maximumEnd := uint64(0)
	for index := uint64(0); index < nfunc; index++ {
		if ctx.Err() != nil {
			return nil, false
		}
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
		if len(name) > remainingNameBytes {
			return nil, false
		}
		remainingNameBytes -= len(name)
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

	out := make(map[uint64]inlineMetadata)
	remainingPCDataSteps := maxTotalPCDataSteps
	remainingInlineCalls := maxTotalInlineCalls
	for _, item := range metadata {
		if ctx.Err() != nil {
			return nil, false
		}
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
		ranges, maximumIndex, valid := inlinePCDataRanges(ctx, data, pctabOffset+uint64(pcdataOffset), item.functionLen, &remainingPCDataSteps)
		if !valid || maximumIndex < 0 || maximumIndex >= maxEntryCallInlineCalls {
			return nil, false
		}
		count := maximumIndex + 1
		if count > remainingInlineCalls {
			return nil, false
		}
		remainingInlineCalls -= count
		inlineStart := goFuncOffset + uint64(inlineOffset)
		if inlineStart < goFuncOffset || inlineStart > uint64(len(data)) || uint64(count) > (uint64(len(data))-inlineStart)/inlineCallBytes {
			return nil, false
		}
		calls := make([]inlineCall, count)
		for index := range calls {
			if ctx.Err() != nil {
				return nil, false
			}
			offset := inlineStart + uint64(index*inlineCallBytes)
			if data[offset+1] != 0 || data[offset+2] != 0 || data[offset+3] != 0 {
				return nil, false
			}
			nameOffset := int64(int32(binary.LittleEndian.Uint32(data[offset+4:])))
			name, valid := pclntabFunctionName(data, funcNameOffset, nameOffset)
			if !valid {
				return nil, false
			}
			if len(name) > remainingNameBytes {
				return nil, false
			}
			remainingNameBytes -= len(name)
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
		if !validInlineCallParents(ctx, calls) {
			return nil, false
		}
		matches, matched := inlineCallMatches(ctx, calls, wantedIndex)
		if !matched {
			return nil, false
		}
		if len(matches) != 0 {
			out[item.function.entry] = inlineMetadata{calls: calls, matches: matches}
		}
	}
	return out, true
}

func pclntabFunctionName(data []byte, functionNameOffset uint64, nameOffset int64) (string, bool) {
	if nameOffset < 0 || functionNameOffset+uint64(nameOffset) >= uint64(len(data)) {
		return "", false
	}
	start := functionNameOffset + uint64(nameOffset)
	endOffset := start + maxEntryCallFunctionName + 1
	if endOffset < start || endOffset > uint64(len(data)) {
		endOffset = uint64(len(data))
	}
	end := bytes.IndexByte(data[start:endOffset], 0)
	if end <= 0 {
		return "", false
	}
	return string(data[start : start+uint64(end)]), true
}

func inlinePCDataRanges(ctx context.Context, data []byte, offset, functionLen uint64, remaining *int) ([]pcDataRange, int, bool) {
	if ctx.Err() != nil || offset >= uint64(len(data)) || functionLen == 0 {
		return nil, 0, false
	}
	cursor := offset
	pc := uint64(0)
	value := -1
	maximum := -1
	first := true
	var ranges []pcDataRange
	for steps := 0; steps < maxEntryCallPCDataSteps; steps++ {
		if ctx.Err() != nil || *remaining == 0 {
			return nil, 0, false
		}
		*remaining -= 1
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
	index := sort.Search(len(ranges), func(index int) bool { return pc < ranges[index].end })
	if index == len(ranges) {
		return 0, false
	}
	parent := ranges[index].value
	if parent < -1 || parent >= count {
		return 0, false
	}
	return parent, true
}

func validInlineCallParents(ctx context.Context, calls []inlineCall) bool {
	states := make([]uint8, len(calls))
	for start := range calls {
		if ctx.Err() != nil {
			return false
		}
		if states[start] != 0 {
			continue
		}
		index := start
		for index != -1 {
			if ctx.Err() != nil || index < 0 || index >= len(calls) {
				return false
			}
			if states[index] != 0 {
				break
			}
			states[index] = 1
			index = calls[index].parent
		}
		if index != -1 && states[index] == 1 {
			return false
		}
		for index = start; index != -1 && states[index] == 1; index = calls[index].parent {
			states[index] = 2
		}
	}
	return true
}

func inlineCallMatches(ctx context.Context, calls []inlineCall, wanted map[goSymbolKey][]string) (map[string]int, bool) {
	matches := make(map[string]int)
	for index, call := range calls {
		if ctx.Err() != nil {
			return nil, false
		}
		key, valid := goSymbolKeyFor(call.name)
		if !valid {
			continue
		}
		for _, subject := range wanted[key] {
			if _, alreadyMatched := matches[subject]; !alreadyMatched {
				matches[subject] = index
			}
		}
	}
	return matches, true
}

func inlineCallPath(ctx context.Context, calls []inlineCall, index int) ([]string, bool) {
	path := make([]string, 0, 8)
	for steps := 0; index != -1; steps++ {
		if ctx.Err() != nil || index < 0 || index >= len(calls) || steps >= len(calls) || steps >= maxWitnessDepth {
			return nil, false
		}
		path = append(path, calls[index].name)
		index = calls[index].parent
	}
	for left, right := 0, len(path)-1; left < right; left, right = left+1, right-1 {
		path[left], path[right] = path[right], path[left]
	}
	return path, true
}

// walkDirectCalls preserves only edges whose source instruction and target function entry were both observed.
// It stops an undecodable branch, but retains an already decoded path to a queried symbol: that positive is
// independent of coverage elsewhere. The complete return value is therefore useful only for deciding whether a
// binary with no positive evidence provided any usable coverage at all.
func walkDirectCalls(ctx context.Context, text []byte, textAddress uint64, functions map[uint64]pclntabFunction, start pclntabFunction, wanted map[goSymbolKey][]string) (map[string][]string, bool) {
	paths := map[string][]string{}
	complete := true
	remainingWitnessFrames := maxWitnessFrames
	// Retain one predecessor per visited function. Full paths are built only for matched subjects.
	parents := make(map[uint64]uint64)
	depths := map[uint64]int{start.entry: 1}
	buildPath := func(entry uint64) []string {
		depth := depths[entry]
		if depth == 0 || depth > maxWitnessDepth {
			return nil
		}
		path := make([]string, depth)
		for index := depth - 1; index >= 0; index-- {
			function, exists := functions[entry]
			if !exists {
				return nil
			}
			path[index] = function.name
			if index > 0 {
				parent, exists := parents[entry]
				if !exists {
					return nil
				}
				entry = parent
			}
		}
		return path
	}
	queue := []pclntabFunction{start}
	seen := map[uint64]bool{start.entry: true}
	for len(queue) > 0 {
		if ctx.Err() != nil || len(seen) > maxEntryCallWalk {
			return paths, false
		}
		current := queue[0]
		queue = queue[1:]
		var path []string
		witness := func() []string {
			if path == nil {
				path = buildPath(current.entry)
			}
			return path
		}
		currentKey, currentValid := goSymbolKeyFor(current.name)
		for _, subject := range wanted[currentKey] {
			if _, found := paths[subject]; !found && currentValid {
				proof := witness()
				if len(proof) == 0 || len(proof) > remainingWitnessFrames {
					complete = false
					continue
				}
				paths[subject] = append([]string(nil), proof...)
				remainingWitnessFrames -= len(proof)
			}
		}
		// Linker-recorded inline frames are executable code inside the reached physical parent. They carry their
		// logical source call chain even when optimization eliminated a standalone function range, so retain that
		// precise metadata rather than treating an optimized-away function as absent.
		for subject, index := range current.inlineMatches {
			if ctx.Err() != nil {
				return paths, false
			}
			if _, found := paths[subject]; found {
				continue
			}
			inlinePath, valid := inlineCallPath(ctx, current.inlineCalls, index)
			if !valid {
				return paths, false
			}
			proof := witness()
			if len(proof) == 0 || len(proof)+len(inlinePath) > maxWitnessDepth ||
				len(proof)+len(inlinePath) > remainingWitnessFrames {
				complete = false
				continue
			}
			paths[subject] = append(append([]string(nil), proof...), inlinePath...)
			remainingWitnessFrames -= len(proof) + len(inlinePath)
		}

		codeStart := current.entry - textAddress
		codeEnd := current.end - textAddress
		if codeEnd <= codeStart || codeEnd-codeStart > maxFunctionCodeBytes || codeEnd > uint64(len(text)) {
			complete = false
			continue
		}
		targets, decoded := directCallTargets(ctx, text[codeStart:codeEnd], current.entry)
		if !decoded {
			complete = false
		}
		if ctx.Err() != nil {
			return paths, false
		}
		for _, target := range targets {
			if ctx.Err() != nil {
				return paths, false
			}
			callee, exists := functions[target]
			if !exists || seen[target] {
				continue
			}
			if depths[current.entry] >= maxWitnessDepth {
				complete = false
				continue
			}
			seen[target] = true
			parents[target] = current.entry
			depths[target] = depths[current.entry] + 1
			queue = append(queue, callee)
		}
	}
	return paths, complete
}

// directCallTargets decodes an x86-64 function linearly and returns only E8 rel32 calls that begin on a decoded
// instruction boundary. It supports the compact instruction forms emitted by the Go Linux/amd64 compiler; an
// unfamiliar form stops this function at the last safe boundary instead of scanning arbitrary bytes for 0xe8.
func directCallTargets(ctx context.Context, code []byte, address uint64) ([]uint64, bool) {
	var targets []uint64
	for offset := 0; offset < len(code); {
		if ctx.Err() != nil {
			return targets, false
		}
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
	if opcode == 0xc4 || opcode == 0xc5 || opcode == 0x62 {
		return 0, 0, false, false // unsupported VEX/EVEX encodings must not expose payload bytes as instruction boundaries
	}
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
