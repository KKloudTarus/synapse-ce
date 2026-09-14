// Package gobinreach implements RAISE-ONLY symbol reachability for COMPILED Go binaries (EPIC #1034 D4.8,
// #1038). It reads a Go binary's function symbol table (the `.gopclntab`) and returns the fully-qualified
// function names (`importPath.Func`, `importPath.(*Recv).Method`) it observes, for symreach's raise-only
// tail-match against an advisory's affected symbols.
//
// It is RAISE-ONLY by construction: the PRESENCE of a matched affected symbol raises a finding's urgency, but
// ABSENCE is NO COVERAGE, never not_reachable. A stripped binary, an inlined or dead-code-eliminated function,
// a non-Go binary, an object format it cannot read, or a malformed pclntab all contribute NOTHING (they are
// treated as no coverage), so the analyzer can never mint a false not_reachable and its proof actors are
// excluded from the deterministic-reachability set (a verdict here can never become an OpenVEX not_affected).
// Every read is panic-contained: a corrupt pclntab that makes debug/gosym panic is recovered and yields no
// coverage rather than crashing the scan.
package gobinreach

import (
	"bytes"
	"context"
	"debug/elf"
	"debug/gosym"
	"debug/macho"
	"debug/pe"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// scan limits bound the walk so a hostile or huge tree cannot exhaust time/memory. Real repos have a handful
// of binaries; exceeding these simply stops (no coverage), never a false verdict.
const (
	maxFilesWalked = 200_000
	maxBinaryBytes = 512 << 20 // a 512 MiB cap on a candidate binary read
)

// skipDir prunes VCS and dependency-cache directories that never hold a first-party build artifact.
var skipDir = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".hg": true, ".svn": true,
}

// GoBinarySymbolScanner satisfies symreach.SymbolReferenceScanner by walking a directory for compiled Go
// binaries and returning the function symbols in their `.gopclntab`.
type GoBinarySymbolScanner struct{}

// New returns a Go-binary symbol scanner.
func New() *GoBinarySymbolScanner { return &GoBinarySymbolScanner{} }

// ScanSymbolRefs walks dir for compiled Go binaries and returns the sorted, de-duplicated set of
// fully-qualified function names in their symbol tables. A file that is not a Go binary, is stripped, or has a
// malformed pclntab contributes nothing. It never returns an error for a per-file read failure (that would be
// indistinguishable from coverage-with-absence); it only errors on an unusable directory argument.
func (s *GoBinarySymbolScanner) ScanSymbolRefs(ctx context.Context, dir string) ([]string, error) {
	seen := map[string]bool{}
	files := 0
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // an unreadable entry is skipped, not fatal (raise-only: a miss forgoes a raise)
		}
		if ctx.Err() != nil {
			return ctx.Err()
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
		for _, name := range symbolsFromGoBinary(path) {
			seen[name] = true
		}
		return nil
	})
	if len(seen) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

// symbolsFromGoBinary returns the `.gopclntab` function names of the Go binary at path, or nil for anything
// that is not a readable Go binary (a non-binary, a stripped binary, an unsupported format, a malformed
// pclntab). It is panic-contained: a corrupt pclntab that makes debug/gosym panic yields nil, never a crash.
func symbolsFromGoBinary(path string) (names []string) {
	defer func() {
		if recover() != nil {
			names = nil // a debug/gosym panic on a malformed table is no coverage, never a crash
		}
	}()
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() < 4 || fi.Size() > maxBinaryBytes {
		return nil
	}
	magic := make([]byte, 4)
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	n, _ := f.Read(magic)
	f.Close()
	if n < 4 || !looksLikeObject(magic) { // cheap pre-filter so we don't open every source file as a binary
		return nil
	}
	pclntab, textStart, ok := goPclntab(path)
	if !ok || len(pclntab) == 0 {
		return nil // not a Go binary, or stripped of its pclntab -> no coverage (never not_reachable)
	}
	lt := gosym.NewLineTable(pclntab, textStart)
	table, err := gosym.NewTable(nil, lt) // modern Go carries func names in the pclntab; the symtab may be empty
	if err != nil || table == nil {
		return nil
	}
	for i := range table.Funcs {
		if fn := strings.TrimSpace(table.Funcs[i].Name); fn != "" {
			names = append(names, fn)
		}
	}
	return names
}

// looksLikeObject reports whether the first bytes are a known executable/object magic (ELF, Mach-O 32/64 or
// universal, or PE/COFF "MZ"), so a plain source file is never opened as a binary.
func looksLikeObject(magic []byte) bool {
	switch {
	case bytes.HasPrefix(magic, []byte("\x7fELF")):
		return true
	case bytes.HasPrefix(magic, []byte("MZ")):
		return true
	}
	switch string(magic) {
	case "\xfe\xed\xfa\xce", "\xfe\xed\xfa\xcf", "\xce\xfa\xed\xfe", "\xcf\xfa\xed\xfe", // Mach-O 32/64 both-endian
		"\xca\xfe\xba\xbe", "\xbe\xba\xfe\xca": // Mach-O universal (fat)
		return true
	}
	return false
}

// goPclntab extracts the .gopclntab bytes and the text-segment start address from a binary in any of the
// three object formats. ok is false when the format is unreadable or has no pclntab section (a non-Go or
// stripped binary).
func goPclntab(path string) (pclntab []byte, textStart uint64, ok bool) {
	if ef, err := elf.Open(path); err == nil {
		defer ef.Close()
		sec := ef.Section(".gopclntab")
		if sec == nil {
			return nil, 0, false
		}
		data, err := sec.Data()
		if err != nil {
			return nil, 0, false
		}
		var text uint64
		if t := ef.Section(".text"); t != nil {
			text = t.Addr
		}
		return data, text, true
	}
	if mf, err := macho.Open(path); err == nil {
		defer mf.Close()
		sec := mf.Section("__gopclntab")
		if sec == nil {
			return nil, 0, false
		}
		data, err := sec.Data()
		if err != nil {
			return nil, 0, false
		}
		var text uint64
		if t := mf.Section("__text"); t != nil {
			text = t.Addr
		}
		return data, text, true
	}
	if pf, err := pe.Open(path); err == nil {
		defer pf.Close()
		sec := pf.Section(".gopclntab")
		if sec == nil {
			// A PE Go binary may keep the table under the runtime.pclntab symbol rather than a named section;
			// that path needs symbol resolution and is left as no coverage here (raise-only tolerates the miss).
			return nil, 0, false
		}
		data, err := sec.Data()
		if err != nil {
			return nil, 0, false
		}
		var imageBase uint64
		switch h := pf.OptionalHeader.(type) {
		case *pe.OptionalHeader32:
			imageBase = uint64(h.ImageBase)
		case *pe.OptionalHeader64:
			imageBase = h.ImageBase
		}
		var text uint64
		if t := pf.Section(".text"); t != nil {
			text = imageBase + uint64(t.VirtualAddress)
		}
		return data, text, true
	}
	return nil, 0, false
}
