// Package gobinreach provides raise-only reachability evidence from compiled Go binaries.
// It reads Go function metadata and proves direct-call paths from main.main to version-bound affected symbols.
//
// Unproven paths provide no coverage and cannot produce a not_reachable or OpenVEX not_affected verdict.
// Malformed function metadata yields no coverage instead of crashing the scan.
package gobinreach

import (
	"bytes"
	"context"
	"debug/elf"
	"debug/gosym"
	"debug/macho"
	"debug/pe"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// scan limits bound the walk so a hostile or huge tree cannot exhaust time/memory. Real repos have a handful
// of binaries; exceeding these simply stops (no coverage), never a false verdict.
const (
	maxWalkEntries = 200_000
	maxBinaryBytes = 512 << 20 // a 512 MiB cap on a candidate binary read
	maxPCLNBytes   = 64 << 20  // bound section decompression before reading untrusted metadata
	maxTextBytes   = 128 << 20
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
	walkErr := walkBoundedRegularFiles(ctx, dir, maxWalkEntries, func(path string) error {
		for _, name := range symbolsFromGoBinary(ctx, path) {
			seen[name] = true
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	if len(seen) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

// walkBoundedRegularFiles reads at most limit+1 entries from any directory before sorting it.
// This keeps a single adversarial directory from making filepath.WalkDir allocate for millions
// of names before its callback can apply a limit. An oversized or unreadable directory has no
// coverage; completed earlier paths remain valid positive evidence.
func walkBoundedRegularFiles(ctx context.Context, root string, limit int, visit func(string) error) error {
	if limit <= 0 {
		return nil
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return nil
	}
	type item struct {
		path  string
		entry fs.DirEntry
	}
	stack := []item{{path: root, entry: fs.FileInfoToDirEntry(rootInfo)}}
	discovered := 1
	for len(stack) != 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if current.entry.IsDir() {
			if current.path != root && skipDir[current.entry.Name()] {
				continue
			}
			folder, err := os.Open(current.path)
			if err != nil {
				continue
			}
			remaining := limit - discovered
			children, readErr := folder.ReadDir(remaining + 1)
			_ = folder.Close()
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				continue
			}
			if len(children) > remaining {
				return nil
			}
			discovered += len(children)
			sort.Slice(children, func(left, right int) bool { return children[left].Name() < children[right].Name() })
			for index := len(children) - 1; index >= 0; index-- {
				stack = append(stack, item{path: filepath.Join(current.path, children[index].Name()), entry: children[index]})
			}
			continue
		}
		if current.entry.Type().IsRegular() {
			if err := visit(current.path); err != nil {
				return err
			}
		}
	}
	return nil
}

// symbolsFromGoBinary returns the `.gopclntab` function names of the Go binary at path, or nil for anything
// that is not a readable Go binary (a non-binary, a stripped binary, an unsupported format, a malformed
// pclntab). It is panic-contained: a corrupt pclntab that makes debug/gosym panic yields nil, never a crash.
func symbolsFromGoBinary(ctx context.Context, path string) (names []string) {
	defer func() {
		if recover() != nil {
			names = nil // a debug/gosym panic on a malformed table is no coverage, never a crash
		}
	}()
	if ctx.Err() != nil {
		return nil
	}
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() < 4 || fi.Size() > maxBinaryBytes || ctx.Err() != nil {
		return nil
	}
	magic := make([]byte, 4)
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	n, _ := f.Read(magic)
	_ = f.Close()
	if ctx.Err() != nil {
		return nil
	}
	if n < 4 || !looksLikeObject(magic) { // cheap pre-filter so we don't open every source file as a binary
		return nil
	}
	pclntab, textStart, ok := goPclntab(ctx, path)
	if !ok || len(pclntab) == 0 || !boundedPCLNFunctionNames(pclntab) || ctx.Err() != nil {
		return nil // not a Go binary, or stripped of its pclntab -> no coverage (never not_reachable)
	}
	lt := gosym.NewLineTable(pclntab, textStart)
	table, err := gosym.NewTable(nil, lt) // modern Go carries func names in the pclntab; the symtab may be empty
	if err != nil || table == nil || ctx.Err() != nil {
		return nil
	}
	for i := range table.Funcs {
		if ctx.Err() != nil {
			return nil
		}
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
func goPclntab(ctx context.Context, path string) (pclntab []byte, textStart uint64, ok bool) {
	if ctx.Err() != nil {
		return nil, 0, false
	}
	if file, err := os.Open(path); err == nil {
		defer func() { _ = file.Close() }()
		var magic [4]byte
		if _, readErr := file.ReadAt(magic[:], 0); readErr != nil {
			return nil, 0, false
		}
		if string(magic[:]) == "\x7fELF" {
			info, statErr := file.Stat()
			if statErr != nil || !info.Mode().IsRegular() || !preflightELF(file, info.Size()) {
				return nil, 0, false
			}
			ef, parseErr := elf.NewFile(file)
			if parseErr != nil {
				return nil, 0, false
			}
			defer func() { _ = ef.Close() }()
			if ctx.Err() != nil {
				return nil, 0, false
			}
			sec := ef.Section(".gopclntab")
			if sec == nil || sec.Size == 0 || sec.Size > maxPCLNBytes ||
				sec.Flags&elf.SHF_ALLOC == 0 || sec.Flags&elf.SHF_COMPRESSED != 0 {
				return nil, 0, false
			}
			data, err := sec.Data()
			if err != nil || ctx.Err() != nil {
				return nil, 0, false
			}
			var text uint64
			if t := ef.Section(".text"); t != nil {
				text = t.Addr
			}
			return data, text, true
		}
	}
	if ctx.Err() != nil {
		return nil, 0, false
	}
	if mf, err := macho.Open(path); err == nil {
		defer func() { _ = mf.Close() }()
		if ctx.Err() != nil {
			return nil, 0, false
		}
		sec := mf.Section("__gopclntab")
		if sec == nil || sec.Size == 0 || sec.Size > maxPCLNBytes {
			return nil, 0, false
		}
		data, err := sec.Data()
		if err != nil || ctx.Err() != nil {
			return nil, 0, false
		}
		var text uint64
		if t := mf.Section("__text"); t != nil {
			text = t.Addr
		}
		return data, text, true
	}
	if ctx.Err() != nil {
		return nil, 0, false
	}
	if pf, err := pe.Open(path); err == nil {
		defer func() { _ = pf.Close() }()
		if ctx.Err() != nil {
			return nil, 0, false
		}
		sec := pf.Section(".gopclntab")
		if sec == nil || sec.Size == 0 || sec.Size > maxPCLNBytes {
			// A PE Go binary may keep the table under the runtime.pclntab symbol rather than a named section;
			// that path needs symbol resolution and is left as no coverage here (raise-only tolerates the miss).
			return nil, 0, false
		}
		data, err := sec.Data()
		if err != nil || ctx.Err() != nil {
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
