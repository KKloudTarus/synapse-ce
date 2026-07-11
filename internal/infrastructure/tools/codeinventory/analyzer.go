// Package codeinventory is a deterministic, pure-Go code-size inventory: it walks a source tree,
// classifies each file's language with go-enry, and counts code / comment / blank lines per language,
// plus functions where a first-party parser exists (Go today, via go/parser). It NEVER executes the
// target and reads bounded (skips vendored/binary/generated/oversized files, follows no symlinks),
// mirroring the go-enry and SAST library adapters. It is the Phase-0 producer of the code-quality
// capability; accurate multi-language function/complexity counting arrives with the AST phase.
package codeinventory

import (
	"bytes"
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	enry "github.com/go-enry/go-enry/v2"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	maxFileBytes = 4 << 20 // skip files larger than 4 MiB (generated/data, not hand-written source)
	maxFiles     = 200_000 // bound walk time on a hostile/huge tree
)

// skipDirs are heavy vendored/build trees never worth counting as first-party code.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true, "build": true,
	".venv": true, "venv": true, "__pycache__": true, "target": true, ".idea": true,
	".vscode": true, ".tox": true, ".hg": true, ".svn": true,
}

// Analyzer is the pure-Go code-inventory adapter. An optional ASTProvider (the synapse-ast sidecar)
// supplies accurate function counts for the non-Go languages it supports; without it, only Go function
// counts are known.
type Analyzer struct {
	provider ports.ASTProvider
}

// Option configures an Analyzer.
type Option func(*Analyzer)

// WithASTProvider wires an ASTProvider so function counts are filled for the languages it parses. A nil
// provider is ignored (the analyzer stays pure-Go, Go-only function counts).
func WithASTProvider(p ports.ASTProvider) Option {
	return func(a *Analyzer) { a.provider = p }
}

// New returns a new analyzer with the given options.
func New(opts ...Option) *Analyzer {
	a := &Analyzer{}
	for _, o := range opts {
		o(a)
	}
	return a
}

var _ ports.CodeInventoryScanner = (*Analyzer)(nil)

// Inventory walks root and returns a per-language code-size inventory. It honors ctx cancellation and
// never aborts the whole walk on a single unreadable file.
func (a *Analyzer) Inventory(ctx context.Context, root string) (measure.Inventory, error) {
	if root == "" {
		return measure.Inventory{}, nil
	}
	byLang := map[string]measure.LanguageInventory{}
	brokenFuncs := map[string]bool{} // a parser-supported language with an unparseable file: count is unreliable
	files := 0
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries; don't abort the whole inventory
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if path != root && skipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() { // never follow symlinks/devices
			return nil
		}
		if files++; files > maxFiles {
			return io.EOF // stop the walk; bounded
		}
		content, ok := readBounded(path)
		if !ok {
			return nil
		}
		base := filepath.Base(path)
		if enry.IsVendor(path) || enry.IsDotFile(path) || enry.IsGenerated(path, content) || enry.IsBinary(content) {
			return nil
		}
		lang := enry.GetLanguage(base, content)
		if lang == "" {
			return nil
		}
		switch enry.GetLanguageType(lang) {
		case enry.Programming, enry.Markup:
		default:
			return nil // skip data/prose/config-only languages for a code inventory
		}

		code, comment, blank := classifyLines(lang, content)
		li := byLang[lang]
		li.Language = lang
		li.Files++
		li.CodeLines += code
		li.CommentLines += comment
		li.BlankLines += blank
		if fn, supported, ok := countFunctions(lang, content); supported {
			li.FunctionsKnown = true // the language has a first-party parser
			if ok {
				li.Functions += fn
			} else {
				brokenFuncs[lang] = true // one file did not parse; the aggregate is an undercount
			}
		}
		byLang[lang] = li
		return nil
	})
	if walkErr != nil && walkErr != io.EOF {
		return measure.Inventory{}, walkErr
	}
	// Downgrade any language with an unparseable file to "not counted", so a reported count is never a
	// silent undercount (the doc promise: an accurate count, or FunctionsKnown=false).
	for lang := range brokenFuncs {
		li := byLang[lang]
		li.FunctionsKnown = false
		byLang[lang] = li
	}
	// If an AST provider (the synapse-ast sidecar) is wired and available, fill accurate function counts
	// for the languages it parses (e.g. Python/JavaScript/Java) – only for languages already present in
	// the inventory, so it never invents a language the walk did not see. Go stays on the in-process count.
	if a.provider != nil {
		counts, available, perr := a.provider.FunctionCounts(ctx, root)
		if perr != nil {
			return measure.Inventory{}, fmt.Errorf("ast provider: %w", perr)
		}
		if available {
			for lang, n := range counts {
				li, ok := byLang[lang]
				if !ok || li.FunctionsKnown {
					continue // language not in inventory, or already accurately counted in-process (Go)
				}
				li.Functions = n
				li.FunctionsKnown = true
				byLang[lang] = li
			}
		}
	}
	return measure.NewInventory(byLang), nil
}

// readBounded reads up to maxFileBytes of a regular file via Lstat (never follows a symlink out of the
// tree). ok=false on any miss (irregular, oversized, unreadable).
func readBounded(path string) ([]byte, bool) {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxFileBytes {
		return nil, false
	}
	b, err := os.ReadFile(path) // #nosec G304 -- regular file, size-capped via Lstat above, under the walked root
	if err != nil {
		return nil, false
	}
	return b, true
}

// commentSyntax describes a language's line- and block-comment delimiters for line classification.
type commentSyntax struct {
	line       []string
	blockStart string
	blockEnd   string
}

// syntaxByLang maps a go-enry language name to its comment syntax. Languages absent here have their
// comment lines counted as code (a conservative, documented default), never miscounted as blank.
var syntaxByLang = map[string]commentSyntax{
	"Go":         {line: []string{"//"}, blockStart: "/*", blockEnd: "*/"},
	"JavaScript": {line: []string{"//"}, blockStart: "/*", blockEnd: "*/"},
	"TypeScript": {line: []string{"//"}, blockStart: "/*", blockEnd: "*/"},
	"TSX":        {line: []string{"//"}, blockStart: "/*", blockEnd: "*/"},
	"JSX":        {line: []string{"//"}, blockStart: "/*", blockEnd: "*/"},
	"Java":       {line: []string{"//"}, blockStart: "/*", blockEnd: "*/"},
	"Kotlin":     {line: []string{"//"}, blockStart: "/*", blockEnd: "*/"},
	"Scala":      {line: []string{"//"}, blockStart: "/*", blockEnd: "*/"},
	"C":          {line: []string{"//"}, blockStart: "/*", blockEnd: "*/"},
	"C++":        {line: []string{"//"}, blockStart: "/*", blockEnd: "*/"},
	"C#":         {line: []string{"//"}, blockStart: "/*", blockEnd: "*/"},
	"Rust":       {line: []string{"//"}, blockStart: "/*", blockEnd: "*/"},
	"Swift":      {line: []string{"//"}, blockStart: "/*", blockEnd: "*/"},
	"Dart":       {line: []string{"//"}, blockStart: "/*", blockEnd: "*/"},
	"PHP":        {line: []string{"//", "#"}, blockStart: "/*", blockEnd: "*/"},
	"Python":     {line: []string{"#"}, blockStart: `"""`, blockEnd: `"""`},
	"Ruby":       {line: []string{"#"}, blockStart: "=begin", blockEnd: "=end"},
	"Shell":      {line: []string{"#"}},
	"YAML":       {line: []string{"#"}},
	"Perl":       {line: []string{"#"}},
	"SQL":        {line: []string{"--"}},
	"Lua":        {line: []string{"--"}},
	"HTML":       {blockStart: "<!--", blockEnd: "-->"},
	"XML":        {blockStart: "<!--", blockEnd: "-->"},
}

// classifyLines counts code, comment and blank lines. A blank line is whitespace-only. A line is a
// comment when it starts with a line-comment token or lies inside a block comment; a line with trailing
// code before a comment counts as code (standard cloc-style accounting). Deterministic, no allocation
// beyond the line split. Limitation (Phase 0): a block comment opened AFTER code on the same line
// (`foo() /* ...`) is not tracked, so its continuation lines count as code; the AST phase removes this.
func classifyLines(lang string, content []byte) (code, comment, blank int) {
	syn, hasSyntax := syntaxByLang[lang]
	inBlock := false
	lines := bytes.Split(content, []byte("\n"))
	// A trailing newline terminates the last line rather than starting a new (empty) one; drop that one
	// phantom empty field so a file ending in "\n" is not counted with an extra blank line.
	if n := len(lines); n > 0 && len(lines[n-1]) == 0 {
		lines = lines[:n-1]
	}
	for _, raw := range lines {
		t := strings.TrimSpace(string(raw))
		if t == "" {
			blank++
			continue
		}
		if !hasSyntax {
			code++ // unknown language: count non-blank as code (comments fold into code, never blank)
			continue
		}
		if inBlock {
			comment++
			if syn.blockEnd != "" && strings.Contains(t, syn.blockEnd) {
				inBlock = false
			}
			continue
		}
		if syn.blockStart != "" && strings.HasPrefix(t, syn.blockStart) {
			comment++
			// still open if the block-end does not appear after the opening token on this same line
			rest := t[len(syn.blockStart):]
			if syn.blockEnd != "" && !strings.Contains(rest, syn.blockEnd) {
				inBlock = true
			}
			continue
		}
		isLineComment := false
		for _, lc := range syn.line {
			if strings.HasPrefix(t, lc) {
				isLineComment = true
				break
			}
		}
		if isLineComment {
			comment++
			continue
		}
		code++
	}
	return code, comment, blank
}

// countFunctions counts functions for a language with a first-party parser. Go uses go/parser
// (top-level and method FuncDecls). supported=false for every other language until the AST phase (the
// caller then reports "not counted", never a wrong zero); ok=false when a supported language's file
// does not parse, so the caller can downgrade that language's whole count to not-known.
func countFunctions(lang string, content []byte) (n int, supported, ok bool) {
	if lang != "Go" {
		return 0, false, false
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", content, parser.SkipObjectResolution)
	if err != nil || f == nil {
		return 0, true, false // supported, but this file did not parse (e.g. a fragment)
	}
	for _, decl := range f.Decls {
		if _, ok := decl.(*ast.FuncDecl); ok {
			n++
		}
	}
	return n, true, true
}
