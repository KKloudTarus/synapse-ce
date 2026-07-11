// Package astwalk is the source-tree walk + result model shared by the synapse-ast sidecar's CGO
// (tree-sitter) and CGO-free (stub) builds. The traversal, language detection and aggregation here are
// pure Go and build under any configuration; only the per-file parse step is language-aware and lives in
// the build-tagged parse_cgo.go / parse_nocgo.go files. Keeping tree-sitter behind the `cgo` build tag
// means `CGO_ENABLED=0 go build ./cmd/...` (the distroless-parity CI step) still compiles this binary.
package astwalk

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	enry "github.com/go-enry/go-enry/v2"
)

// ErrUnavailable is returned by the FunctionsFor/MetricsFor entry points in a CGO-free build: no grammar
// backend is compiled in.
var ErrUnavailable = errors.New("astwalk: tree-sitter backend not available (built without cgo)")

// Result is the `functions` wire output: accurate function counts keyed by go-enry language name.
// Truncated is set when the file-count cap tripped, so a caller can tell an undercount from a complete one.
type Result struct {
	Functions map[string]int `json:"functions"`
	Truncated bool           `json:"truncated,omitempty"`
}

// FunctionMetric is one function's size/complexity record. Line is 1-based; File is relative to the walk
// root. Cyclomatic is McCabe's measure (1 + decision points); Cognitive is the nesting-aware readability
// measure (see parse_cgo.go for the exact rules).
type FunctionMetric struct {
	File       string `json:"file"`
	Line       int    `json:"line"`
	Name       string `json:"name"`
	Language   string `json:"language"`
	Cyclomatic int    `json:"cyclomatic"`
	Cognitive  int    `json:"cognitive"`
}

// Metrics is the `metrics` wire output: one record per function.
type Metrics struct {
	Functions []FunctionMetric `json:"functions"`
	Truncated bool             `json:"truncated,omitempty"`
}

const (
	maxFileBytes = 4 << 20
	maxFiles     = 200_000
)

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true, "build": true,
	".venv": true, "venv": true, "__pycache__": true, "target": true, ".idea": true,
	".vscode": true, ".tox": true, ".hg": true, ".svn": true,
}

// walkSource traverses root and calls visit(rel, language, content) for each regular, non-vendored,
// non-binary source file (rel is the path relative to root). It follows no symlinks, bounds file size and
// count, and honors ctx cancellation, mirroring the codeinventory and enry adapters. truncated is true
// when the file cap tripped (a signalled undercount, not a silent one).
func walkSource(ctx context.Context, root string, visit func(rel, lang string, content []byte)) (truncated bool, err error) {
	if root == "" {
		return false, nil
	}
	files := 0
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return nil
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
		if !d.Type().IsRegular() {
			return nil
		}
		if files++; files > maxFiles {
			truncated = true
			return fs.SkipAll
		}
		fi, lerr := os.Lstat(path)
		if lerr != nil || !fi.Mode().IsRegular() || fi.Size() > maxFileBytes {
			return nil
		}
		content, rerr := os.ReadFile(path) // #nosec G304 -- regular file, size-capped via Lstat above, under the walked root
		if rerr != nil {
			return nil
		}
		if enry.IsVendor(path) || enry.IsDotFile(path) || enry.IsGenerated(path, content) || enry.IsBinary(content) {
			return nil
		}
		lang := enry.GetLanguage(filepath.Base(path), content)
		if lang == "" {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		visit(rel, lang, content)
		return nil
	})
	if walkErr != nil {
		return false, walkErr
	}
	return truncated, nil
}
