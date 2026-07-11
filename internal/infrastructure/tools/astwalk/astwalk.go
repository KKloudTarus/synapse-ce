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

// ErrUnavailable is returned by FunctionsFor in a CGO-free build: no grammar backend is compiled in.
var ErrUnavailable = errors.New("astwalk: tree-sitter backend not available (built without cgo)")

// Result is the sidecar's wire output: accurate function counts keyed by go-enry language name.
// Truncated is set when the file-count cap tripped, so a caller can tell an undercount from a complete one.
type Result struct {
	Functions map[string]int `json:"functions"`
	Truncated bool           `json:"truncated,omitempty"`
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

// walk traverses root and calls parse(language, content) for each regular, non-vendored, non-binary
// source file, summing the returned per-file function counts by language. It follows no symlinks, bounds
// file size and count, and honors ctx cancellation, mirroring the codeinventory and enry adapters. parse
// returns (n, ok); ok=false when the language has no grammar, so that file contributes nothing.
func walk(ctx context.Context, root string, parse func(lang string, content []byte) (int, bool)) (Result, error) {
	res := Result{Functions: map[string]int{}}
	if root == "" {
		return res, nil
	}
	files := 0
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
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
			res.Truncated = true // signal the undercount rather than silently returning a partial result
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
		if n, ok := parse(lang, content); ok {
			res.Functions[lang] += n
		}
		return nil
	})
	if walkErr != nil {
		return Result{}, walkErr
	}
	return res, nil
}
