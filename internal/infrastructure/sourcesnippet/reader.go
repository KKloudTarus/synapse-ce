// Package sourcesnippet reads a bounded source excerpt from a scanned workspace for the AI false-positive
// triage. It is the concrete ports.SourceSnippetReader; the fs read lives here (infrastructure), never in
// the usecase layer.
package sourcesnippet

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// maxSnippetFileBytes bounds how much of a source file is read for a snippet. A source file a scanner
// already parsed is small, so this is defense-in-depth against a pathological/huge file, not a real limit.
const maxSnippetFileBytes = 8 << 20 // 8 MiB

// Reader reads snippets from files under Root (the Synapse-controlled scanned tree).
type Reader struct{ Root string }

var _ ports.SourceSnippetReader = Reader{}

// Snippet returns the [line-radius, line+radius] window of the file (1-based), each line prefixed with its
// number. Symlinks are resolved and the read is contained inside Root (defense-in-depth: the path is our
// own finding's, but a link inside the tree must not point outside), the read is size-capped, and ctx is
// honored.
func (r Reader) Snippet(ctx context.Context, file string, line, radius int) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	p := filepath.Join(r.Root, filepath.FromSlash(file))
	root, err := filepath.EvalSymlinks(r.Root)
	if err != nil {
		root = r.Root
	}
	rp, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", err // missing/broken file → the coordinator critiques on metadata only
	}
	rel, err := filepath.Rel(root, rp)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("snippet path escapes scan root")
	}
	f, err := os.Open(rp)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxSnippetFileBytes))
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(data), "\n")
	lo := line - radius
	if lo < 1 {
		lo = 1
	}
	hi := line + radius
	if hi > len(lines) {
		hi = len(lines)
	}
	var b strings.Builder
	for i := lo; i <= hi; i++ {
		fmt.Fprintf(&b, "%d: %s\n", i, lines[i-1])
	}
	return b.String(), nil
}
