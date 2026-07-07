// Package ignorefile loads a repo-committed .synapseignore suppression policy from a prepared workspace.
// It is the thin infrastructure adapter over the pure domain parser (internal/domain/ignore): read the
// file, hand the bytes to the parser. Reading one fixed file is all it does; the policy semantics live in
// the domain and the application of the policy lives in the SCA pipeline.
package ignorefile

import (
	"context"
	"os"
	"path/filepath"

	"github.com/KKloudTarus/synapse-ce/internal/domain/ignore"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	fileName = ".synapseignore"
	maxBytes = 1 << 20 // an accepted-risk policy is small; cap the read defensively
)

// Loader reads <workspace>/.synapseignore.
type Loader struct{}

var _ ports.SuppressionLoader = (*Loader)(nil)

// New returns a loader.
func New() *Loader { return &Loader{} }

// Load reads and parses <dir>/.synapseignore. A missing, non-regular, oversized, or unreadable file is a
// silent empty policy (never a scan failure) — accepted risk that can't be read simply isn't applied.
func (l *Loader) Load(_ context.Context, dir string) (ignore.Set, error) {
	path := filepath.Join(dir, fileName)
	// Lstat + IsRegular: never follow a .synapseignore symlink out of the (untrusted) workspace.
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxBytes {
		return nil, nil
	}
	data, err := os.ReadFile(path) // #nosec G304 -- fixed filename under the prepared workspace, re-verified regular via Lstat
	if err != nil {
		return nil, nil
	}
	return ignore.Parse(data), nil
}
