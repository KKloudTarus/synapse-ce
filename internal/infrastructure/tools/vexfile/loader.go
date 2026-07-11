// Package vexfile loads an in-repo OpenVEX document (.synapse.vex.json) from a prepared workspace. It is the
// thin infrastructure adapter over the pure domain parser (internal/domain/vex): read the file, hand the
// bytes to vex.Parse. Matching statements to findings and applying them (annotate accepted-risk, never
// remove) is the SCA pipeline's job.
package vexfile

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vex"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	fileName = ".synapse.vex.json"
	maxBytes = 8 << 20 // an in-repo VEX doc is small; cap the read defensively
)

// Loader reads <workspace>/.synapse.vex.json.
type Loader struct{}

var _ ports.VEXLoader = (*Loader)(nil)

// New returns a loader.
func New() *Loader { return &Loader{} }

// Load reads and parses <dir>/.synapse.vex.json. A missing or non-regular file is an empty document with no
// error (nothing to apply). An oversized file, or one that isn't a valid OpenVEX document, returns an error
// the caller surfaces – so a malformed VEX is visible, and fail-safe (no assertions applied → nothing
// suppressed).
func (l *Loader) Load(_ context.Context, dir string) (vex.Document, error) {
	path := filepath.Join(dir, fileName)
	// Lstat + IsRegular: never follow a .synapse.vex.json symlink out of the (untrusted) workspace.
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return vex.Document{}, nil // absent or non-regular → empty, no error
	}
	if info.Size() > maxBytes {
		return vex.Document{}, fmt.Errorf("%w: .synapse.vex.json exceeds %d bytes", shared.ErrValidation, maxBytes)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- fixed filename under the prepared workspace, guarded regular (non-symlink) via the Lstat above
	if err != nil {
		return vex.Document{}, fmt.Errorf("read .synapse.vex.json: %w", err) // surfaced as a SourceWarning, not swallowed
	}
	return vex.Parse(data)
}
