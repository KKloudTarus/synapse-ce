//go:build !unix

package runtimeevidence

import "github.com/KKloudTarus/synapse-ce/internal/domain/runtimereach"

// fileID has no portable filesystem-identity source off Unix, so it reports none; the join falls back to a
// unique-path match. Runtime evidence is a Linux-host concern, so this path is only reached by a
// cross-compiled build's tests.
func fileID(string) (runtimereach.FileID, bool) { return runtimereach.FileID{}, false }
