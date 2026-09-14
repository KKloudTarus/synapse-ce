//go:build unix

package runtimeevidence

import (
	"os"
	"syscall"

	"github.com/KKloudTarus/synapse-ce/internal/domain/runtimereach"
)

// fileID returns the filesystem identity (device + inode) of the file at abs, following symlinks (Stat, not
// Lstat) so a loaded symlink and the package's real file share the identity that makes the join
// misattribution-proof. ok is false when the file cannot be stat'd (gone, unreadable), which the join
// tolerates by falling back to a unique-path match.
func fileID(abs string) (runtimereach.FileID, bool) {
	info, err := os.Stat(abs)
	if err != nil {
		return runtimereach.FileID{}, false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return runtimereach.FileID{}, false
	}
	return runtimereach.FileID{Device: uint64(st.Dev), Inode: uint64(st.Ino)}, true
}
