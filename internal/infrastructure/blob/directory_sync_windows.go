//go:build windows

package blob

import "os"

// Windows does not expose a portable Go operation for flushing directory
// metadata, and os.File.Sync on an opened directory returns access denied. The
// object file itself is flushed before the atomic publication link.
func syncDirectory(*os.File) error {
	return nil
}
