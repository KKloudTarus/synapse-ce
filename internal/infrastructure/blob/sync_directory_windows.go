//go:build windows

package blob

import "os"

// Windows does not permit fsync on a directory handle opened through os.Root.
// The object file itself is flushed before its atomic publication link is made.
func syncDirectory(*os.File) error {
	return nil
}
