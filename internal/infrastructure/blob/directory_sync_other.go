//go:build !windows

package blob

import "os"

func syncDirectory(directory *os.File) error {
	return directory.Sync()
}
