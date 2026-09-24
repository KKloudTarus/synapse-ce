//go:build !linux

package scabench

import (
	"os"
	"path/filepath"
)

// openPinnedBundleFile keeps non-Linux builds compatible. CopyTo still verifies the opened descriptor is
// a regular file and rehashes it before accepting any bytes.
func openPinnedBundleFile(root, relative string) (*os.File, error) {
	return os.Open(filepath.Join(root, relative)) // #nosec G304 -- relative path is validated by the caller
}
