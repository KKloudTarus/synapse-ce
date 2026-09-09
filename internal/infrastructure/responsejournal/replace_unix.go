//go:build !windows

package responsejournal

import "os"

func replaceFile(oldPath, newPath string) error { return os.Rename(oldPath, newPath) }
