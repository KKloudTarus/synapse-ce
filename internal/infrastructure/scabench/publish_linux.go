//go:build linux

package scabench

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func publishBundle(stage, output string) error {
	if err := unix.Renameat2(unix.AT_FDCWD, stage, unix.AT_FDCWD, output, unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("publish output bundle without overwrite: %w", err)
	}
	return nil
}
