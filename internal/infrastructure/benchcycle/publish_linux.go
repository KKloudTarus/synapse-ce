//go:build linux

package benchcycle

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// PublishDirectory atomically publishes a validated staged directory without overwrite.
func PublishDirectory(stage, output string) error {
	if err := validatePublicationStage(stage); err != nil {
		return err
	}
	if err := unix.Renameat2(unix.AT_FDCWD, stage, unix.AT_FDCWD, output, unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("publish output bundle without overwrite: %w", err)
	}
	return nil
}
