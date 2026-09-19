//go:build !linux

package benchcycle

import (
	"fmt"
	"os"
)

// PublishDirectory publishes a validated staged directory without replacing an existing path.
func PublishDirectory(stage, output string) error {
	if err := validatePublicationStage(stage); err != nil {
		return err
	}
	if err := EnsureAbsent(output, "output bundle"); err != nil {
		return err
	}
	if err := os.Rename(stage, output); err != nil {
		return fmt.Errorf("publish output bundle: %w", err)
	}
	return nil
}
