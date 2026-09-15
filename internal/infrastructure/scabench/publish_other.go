//go:build !linux

package scabench

import (
	"fmt"
	"os"
)

func publishBundle(stage, output string) error {
	if _, err := os.Lstat(output); err == nil {
		return fmt.Errorf("output bundle already exists")
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect output bundle: %w", err)
	}
	if err := os.Rename(stage, output); err != nil {
		return fmt.Errorf("publish output bundle: %w", err)
	}
	return nil
}
