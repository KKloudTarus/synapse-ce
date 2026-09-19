//go:build !linux

package scabench

import "github.com/KKloudTarus/synapse-ce/internal/infrastructure/benchcycle"

func publishBundle(stage, output string) error {
	return benchcycle.PublishDirectory(stage, output)
}
