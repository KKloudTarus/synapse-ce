package main

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/testutil/gobinbenchmark"
)

func TestCurrentGoBinaryBindingBenchmark(t *testing.T) {
	gobinbenchmark.Run(t, "worker", installGoBinaryReachability)
}
