package main

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/composition/sandboxcheck"
)

func TestCommandUsesConformancePolicy(t *testing.T) {
	r := sandboxcheck.Report{
		Strict: true,
		Checks: []sandboxcheck.CheckResult{
			sandboxcheck.PassResult("network", "network", "blocked"),
		},
	}
	if sandboxcheck.Failed(r) {
		t.Fatal("passing strict report must not fail")
	}
}
