package main

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
)

func TestExplicitJudgmentScannerEnvKeyPrefersEnabledJVM(t *testing.T) {
	t.Setenv("SYNAPSE_JVM_REACHABILITY_ENABLED", "true")

	got := explicitJudgmentScannerEnvKey(config.Config{JVMReachabilityEnabled: true})
	if got != "SYNAPSE_JVM_REACHABILITY_ENABLED" {
		t.Fatalf("explicitJudgmentScannerEnvKey() = %q, want JVM reachability key", got)
	}
}

func TestExplicitJudgmentScannerEnvKeyIgnoresDisabledJVM(t *testing.T) {
	t.Setenv("SYNAPSE_JVM_REACHABILITY_ENABLED", "false")

	got := explicitJudgmentScannerEnvKey(config.Config{JVMReachabilityEnabled: false})
	if got == "SYNAPSE_JVM_REACHABILITY_ENABLED" {
		t.Fatalf("explicitJudgmentScannerEnvKey() = %q for disabled JVM reachability", got)
	}
}
