package scabench

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type cyclePolicy struct {
	SchemaVersion                      string `json:"schema_version"`
	Repetitions                        int    `json:"repetitions"`
	MaxAttempts                        int    `json:"max_attempts"`
	RawRetention                       string `json:"raw_retention"`
	AcceptedArtifactRetentionDays      int    `json:"accepted_artifact_retention_days"`
	FailedAttemptArtifactRetentionDays int    `json:"failed_attempt_artifact_retention_days"`
}

func TestCheckedInCyclePolicyLeavesMatrixDerivationToMaterialization(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve cycle policy path")
	}
	body, err := os.ReadFile(filepath.Join(filepath.Dir(source), "corpus", "cycle-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	var policy cyclePolicy
	if err := strictDecode(bytes.NewReader(body), &policy); err != nil {
		t.Fatalf("decode cycle policy: %v", err)
	}
	if policy.SchemaVersion != "synapse-sca-benchmark-cycle-policy-v1" {
		t.Fatalf("cycle policy schema = %q", policy.SchemaVersion)
	}
	if policy.Repetitions != 2 || policy.MaxAttempts != 3 {
		t.Fatalf("cycle repetitions/attempts = %d/%d, want 2/3", policy.Repetitions, policy.MaxAttempts)
	}
	if policy.RawRetention != "delete_after_verification" || policy.AcceptedArtifactRetentionDays != 90 || policy.FailedAttemptArtifactRetentionDays != 3 {
		t.Fatalf("cycle retention policy = %+v", policy)
	}
}
