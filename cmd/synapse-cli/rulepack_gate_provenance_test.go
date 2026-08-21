package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRulePackGateRequiresEvidenceTrustKey(t *testing.T) {
	err := runRulePackGate([]string{"--artifact", "pack.json", "--public-key", "pack.pub", "--evidence", "evidence.json"})
	if err == nil || !strings.Contains(err.Error(), "--evidence-public-key") {
		t.Fatalf("missing evidence trust key error = %v", err)
	}
}

func TestRulePackGateRejectsRawUnattestedGateInput(t *testing.T) {
	artifact, pub := cliRulePack(t)
	dir := t.TempDir()
	artifactPath := filepath.Join(dir, "artifact.json")
	artifactBytes, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifactPath, artifactBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	packKeyPath := filepath.Join(dir, "pack.pub")
	evidenceKeyPath := filepath.Join(dir, "evidence.pub")
	keyBytes := []byte(base64.StdEncoding.EncodeToString(pub))
	if err := os.WriteFile(packKeyPath, keyBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(evidenceKeyPath, keyBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	evidencePath := filepath.Join(dir, "evidence.json")
	if err := os.WriteFile(evidencePath, []byte(`{"deployment":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err = runRulePackGate([]string{
		"--artifact", artifactPath,
		"--public-key", packKeyPath,
		"--evidence", evidencePath,
		"--evidence-public-key", evidenceKeyPath,
		"--phase", "pre-canary",
	})
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("raw GateInput must be rejected before evaluation, got %v", err)
	}
}
