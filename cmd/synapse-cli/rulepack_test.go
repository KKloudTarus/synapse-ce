package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	rulepackdomain "github.com/KKloudTarus/synapse-ce/internal/domain/rulepack"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func cliRulePack(t *testing.T) (rulepackdomain.SignedArtifact, ed25519.PublicKey) {
	t.Helper()
	now := time.Unix(1_700_000_000, 0).UTC()
	rule := detection.Rule{
		ID: "det.cli", Version: 1, Class: detection.ClassProcess, Title: "cli test", Severity: shared.SeverityHigh,
		Matcher: detection.Matcher{Class: detection.ClassProcess, All: []detection.Predicate{{Field: detection.FieldProcComm, Op: detection.OpEquals, Value: "tool"}}},
	}
	positive := detection.Event{Class: detection.ClassProcess, At: now, Host: "h1", Process: &detection.ProcessEvent{Comm: "tool"}}
	negative := detection.Event{Class: detection.ClassProcess, At: now, Host: "h1", Process: &detection.ProcessEvent{Comm: "safe"}}
	pack, err := rulepackdomain.New(rulepackdomain.RulePack{
		ID: "cli-pack", Version: 1, Rules: []detection.Rule{rule}, MinAgentVersion: "1.0.0",
		RequiredSchemaVersions: []int{1},
		RequiredSensors:        []rulepackdomain.SensorRequirement{{ID: "ebpf", MinVersion: "1.0.0"}},
		RequiredFields:         []detection.Field{detection.FieldProcComm},
		ATTACKMappings:         []rulepackdomain.ATTACKMapping{{RuleID: "det.cli", TechniqueID: "T1059"}},
		PositiveFixtures:       []rulepackdomain.Fixture{{ID: "positive", Event: positive, ExpectedRuleIDs: []string{"det.cli"}}},
		NegativeFixtures:       []rulepackdomain.Fixture{{ID: "negative", Event: negative}},
		ExpectedCost:           []rulepackdomain.RuleCostBudget{{RuleID: "det.cli", MaxLatencyMicros: 100, MaxCPUMicrosPerHostDay: 1000}},
		RolloutCohort:          []string{"canary"},
	})
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := rulepackdomain.Sign(priv, *pack)
	if err != nil {
		t.Fatal(err)
	}
	return artifact, pub
}

func TestDecodeRulePackJSONFileIsStrictAndBounded(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	if err := os.WriteFile(good, []byte(`{"value":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Value int `json:"value"`
	}
	if err := decodeRulePackJSONFile(good, 64, &got); err != nil || got.Value != 1 {
		t.Fatalf("strict decode = %+v, %v", got, err)
	}
	unknown := filepath.Join(dir, "unknown.json")
	if err := os.WriteFile(unknown, []byte(`{"value":1,"extra":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := decodeRulePackJSONFile(unknown, 64, &got); err == nil {
		t.Fatal("unknown JSON field must fail")
	}
	trailing := filepath.Join(dir, "trailing.json")
	if err := os.WriteFile(trailing, []byte(`{"value":1} {}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := decodeRulePackJSONFile(trailing, 64, &got); err == nil {
		t.Fatal("trailing JSON content must fail")
	}
	oversized := filepath.Join(dir, "oversized.json")
	if err := os.WriteFile(oversized, []byte(`{"value":12345}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := decodeRulePackJSONFile(oversized, 4, &got); err == nil {
		t.Fatal("input beyond the read bound must fail")
	}
}

func TestLoadVerifiedRulePackPinsExternalPublicKey(t *testing.T) {
	artifact, pub := cliRulePack(t)
	dir := t.TempDir()
	artifactPath := filepath.Join(dir, "artifact.json")
	data, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifactPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "trusted.pub")
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, trusted, err := loadVerifiedRulePack(artifactPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Pack.Digest != artifact.Pack.Digest || string(trusted) != string(pub) {
		t.Fatal("verified artifact/key changed while loading")
	}
	wrongPub, _, _ := ed25519.GenerateKey(nil)
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(wrongPub)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadVerifiedRulePack(artifactPath, keyPath); err == nil {
		t.Fatal("artifact must not trust a different externally pinned key")
	}
}

func TestRulePackGatePhaseRequiresLifecycleState(t *testing.T) {
	tests := []struct {
		phase string
		state rulepackdomain.DeploymentState
		want  bool
	}{
		{phase: "pre-canary", state: rulepackdomain.DeploymentCandidate, want: true},
		{phase: "pre-canary", state: rulepackdomain.DeploymentCanary, want: false},
		{phase: "canary", state: rulepackdomain.DeploymentCanary, want: true},
		{phase: "canary", state: rulepackdomain.DeploymentCandidate, want: false},
		{phase: "promotion", state: rulepackdomain.DeploymentCanary, want: true},
		{phase: "promotion", state: rulepackdomain.DeploymentCandidate, want: false},
		{phase: "promotion", state: rulepackdomain.DeploymentPromoted, want: false},
		{phase: "unknown", state: rulepackdomain.DeploymentCanary, want: false},
	}
	for _, tt := range tests {
		if got := rulePackGatePhaseAcceptsState(tt.phase, tt.state); got != tt.want {
			t.Errorf("phase %q state %q accepted=%t, want %t", tt.phase, tt.state, got, tt.want)
		}
	}
}
