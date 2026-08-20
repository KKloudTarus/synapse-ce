package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	rulepackdomain "github.com/KKloudTarus/synapse-ce/internal/domain/rulepack"
	rulepackuc "github.com/KKloudTarus/synapse-ce/internal/usecase/rulepack"
)

const (
	maxRulePackCLIBytes = int64(128 << 20)
	maxRulePackKeyBytes = int64(4096)
)

func runRulePack(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: synapse-cli rulepack verify|replay|gate")
	}
	switch args[0] {
	case "verify":
		return runRulePackVerify(args[1:])
	case "replay":
		return runRulePackReplay(args[1:])
	case "gate":
		return runRulePackGate(args[1:])
	default:
		return fmt.Errorf("unknown rulepack subcommand %q (want verify|replay|gate)", args[0])
	}
}

func runRulePackVerify(args []string) error {
	fs := flag.NewFlagSet("rulepack verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	artifactPath := fs.String("artifact", "", "signed RulePack artifact JSON")
	keyPath := fs.String("public-key", "", "trusted Ed25519 public key, base64 text")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || strings.TrimSpace(*artifactPath) == "" || strings.TrimSpace(*keyPath) == "" {
		return fmt.Errorf("usage: synapse-cli rulepack verify --artifact FILE --public-key FILE")
	}
	artifact, _, err := loadVerifiedRulePack(*artifactPath, *keyPath)
	if err != nil {
		return err
	}
	return writeRulePackJSON(struct {
		Verified bool   `json:"verified"`
		PackID   string `json:"pack_id"`
		Version  int    `json:"version"`
		Digest   string `json:"digest"`
		KeyID    string `json:"key_id"`
	}{true, artifact.Pack.ID, artifact.Pack.Version, artifact.Pack.Digest, artifact.KeyID})
}

func runRulePackReplay(args []string) error {
	fs := flag.NewFlagSet("rulepack replay", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	artifactPath := fs.String("artifact", "", "signed RulePack artifact JSON")
	keyPath := fs.String("public-key", "", "trusted Ed25519 public key, base64 text")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || strings.TrimSpace(*artifactPath) == "" || strings.TrimSpace(*keyPath) == "" {
		return fmt.Errorf("usage: synapse-cli rulepack replay --artifact FILE --public-key FILE")
	}
	artifact, _, err := loadVerifiedRulePack(*artifactPath, *keyPath)
	if err != nil {
		return err
	}
	results, err := rulepackdomain.Replay(artifact.Pack)
	if err != nil {
		return err
	}
	if err := writeRulePackJSON(results); err != nil {
		return err
	}
	for _, result := range results {
		if !result.Pass {
			return fmt.Errorf("rulepack replay failed: fixture %s did not match its expected detections", result.FixtureID)
		}
	}
	return nil
}

func runRulePackGate(args []string) error {
	fs := flag.NewFlagSet("rulepack gate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	artifactPath := fs.String("artifact", "", "signed RulePack artifact JSON")
	keyPath := fs.String("public-key", "", "trusted RulePack Ed25519 public key, base64 text")
	evidencePath := fs.String("evidence", "", "attested RulePack gate-evidence JSON")
	evidenceKeyPath := fs.String("evidence-public-key", "", "trusted gate-evidence collector Ed25519 public key, base64 text")
	phase := fs.String("phase", "promotion", "release phase: pre-canary|canary|promotion")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || strings.TrimSpace(*artifactPath) == "" || strings.TrimSpace(*keyPath) == "" || strings.TrimSpace(*evidencePath) == "" || strings.TrimSpace(*evidenceKeyPath) == "" {
		return fmt.Errorf("usage: synapse-cli rulepack gate --artifact FILE --public-key FILE --evidence FILE --evidence-public-key FILE [--phase pre-canary|canary|promotion]")
	}
	if *phase != "pre-canary" && *phase != "canary" && *phase != "promotion" {
		return fmt.Errorf("--phase must be pre-canary, canary, or promotion")
	}
	artifact, _, err := loadVerifiedRulePack(*artifactPath, *keyPath)
	if err != nil {
		return err
	}
	var signedEvidence rulepackuc.SignedGateEvidence
	if err := decodeRulePackJSONFile(*evidencePath, maxRulePackCLIBytes, &signedEvidence); err != nil {
		return fmt.Errorf("load attested rulepack gate evidence: %w", err)
	}
	evidencePub, err := loadEd25519PublicKey(*evidenceKeyPath, "rulepack gate-evidence")
	if err != nil {
		return err
	}
	input, err := rulepackuc.VerifyGateEvidence(signedEvidence, artifact.Pack, evidencePub)
	if err != nil {
		return fmt.Errorf("verify rulepack gate evidence: %w", err)
	}
	report, err := rulepackuc.Evaluate(artifact.Pack, input)
	if err != nil {
		return err
	}
	if err := writeRulePackJSON(report); err != nil {
		return err
	}
	if !rulePackGatePhaseAcceptsState(*phase, input.Deployment.State) {
		return fmt.Errorf("rulepack %s gate requires deployment state %q, got %q", *phase, rulePackGateRequiredState(*phase), input.Deployment.State)
	}
	var passed bool
	switch *phase {
	case "pre-canary":
		passed = report.PreCanaryPassed
	case "canary":
		passed = report.CanaryPassed
	case "promotion":
		passed = report.Passed
	}
	if !passed {
		return fmt.Errorf("rulepack %s gate failed", *phase)
	}
	return nil
}

func rulePackGateRequiredState(phase string) rulepackdomain.DeploymentState {
	switch phase {
	case "pre-canary":
		return rulepackdomain.DeploymentCandidate
	case "canary", "promotion":
		return rulepackdomain.DeploymentCanary
	default:
		return ""
	}
}

func rulePackGatePhaseAcceptsState(phase string, state rulepackdomain.DeploymentState) bool {
	required := rulePackGateRequiredState(phase)
	return required != "" && state == required
}

func loadVerifiedRulePack(artifactPath, keyPath string) (rulepackdomain.SignedArtifact, ed25519.PublicKey, error) {
	var artifact rulepackdomain.SignedArtifact
	if err := decodeRulePackJSONFile(artifactPath, maxRulePackCLIBytes, &artifact); err != nil {
		return rulepackdomain.SignedArtifact{}, nil, fmt.Errorf("load signed rulepack: %w", err)
	}
	trusted, err := loadRulePackPublicKey(keyPath)
	if err != nil {
		return rulepackdomain.SignedArtifact{}, nil, err
	}
	if err := rulepackdomain.Verify(artifact, trusted); err != nil {
		return rulepackdomain.SignedArtifact{}, nil, fmt.Errorf("verify signed rulepack: %w", err)
	}
	return artifact, trusted, nil
}

func loadRulePackPublicKey(path string) (ed25519.PublicKey, error) {
	return loadEd25519PublicKey(path, "rulepack")
}

func loadEd25519PublicKey(path, purpose string) (ed25519.PublicKey, error) {
	data, err := readRulePackBounded(path, maxRulePackKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("load trusted %s public key: %w", purpose, err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("trusted %s public key must be base64-encoded %d-byte Ed25519 public key", purpose, ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(append([]byte(nil), raw...)), nil
}

func decodeRulePackJSONFile(path string, maxBytes int64, dst any) error {
	data, err := readRulePackBounded(path, maxBytes)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode JSON: trailing content")
		}
		return fmt.Errorf("decode JSON: trailing content: %w", err)
	}
	return nil
}

func readRulePackBounded(path string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("invalid read bound %d", maxBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("input exceeds %d bytes", maxBytes)
	}
	return data, nil
}

func writeRulePackJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
