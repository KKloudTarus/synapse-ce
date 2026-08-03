package sca

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestFPTriageCandidates(t *testing.T) {
	fs := []finding.Finding{
		{DedupKey: "sast-prod", Kind: finding.KindSAST, Scope: sbom.ScopeProduction},
		{DedupKey: "secret-prod", Kind: finding.KindSecret, Scope: sbom.ScopeProduction},
		{DedupKey: "misconfig-prod", Kind: finding.KindMisconfig, Scope: sbom.ScopeProduction},
		{DedupKey: "sast-test", Kind: finding.KindSAST, Scope: sbom.ScopeTest},       // background → skip
		{DedupKey: "sca-prod", Kind: finding.KindSCA, Scope: sbom.ScopeProduction},   // SCA → skip (DB-backed fact)
		{DedupKey: "sast-fixture", Kind: finding.KindSAST, Scope: sbom.ScopeFixture}, // background → skip
	}
	got := fpTriageCandidates(fs)
	if len(got) != 3 {
		t.Fatalf("want 3 production source candidates, got %d: %+v", len(got), got)
	}
	for _, c := range got {
		if sbom.IsBackgroundScope(c.Scope) || c.Kind == finding.KindSCA {
			t.Errorf("unexpected candidate: %+v", c)
		}
	}
}

func TestSuspectedFPKeys(t *testing.T) {
	consensus := verifiedCritique("c")
	consensus.GateExempt = true
	consensus.PolicyVersion = aiTriagePolicyVersion
	consensus.PolicyReason = aiPolicyVerifiedConsensus
	res := &ScanResult{AITriage: []ports.AICritique{
		{DedupKey: "a", SuspectedFP: true, GateExempt: false},
		{DedupKey: "b", SuspectedFP: false},
		consensus,
	}, Findings: []finding.Finding{{DedupKey: "c", Kind: finding.KindSAST, Severity: shared.SeverityMedium, CWE: "CWE-327"}}}
	keys := res.SuspectedFPKeys()
	if len(keys) != 2 || !keys["a"] || !keys["c"] || keys["b"] {
		t.Errorf("SuspectedFPKeys = %v, want {a,c}", keys)
	}
	exempt := res.AIGateExemptKeys()
	if len(exempt) != 1 || !exempt["c"] || exempt["a"] {
		t.Errorf("AIGateExemptKeys = %v, want only {c}", exempt)
	}
}

func verifiedCritique(key string) ports.AICritique {
	return ports.AICritique{
		DedupKey:           key,
		Verdict:            "refuted",
		Confidence:         95,
		SuspectedFP:        true,
		ProposerModel:      "proposer-a",
		VerifierModel:      "verifier-b",
		Verified:           true,
		VerifierVerdict:    "refuted",
		VerifierConfidence: 93,
		PromptVersion:      "fp-triage-v1",
	}
}

func TestApplyAIGatePolicy(t *testing.T) {
	single := verifiedCritique("single")
	single.Verified = false
	single.VerifierModel = ""
	single.VerifierVerdict = ""
	single.VerifierConfidence = 0

	result := &ScanResult{
		Findings: []finding.Finding{
			{DedupKey: "safe-medium", Kind: finding.KindSAST, Severity: shared.SeverityMedium, CWE: "CWE-327"},
			{DedupKey: "single", Kind: finding.KindSAST, Severity: shared.SeverityMedium, CWE: "CWE-327"},
			{DedupKey: "high", Kind: finding.KindSAST, Severity: shared.SeverityHigh, CWE: "CWE-327"},
			{DedupKey: "secret", Kind: finding.KindSecret, Severity: shared.SeverityMedium, CWE: "CWE-798"},
			{DedupKey: "sqli", Kind: finding.KindSAST, Severity: shared.SeverityMedium, CWE: "CWE-89"},
		},
		AITriage: []ports.AICritique{
			verifiedCritique("safe-medium"),
			single,
			verifiedCritique("high"),
			verifiedCritique("secret"),
			verifiedCritique("sqli"),
			{DedupKey: "sound", Verdict: "sound", Confidence: 99, ProposerModel: "proposer-a"},
			verifiedCritique("missing"),
		},
	}

	applyAIGatePolicy(result)
	byKey := map[string]ports.AICritique{}
	for _, c := range result.AITriage {
		byKey[c.DedupKey] = c
		if c.PolicyVersion != aiTriagePolicyVersion {
			t.Errorf("%s policy version = %q", c.DedupKey, c.PolicyVersion)
		}
	}
	if c := byKey["safe-medium"]; !c.GateExempt || c.ReviewRequired || c.PolicyReason != aiPolicyVerifiedConsensus {
		t.Errorf("verified low-risk consensus should be gate-exempt: %+v", c)
	}
	for key, reason := range map[string]string{
		"single":  aiPolicyVerifierRequired,
		"high":    aiPolicySeverityFloor,
		"secret":  aiPolicySecretFloor,
		"sqli":    aiPolicyDangerousCWEFloor,
		"missing": aiPolicyFindingMissing,
	} {
		c := byKey[key]
		if c.GateExempt || !c.ReviewRequired || c.PolicyReason != reason {
			t.Errorf("%s must remain gating for %s: %+v", key, reason, c)
		}
	}
	if c := byKey["sound"]; c.GateExempt || c.ReviewRequired || c.PolicyReason != aiPolicyNotSuspected {
		t.Errorf("non-refuted critique should be informational only: %+v", c)
	}
}

func TestApplyAIGatePolicyRejectsForgedVerifiedFlag(t *testing.T) {
	cases := []ports.AICritique{
		verifiedCritique("same-model"),
		verifiedCritique("low-verifier"),
		verifiedCritique("wrong-verdict"),
	}
	cases[0].VerifierModel = cases[0].ProposerModel
	cases[1].VerifierConfidence = 74
	cases[2].VerifierVerdict = "sound"
	result := &ScanResult{
		Findings: []finding.Finding{
			{DedupKey: "same-model", Kind: finding.KindSAST, Severity: shared.SeverityMedium},
			{DedupKey: "low-verifier", Kind: finding.KindSAST, Severity: shared.SeverityMedium},
			{DedupKey: "wrong-verdict", Kind: finding.KindSAST, Severity: shared.SeverityMedium},
		},
		AITriage: cases,
	}
	applyAIGatePolicy(result)
	if got := result.AIGateExemptKeys(); len(got) != 0 {
		t.Fatalf("forged/incomplete consensus must never receive gate authority: %v", got)
	}
}

func TestAIGateExemptKeysRevalidatesPersistedDecision(t *testing.T) {
	forged := verifiedCritique("high")
	forged.GateExempt = true
	forged.PolicyVersion = aiTriagePolicyVersion
	forged.PolicyReason = aiPolicyVerifiedConsensus
	result := &ScanResult{
		Findings: []finding.Finding{{DedupKey: "high", Kind: finding.KindSAST, Severity: shared.SeverityHigh}},
		AITriage: []ports.AICritique{forged},
	}
	if got := result.AIGateExemptKeys(); len(got) != 0 {
		t.Fatalf("persisted gate flag must be revalidated against the high-risk floor: %v", got)
	}
}

func TestScanEvidenceContentSealsAIDecisions(t *testing.T) {
	result := &ScanResult{
		Findings: []finding.Finding{{DedupKey: "z"}, {DedupKey: "a"}},
		Manifest: ports.ScanManifest{SBOMSHA256: "sha256:abc"},
		AITriage: []ports.AICritique{
			{DedupKey: "z", FindingID: "fz", ProposerModel: "p", PolicyVersion: aiTriagePolicyVersion, PolicyReason: aiPolicyVerifierRequired, ReviewRequired: true},
			{DedupKey: "a", FindingID: "fa", ProposerModel: "p", VerifierModel: "v", PolicyVersion: aiTriagePolicyVersion, PolicyReason: aiPolicyVerifiedConsensus, Verified: true, GateExempt: true},
		},
	}
	content, err := scanEvidenceContent("tester", time.Date(2026, 8, 3, 1, 2, 3, 0, time.UTC), result)
	if err != nil {
		t.Fatalf("scanEvidenceContent: %v", err)
	}
	var payload scanEvidencePayload
	if err := json.Unmarshal(content, &payload); err != nil {
		t.Fatalf("decode evidence payload: %v", err)
	}
	if payload.AITriagePolicy != aiTriagePolicyVersion || len(payload.AITriage) != 2 {
		t.Fatalf("AI policy/decisions missing from sealed payload: %+v", payload)
	}
	if payload.Findings[0] != "a" || payload.AITriage[0].DedupKey != "a" {
		t.Errorf("evidence payload must sort findings and AI decisions canonically: %+v", payload)
	}
	if !payload.AITriage[0].GateExempt || !payload.AITriage[0].Verified || !payload.AITriage[1].ReviewRequired {
		t.Errorf("gate/verifier/review metadata not sealed: %+v", payload.AITriage)
	}
}
