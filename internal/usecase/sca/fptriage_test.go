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
		{DedupKey: "sast-prod", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction},
		{DedupKey: "secret-prod", Kind: finding.KindSecret, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction}, // raw secret context must never enter an LLM
		{DedupKey: "misconfig-prod", Kind: finding.KindMisconfig, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction},
		{DedupKey: "credential-sast", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, CWE: "CWE-798"},
		{DedupKey: "sast-test", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeTest},       // background → skip
		{DedupKey: "sca-prod", Kind: finding.KindSCA, Class: finding.ClassThirdParty, Scope: sbom.ScopeProduction},   // SCA → skip (DB-backed fact)
		{DedupKey: "sast-fixture", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeFixture}, // background → skip
		{DedupKey: "sast-development", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeDevelopment},
		{DedupKey: "sast-unknown", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeUnknown},
		{DedupKey: "wrong-class", Kind: finding.KindSAST, Class: finding.ClassThirdParty, Scope: sbom.ScopeProduction},
	}
	got := fpTriageCandidates(fs)
	if len(got) != 2 {
		t.Fatalf("want 2 safe-to-transmit production source candidates, got %d: %+v", len(got), got)
	}
	for _, c := range got {
		if sbom.IsBackgroundScope(c.Scope) || c.Kind == finding.KindSCA || c.Kind == finding.KindSecret || c.Class != finding.ClassFirstParty {
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
	}, Findings: []finding.Finding{{DedupKey: "c", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityMedium, CWE: "CWE-327"}}}
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
			{DedupKey: "safe-medium", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityMedium, CWE: "CWE-327"},
			{DedupKey: "single", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityMedium, CWE: "CWE-327"},
			{DedupKey: "high", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityHigh, CWE: "CWE-327"},
			{DedupKey: "secret", Kind: finding.KindSecret, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityMedium, CWE: "CWE-798"},
			{DedupKey: "sqli", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityMedium, CWE: "CWE-89"},
			{DedupKey: "credential", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityMedium, CWE: "CWE-798"},
			{DedupKey: "unknown-cwe", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityMedium},
		},
		AITriage: []ports.AICritique{
			verifiedCritique("safe-medium"),
			single,
			verifiedCritique("high"),
			verifiedCritique("secret"),
			verifiedCritique("sqli"),
			verifiedCritique("credential"),
			verifiedCritique("unknown-cwe"),
			{DedupKey: "sound", Verdict: "sound", Confidence: 99, ProposerModel: "proposer-a"},
			verifiedCritique("missing"),
		},
	}

	applyAIGatePolicy(result, true)
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
		"single":      aiPolicyVerifierRequired,
		"high":        aiPolicySeverityFloor,
		"secret":      aiPolicySecretFloor,
		"sqli":        aiPolicyDangerousCWEFloor,
		"credential":  aiPolicyDangerousCWEFloor,
		"unknown-cwe": aiPolicyDangerousCWEFloor,
		"missing":     aiPolicyFindingMissing,
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
		verifiedCritique("case-alias"),
		verifiedCritique("provider-alias"),
		verifiedCritique("low-verifier"),
		verifiedCritique("wrong-verdict"),
	}
	cases[0].VerifierModel = cases[0].ProposerModel
	cases[1].VerifierModel = "PROPOSER-A"
	cases[2].VerifierModel = "openai/proposer-a"
	cases[3].VerifierConfidence = 74
	cases[4].VerifierVerdict = "sound"
	result := &ScanResult{
		Findings: []finding.Finding{
			{DedupKey: "same-model", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityMedium, CWE: "CWE-327"},
			{DedupKey: "case-alias", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityMedium, CWE: "CWE-327"},
			{DedupKey: "provider-alias", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityMedium, CWE: "CWE-327"},
			{DedupKey: "low-verifier", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityMedium, CWE: "CWE-327"},
			{DedupKey: "wrong-verdict", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityMedium, CWE: "CWE-327"},
		},
		AITriage: cases,
	}
	applyAIGatePolicy(result, true)
	if got := result.AIGateExemptKeys(); len(got) != 0 {
		t.Fatalf("forged/incomplete consensus must never receive gate authority: %v", got)
	}
}

func TestApplyAIGatePolicyRequiresEvidenceLedger(t *testing.T) {
	result := &ScanResult{
		Findings: []finding.Finding{{DedupKey: "safe", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityMedium, CWE: "CWE-327"}},
		AITriage: []ports.AICritique{verifiedCritique("safe")},
	}
	applyAIGatePolicy(result, false)
	c := result.AITriage[0]
	if c.GateExempt || !c.ReviewRequired || c.PolicyReason != aiPolicyEvidenceRequired {
		t.Fatalf("no-ledger scan must remain gating: %+v", c)
	}
}

func TestApplyAIGatePolicyRejectsIneligibleAlternateTriagerResult(t *testing.T) {
	result := &ScanResult{
		Findings: []finding.Finding{{DedupKey: "sca", Kind: finding.KindSCA, Class: finding.ClassThirdParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityMedium, CWE: "CWE-327"}},
		AITriage: []ports.AICritique{verifiedCritique("sca")},
	}
	applyAIGatePolicy(result, true)
	c := result.AITriage[0]
	if c.GateExempt || !c.ReviewRequired || c.PolicyReason != aiPolicyFindingIneligible {
		t.Fatalf("alternate triager cannot grant authority outside the candidate set: %+v", c)
	}
}

func TestGateExemptKeysRevalidatesOverlaidSeverity(t *testing.T) {
	base := finding.Finding{DedupKey: "profiled", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityMedium, CWE: "CWE-327"}
	result := &ScanResult{Findings: []finding.Finding{base}, AITriage: []ports.AICritique{verifiedCritique("profiled")}}
	applyAIGatePolicy(result, true)
	if !result.AIGateExemptKeys()["profiled"] {
		t.Fatal("baseline medium finding should pass the low-risk policy")
	}
	overlaid := base
	overlaid.Severity = shared.SeverityHigh
	if result.GateExemptKeys([]finding.Finding{overlaid})["profiled"] {
		t.Fatal("tenant severity overlay to high must revoke the AI gate exemption")
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
		Findings: []finding.Finding{
			{DedupKey: "z", Severity: shared.SeverityHigh, CWE: "CWE-89", Kind: finding.KindSAST, Scope: sbom.ScopeProduction, Class: finding.ClassFirstParty},
			{DedupKey: "a", Severity: shared.SeverityMedium, CWE: "CWE-327", Kind: finding.KindSAST, Scope: sbom.ScopeProduction, Class: finding.ClassFirstParty},
		},
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
	if len(payload.AITriageFindings) != 2 || payload.AITriageFindings[0].DedupKey != "a" ||
		payload.AITriageFindings[0].Severity != shared.SeverityMedium ||
		payload.AITriageFindings[1].CWE != "CWE-89" || payload.AITriageFindings[1].Kind != finding.KindSAST {
		t.Errorf("gate-floor inputs missing or non-canonical in evidence: %+v", payload.AITriageFindings)
	}
}
