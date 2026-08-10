package sca

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type staticScanResultStore struct{ data []byte }

func (s staticScanResultStore) SaveResult(context.Context, shared.ID, []byte) error { return nil }
func (s staticScanResultStore) LatestResult(context.Context, shared.ID) ([]byte, error) {
	return s.data, nil
}

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
		PromptVersion:      "fp-triage-v2",
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

	applyAIGatePolicy(result, true, aiTriageModeEnforce)
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
		verifiedCritique("bedrock-alias"),
		verifiedCritique("low-verifier"),
		verifiedCritique("wrong-verdict"),
	}
	cases[0].VerifierModel = cases[0].ProposerModel
	cases[1].VerifierModel = "PROPOSER-A"
	cases[2].VerifierModel = "openai/proposer-a"
	cases[3].ProposerModel = "anthropic.claude-opus-5-v1:0"
	cases[3].VerifierModel = "us.anthropic.claude-opus-5-v1:0"
	cases[4].VerifierConfidence = 74
	cases[5].VerifierVerdict = "sound"
	result := &ScanResult{
		Findings: []finding.Finding{
			{DedupKey: "same-model", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityMedium, CWE: "CWE-327"},
			{DedupKey: "case-alias", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityMedium, CWE: "CWE-327"},
			{DedupKey: "provider-alias", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityMedium, CWE: "CWE-327"},
			{DedupKey: "bedrock-alias", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityMedium, CWE: "CWE-327"},
			{DedupKey: "low-verifier", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityMedium, CWE: "CWE-327"},
			{DedupKey: "wrong-verdict", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityMedium, CWE: "CWE-327"},
		},
		AITriage: cases,
	}
	applyAIGatePolicy(result, true, aiTriageModeEnforce)
	if got := result.AIGateExemptKeys(); len(got) != 0 {
		t.Fatalf("forged/incomplete consensus must never receive gate authority: %v", got)
	}
}

func TestCWETokensCanonicalizeLeadingZerosWithoutSubstringMatching(t *testing.T) {
	got := cweTokens(" cwe-0079, CWE-0890 / CWE-0798 | custom-token ")
	want := []string{"CWE-79", "CWE-890", "CWE-798", "CUSTOM-TOKEN"}
	if len(got) != len(want) {
		t.Fatalf("cweTokens = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("cweTokens[%d] = %q, want %q (%v)", i, got[i], want[i], got)
		}
	}

	protected := finding.Finding{Kind: finding.KindSAST, Severity: shared.SeverityMedium, CWE: "CWE-0079"}
	if got := humanReviewFloor(protected); got != aiPolicyDangerousCWEFloor {
		t.Fatalf("zero-padded protected CWE bypassed human-review floor: %q", got)
	}
	nonCollision := finding.Finding{Kind: finding.KindSAST, Severity: shared.SeverityMedium, CWE: "CWE-0890"}
	if got := humanReviewFloor(nonCollision); got != "" {
		t.Fatalf("CWE-0890 must canonicalize to exact CWE-890, not collide with CWE-89: %q", got)
	}
	if !hasCredentialCWE("CWE-0798") {
		t.Fatal("zero-padded credential CWE must remain excluded from LLM candidate selection")
	}
}

func TestHumanReviewFloorFailsClosedOnEmbeddedSeparatorsAndMalformedCWE(t *testing.T) {
	// A dangerous CWE spelled with an embedded separator/punctuation, or a malformed CWE token, must
	// still be held for human review — the tokenizer's separators are as wide as the canonicalizer's
	// tolerance, and any unparseable CWE-* token fails closed.
	protected := []struct {
		name, cwe string
	}{
		{"colon-space suffix", "CWE-79: Cross-site Scripting"},
		{"trailing dot", "CWE-89."},
		{"parenthesized", "CWE-798 (hard-coded credentials)"},
		{"nbsp separator", "CWE-89 notes"},
		{"form-feed separator", "CWE-89\fnotes"},
		{"zero-padded with suffix", "CWE-0022: path traversal"},
		{"malformed non-digit suffix", "CWE-79A"},
		{"bare prefix", "CWE-"},
	}
	for _, tc := range protected {
		item := finding.Finding{Kind: finding.KindSAST, Severity: shared.SeverityMedium, CWE: tc.cwe}
		if got := humanReviewFloor(item); got != aiPolicyDangerousCWEFloor {
			t.Errorf("%s (%q): floor = %q, want %q (must fail closed)", tc.name, tc.cwe, got, aiPolicyDangerousCWEFloor)
		}
	}

	// A genuinely benign, well-formed, non-protected CWE still clears the CWE floor (no over-blocking).
	benign := finding.Finding{Kind: finding.KindSAST, Severity: shared.SeverityMedium, CWE: "CWE-327"}
	if got := humanReviewFloor(benign); got != "" {
		t.Errorf("well-formed non-protected CWE must not trip the floor, got %q", got)
	}

	// Credential CWEs are detected even with embedded punctuation.
	if !hasCredentialCWE("CWE-798: hard-coded credentials") {
		t.Error("credential CWE with a colon suffix must still be detected")
	}
}

func TestApplyAIGatePolicyRequiresEvidenceLedger(t *testing.T) {
	result := &ScanResult{
		Findings: []finding.Finding{{DedupKey: "safe", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityMedium, CWE: "CWE-327"}},
		AITriage: []ports.AICritique{verifiedCritique("safe")},
	}
	applyAIGatePolicy(result, false, aiTriageModeEnforce)
	c := result.AITriage[0]
	if c.GateExempt || !c.ReviewRequired || c.PolicyReason != aiPolicyEvidenceRequired {
		t.Fatalf("no-ledger scan must remain gating: %+v", c)
	}
}

func TestApplyAIGatePolicyShadowNeverExempts(t *testing.T) {
	result := &ScanResult{
		Findings: []finding.Finding{{DedupKey: "safe", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityMedium, CWE: "CWE-327"}},
		AITriage: []ports.AICritique{verifiedCritique("safe")},
	}
	applyAIGatePolicy(result, true, aiTriageModeShadow)
	c := result.AITriage[0]
	if !c.Shadow || !c.WouldGateExempt || c.GateExempt || !c.ReviewRequired || c.PolicyReason != aiPolicyShadowMode {
		t.Fatalf("shadow policy must retain a would-exempt observation without gate authority: %+v", c)
	}
	if got := result.AIGateExemptKeys(); len(got) != 0 {
		t.Fatalf("shadow decisions must never enter the gate exemption set: %v", got)
	}
	if got := result.AIWouldGateExemptKeys(); !got["safe"] || len(got) != 1 {
		t.Fatalf("shadow observation set = %v, want safe", got)
	}
}

func TestApplyAIGatePolicyRejectsIneligibleAlternateTriagerResult(t *testing.T) {
	result := &ScanResult{
		Findings: []finding.Finding{{DedupKey: "sca", Kind: finding.KindSCA, Class: finding.ClassThirdParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityMedium, CWE: "CWE-327"}},
		AITriage: []ports.AICritique{verifiedCritique("sca")},
	}
	applyAIGatePolicy(result, true, aiTriageModeEnforce)
	c := result.AITriage[0]
	if c.GateExempt || !c.ReviewRequired || c.PolicyReason != aiPolicyFindingIneligible {
		t.Fatalf("alternate triager cannot grant authority outside the candidate set: %+v", c)
	}
}

func TestGateExemptKeysRevalidatesOverlaidSeverity(t *testing.T) {
	base := finding.Finding{DedupKey: "profiled", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityMedium, CWE: "CWE-327"}
	result := &ScanResult{Findings: []finding.Finding{base}, AITriage: []ports.AICritique{verifiedCritique("profiled")}}
	applyAIGatePolicy(result, true, aiTriageModeEnforce)
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

// TestAIGateExemptionsNeverProjectAForgedShadowDecision guards the shadow boundary at the EXPORT seam.
//
// Shadow mode exists so AI triage can be observed without affecting a gate (P1.1). A shadow decision
// reaching SARIF as an "external / accepted" suppression would tell a code-scanning UI the finding was
// accepted while the policy deliberately had no authority to accept it -- the shadow guarantee leaking
// into an artifact customers and CI read as fact.
//
// The critique here is FORGED: Shadow and GateExempt both true, which applyAIGatePolicy never produces
// (it clears GateExempt before the shadow branch). That is the point -- !c.Shadow in
// authorizedAIGateExemption is defence against a persisted or hand-built DTO, so only a forged input
// exercises it. My first attempt at this test used applyAIGatePolicy and passed for the wrong reason:
// GateExempt was already false, so removing !c.Shadow left it green.
func TestAIGateExemptionsNeverProjectAForgedShadowDecision(t *testing.T) {
	forged := verifiedCritique("safe")
	forged.GateExempt = true
	forged.Shadow = true
	forged.PolicyVersion = aiTriagePolicyVersion
	forged.PolicyReason = aiPolicyVerifiedConsensus
	findings := []finding.Finding{
		{DedupKey: "safe", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityMedium, CWE: "CWE-327"},
	}
	result := &ScanResult{Findings: findings, AITriage: []ports.AICritique{forged}}

	if got := result.AIGateExemptions(); len(got) != 0 {
		t.Fatalf("a shadow decision must never be exported as an accepted suppression: %v", got)
	}
	if got := result.AIGateExemptKeys(); len(got) != 0 {
		t.Fatalf("a shadow decision must never authorize a gate: %v", got)
	}

	// The same decision with Shadow cleared MUST project, or this test would pass for the wrong reason
	// again -- it has to be the shadow flag doing the refusing, not some other unmet condition.
	enforced := forged
	enforced.Shadow = false
	ok := &ScanResult{Findings: findings, AITriage: []ports.AICritique{enforced}}
	if got := ok.AIGateExemptions(); len(got) != 1 {
		t.Fatalf("with Shadow cleared the same decision must project exactly one exemption: %v", got)
	}
}

func TestAIGateExemptionsProjectsOnlyPolicyAuthorizedDecision(t *testing.T) {
	findings := []finding.Finding{
		{DedupKey: "safe", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityMedium, CWE: "CWE-327"},
		{DedupKey: "high", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityHigh, CWE: "CWE-327"},
		{DedupKey: "critical", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityCritical, CWE: "CWE-327"},
		{DedupKey: "secret", Kind: finding.KindSecret, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityMedium, CWE: "CWE-327"},
		{DedupKey: "protected-cwe", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityMedium, CWE: "CWE-89"},
		{DedupKey: "ineligible", Kind: finding.KindSCA, Class: finding.ClassThirdParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityMedium, CWE: "CWE-327"},
	}
	result := &ScanResult{Findings: findings}
	for _, item := range findings {
		result.AITriage = append(result.AITriage, verifiedCritique(item.DedupKey))
	}
	applyAIGatePolicy(result, true, aiTriageModeEnforce)

	noLedger := findings[0]
	noLedger.DedupKey = "no-ledger"
	withoutLedger := &ScanResult{Findings: []finding.Finding{noLedger}, AITriage: []ports.AICritique{verifiedCritique("no-ledger")}}
	applyAIGatePolicy(withoutLedger, false, aiTriageModeEnforce)
	result.Findings = append(result.Findings, noLedger)
	result.AITriage = append(result.AITriage, withoutLedger.AITriage[0])

	got := result.AIGateExemptions()
	if len(got) != 1 {
		t.Fatalf("AI gate exemption projection = %+v, want only safe", got)
	}
	exemption, ok := got["safe"]
	if !ok || exemption.DedupKey != "safe" || exemption.PolicyVersion != aiTriagePolicyVersion || exemption.PolicyReason != aiPolicyVerifiedConsensus {
		t.Errorf("safe exemption metadata = %+v", exemption)
	}
	for _, key := range []string{"high", "critical", "secret", "protected-cwe", "ineligible", "no-ledger"} {
		if _, exists := got[key]; exists {
			t.Errorf("unsafe decision %q received export metadata", key)
		}
	}
}

func TestServiceAIGateExemptionsReadsLatestResultDeterministically(t *testing.T) {
	result := &ScanResult{
		Findings: []finding.Finding{
			{DedupKey: "z-safe", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityMedium, CWE: "CWE-327"},
			{DedupKey: "a-safe", Kind: finding.KindMisconfig, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityLow, CWE: "CWE-16"},
		},
		AITriage: []ports.AICritique{verifiedCritique("z-safe"), verifiedCritique("a-safe")},
	}
	applyAIGatePolicy(result, true, aiTriageModeEnforce)
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	svc := &Service{results: staticScanResultStore{data: data}}

	got, err := svc.AIGateExemptions(context.Background(), "e1", result.Findings)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].DedupKey != "a-safe" || got[1].DedupKey != "z-safe" {
		t.Fatalf("stored exemption order = %+v, want a-safe then z-safe", got)
	}
	exportView := append([]finding.Finding(nil), result.Findings...)
	exportView[0].Severity = shared.SeverityHigh
	got, err = svc.AIGateExemptions(context.Background(), "e1", exportView)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].DedupKey != "a-safe" {
		t.Fatalf("severity-escalated export view retained stale exemption: %+v", got)
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
		AITriageBudget: &AITriageBudget{MaxFindings: 10, EligibleFindings: 2, AttemptedFindings: 2},
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
	if payload.AITriageBudget == nil || payload.AITriageBudget.MaxFindings != 10 || payload.AITriageBudget.AttemptedFindings != 2 {
		t.Fatalf("AI request budget missing from sealed payload: %+v", payload.AITriageBudget)
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

func TestScanEvidenceContentSealsShadowDecision(t *testing.T) {
	result := &ScanResult{
		Findings: []finding.Finding{{DedupKey: "safe", Kind: finding.KindSAST, Class: finding.ClassFirstParty, Scope: sbom.ScopeProduction, Severity: shared.SeverityMedium, CWE: "CWE-327"}},
		Manifest: ports.ScanManifest{SBOMSHA256: "sha256:shadow"},
		AITriage: []ports.AICritique{verifiedCritique("safe")},
	}
	applyAIGatePolicy(result, true, aiTriageModeShadow)
	content, err := scanEvidenceContent("tester", time.Date(2026, 8, 8, 1, 2, 3, 0, time.UTC), result)
	if err != nil {
		t.Fatalf("scanEvidenceContent: %v", err)
	}
	var payload scanEvidencePayload
	if err := json.Unmarshal(content, &payload); err != nil {
		t.Fatalf("decode evidence payload: %v", err)
	}
	if len(payload.AITriage) != 1 || !payload.AITriage[0].Shadow || !payload.AITriage[0].WouldGateExempt ||
		payload.AITriage[0].GateExempt || payload.AITriage[0].PolicyReason != aiPolicyShadowMode {
		t.Fatalf("shadow decision missing from sealed payload: %+v", payload.AITriage)
	}
}
