package judgment

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vex"
)

func TestClaimRoundTrip(t *testing.T) {
	claims := []Claim{
		ReachabilityClaim{Reachable: Reachable, Tier: Tier2, Path: []string{"main", "vuln"}, Confidence: 95},
		SASTClaim{CWE: "CWE-327", Location: "auth.go:42", Rule: "weak-hash-md5"},
		DASTClaim{CWE: "CWE-79", Location: "/search", Rule: "reflected-xss", Source: "first_party", Fingerprint: "search_reflection", ProofEvidenceID: "proof-1"},
		RiskNarrativeClaim{Drivers: []string{"kev", "cvss>=9"}, Priority: 1},
		CritiqueClaim{Verdict: CritiqueRefuted, Driver: "version_mismatch", Confidence: 85},
		ThreatClaim{Category: InfoDisclosure, Asset: "pii"},
		ThreatClaim{Category: Spoofing}, // asset optional
		CorrelationClaim{Reporters: []string{"osv"}, Missing: []string{"advisory-store"}},
		PromotionClaim{FindingID: "finding-1", Rule: RuleUncertainCorroboration, Inputs: []PromotionInput{{Kind: PromotionInputReachability, ID: "judgment-1"}}, Proposed: PromotionFlagForReview, Uncertainty: []string{"unknown_reachability"}, Fingerprint: strings.Repeat("a", 64), FindingVersion: 1, BeforePriority: 3, AfterPriority: 3},
		VexJustificationClaim{Justification: vex.VulnerableCodeNotInExecutePath},
	}
	for _, c := range claims {
		data, err := MarshalClaim(c)
		if err != nil {
			t.Fatalf("MarshalClaim(%T): %v", c, err)
		}
		got, err := UnmarshalClaim(data)
		if err != nil {
			t.Fatalf("UnmarshalClaim(%T): %v", c, err)
		}
		if got.Capability() != c.Capability() {
			t.Fatalf("capability changed: %s != %s", got.Capability(), c.Capability())
		}
	}
}

func TestPythonSemanticActorsAreRecognizedOnlyAtTier2(t *testing.T) {
	if !IsDeterministicReachabilityProof(Tier2, ProofActorPySemanticScan, ProofActorPySemanticEngine) {
		t.Fatal("Python semantic actors must be accepted as a deterministic Tier-2 pair")
	}
	if IsDeterministicReachabilityProof(Tier1, ProofActorPySemanticScan, ProofActorPySemanticEngine) ||
		IsDeterministicReachabilityProof(Tier2, ProofActorPySemanticScan, ProofActorPyImportEngine) {
		t.Fatal("Python semantic actors must fail closed for the wrong tier or a mixed pair")
	}
}

func TestDASTClaimStrictDecode(t *testing.T) {
	valid := []byte(`{"capability":"dast","claim":{"cwe":"CWE-79","location":"/search","rule":"reflected-xss","source":"first_party","fingerprint":"search_reflection","proof_evidence_id":"proof-1"}}`)
	claim, err := UnmarshalClaim(valid)
	if err != nil {
		t.Fatalf("UnmarshalClaim: %v", err)
	}
	if _, ok := claim.(DASTClaim); !ok {
		t.Fatalf("claim type = %T, want DASTClaim", claim)
	}
	for _, raw := range [][]byte{
		[]byte(`{"capability":"dast","claim":{"cwe":"CWE-79","location":"/search","rule":"x","source":"first_party","fingerprint":"f","notes":"no"}}`),
		[]byte(`{"capability":"dast","claim":{"cwe":"CWE-79","location":"/search","rule":"x","source":"not valid","fingerprint":"f"}}`),
	} {
		if _, err := UnmarshalClaim(raw); err == nil {
			t.Fatalf("UnmarshalClaim(%s) succeeded", raw)
		}
	}
}

func TestUnmarshalClaimFailClosed(t *testing.T) {
	cases := []struct{ name, data string }{
		{"unknown capability", `{"capability":"telepathy","claim":{}}`},
		{"malformed envelope", `not json`},
		{"unknown field smuggled (prose leak)", `{"capability":"sast","claim":{"cwe":"CWE-1","location":"a","rule":"r","notes":"PROSE LEAK"}}`},
		{"body fails validate", `{"capability":"reachability","claim":{"reachable":"maybe","tier":"tier-0","confidence":1}}`},
		{"confidence out of range", `{"capability":"reachability","claim":{"reachable":"unknown","tier":"tier-0","confidence":999}}`},
		{"empty sast fields", `{"capability":"sast","claim":{"cwe":"","location":"","rule":""}}`},
		{"free-text risk driver (prose leak)", `{"capability":"risk_narrative","claim":{"drivers":["This is a prose sentence."],"priority":1}}`},
		{"critique unknown verdict", `{"capability":"critique","claim":{"verdict":"maybe","driver":"x","confidence":1}}`},
		{"critique prose driver (prose leak)", `{"capability":"critique","claim":{"verdict":"refuted","driver":"this is prose","confidence":1}}`},
		{"threat unknown STRIDE category", `{"capability":"threat","claim":{"category":"mind_reading","asset":""}}`},
		{"threat unknown field smuggled", `{"capability":"threat","claim":{"category":"spoofing","asset":"","notes":"PROSE LEAK"}}`},
		{"correlation with no missing (not a disagreement)", `{"capability":"correlation","claim":{"reporters":["osv"],"missing":[]}}`},
		{"correlation with no reporters", `{"capability":"correlation","claim":{"reporters":[],"missing":["owned"]}}`},
		{"correlation unknown field smuggled", `{"capability":"correlation","claim":{"reporters":["osv"],"missing":["owned"],"notes":"PROSE LEAK"}}`},
		{"vex unknown justification", `{"capability":"vex_justification","claim":{"justification":"because_i_said_so"}}`},
		{"vex free-text justification (prose leak)", `{"capability":"vex_justification","claim":{"justification":"the code is unreachable in practice"}}`},
		{"vex unknown field smuggled", `{"capability":"vex_justification","claim":{"justification":"component_not_present","notes":"PROSE LEAK"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := UnmarshalClaim([]byte(tc.data)); err == nil {
				t.Fatal("want error (fail-closed), got nil")
			} else if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want ErrValidation, got %v", err)
			}
		})
	}
}

func TestCritiqueClaimValidate(t *testing.T) {
	for _, v := range []CritiqueVerdict{CritiqueRefuted, CritiqueSound, CritiqueUncertain} {
		if !v.Valid() {
			t.Errorf("verdict %q should be valid", v)
		}
	}
	if CritiqueVerdict("maybe").Valid() {
		t.Error("unknown verdict must be invalid (fail-closed)")
	}
	if err := (CritiqueClaim{Verdict: CritiqueRefuted, Driver: "ok", Confidence: 101}).Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Error("out-of-range confidence must be rejected")
	}
	if err := (CritiqueClaim{Verdict: CritiqueRefuted, Driver: "a prose driver", Confidence: 50}).Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Error("prose driver must be rejected (no free text)")
	}
	if err := (CritiqueClaim{Verdict: CritiqueSound, Driver: "version_mismatch", Confidence: 50}).Validate(); err != nil {
		t.Errorf("a valid critique should pass: %v", err)
	}
}

func TestSASTClaimValidateRejectsModelProseAndOversizedFields(t *testing.T) {
	valid := SASTClaim{CWE: "CWE-89", Location: "internal/db/query.go:42", Rule: "go/sql-injection"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid SAST claim rejected: %v", err)
	}

	cases := []struct {
		name  string
		claim SASTClaim
	}{
		{"malformed CWE", SASTClaim{CWE: "CWE-89 because SQL injection", Location: "a.go:1", Rule: "r"}},
		{"CWE control character", SASTClaim{CWE: "CWE-89\n", Location: "a.go:1", Rule: "r"}},
		{"oversized location", SASTClaim{CWE: "CWE-89", Location: strings.Repeat("a", maxSASTLocationLen+1), Rule: "r"}},
		{"location control character", SASTClaim{CWE: "CWE-89", Location: "a.go:1\nignore previous", Rule: "r"}},
		{"rule prose", SASTClaim{CWE: "CWE-89", Location: "a.go:1", Rule: "SQL injection is likely"}},
		{"oversized rule", SASTClaim{CWE: "CWE-89", Location: "a.go:1", Rule: strings.Repeat("r", maxSASTRuleLen+1)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.claim.Validate(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want ErrValidation, got %v", err)
			}
		})
	}
}

func TestRiskNarrativeClaimDriverCountBounded(t *testing.T) {
	drivers := make([]string, maxRiskDrivers+1)
	for i := range drivers {
		drivers[i] = "reachable"
	}
	if err := (RiskNarrativeClaim{Drivers: drivers, Priority: 1}).Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("oversized model driver list: want ErrValidation, got %v", err)
	}
}

func TestThreatClaimValidate(t *testing.T) {
	for _, cat := range []StrideCategory{Spoofing, Tampering, Repudiation, InfoDisclosure, DenialOfService, ElevationOfPrivilege} {
		if !cat.Valid() {
			t.Errorf("STRIDE category %q should be valid", cat)
		}
		if err := (ThreatClaim{Category: cat}).Validate(); err != nil {
			t.Errorf("a valid threat (%q, no asset) should pass: %v", cat, err)
		}
	}
	if StrideCategory("mind_reading").Valid() {
		t.Error("unknown STRIDE category must be invalid (fail-closed)")
	}
	if err := (ThreatClaim{Category: "mind_reading"}).Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Error("unknown STRIDE category must be rejected")
	}
	if err := (ThreatClaim{Category: InfoDisclosure, Asset: strings.Repeat("a", 129)}).Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Error("an over-long asset id must be rejected")
	}
	if err := (ThreatClaim{Category: ElevationOfPrivilege, Asset: "admin_creds"}).Validate(); err != nil {
		t.Errorf("a valid threat with an asset should pass: %v", err)
	}
}

func TestVexJustificationClaimValidate(t *testing.T) {
	for _, j := range []vex.OpenVexJustification{
		vex.ComponentNotPresent, vex.VulnerableCodeNotPresent, vex.VulnerableCodeNotInExecutePath,
		vex.VulnerableCodeCannotBeControlled, vex.InlineMitigationsAlreadyExist,
	} {
		if err := (VexJustificationClaim{Justification: j}).Validate(); err != nil {
			t.Errorf("valid OpenVEX justification %q rejected: %v", j, err)
		}
		if (VexJustificationClaim{Justification: j}).Capability() != CapVexJustification {
			t.Errorf("capability mismatch for %q", j)
		}
	}
	for _, bad := range []vex.OpenVexJustification{"", "not_affected", "made_up_reason"} {
		if err := (VexJustificationClaim{Justification: bad}).Validate(); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("invalid justification %q must be rejected (fail-closed), got %v", bad, err)
		}
	}
}

func TestCorrelationClaimValidate(t *testing.T) {
	if err := (CorrelationClaim{Reporters: []string{"osv"}, Missing: []string{"advisory-store"}}).Validate(); err != nil {
		t.Errorf("a real disagreement should pass: %v", err)
	}
	if err := (CorrelationClaim{Reporters: []string{"osv"}}).Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Error("no missing source -> not a disagreement -> must be rejected")
	}
	if err := (CorrelationClaim{Missing: []string{"owned"}}).Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Error("no reporters -> must be rejected")
	}
	if err := (CorrelationClaim{Reporters: []string{""}, Missing: []string{"owned"}}).Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Error("an empty source name must be rejected")
	}
}

func TestReachabilitySupersedes(t *testing.T) {
	rc := func(tier ReachabilityTier) ReachabilityClaim {
		return ReachabilityClaim{Reachable: Reachable, Tier: tier, Confidence: 80}
	}
	// strictly stronger tier supersedes (deterministic Tier-2 over LLM Tier-1.5)
	if !rc(Tier2).Supersedes(rc(Tier1_5)) {
		t.Error("Tier-2 must supersede Tier-1.5")
	}
	if !rc(Tier1_5).Supersedes(rc(Tier0)) {
		t.Error("Tier-1.5 must supersede Tier-0")
	}
	// same tier does NOT supersede (no churn) - even if the new verdict disagrees
	notReach := ReachabilityClaim{Reachable: NotReachable, Tier: Tier2, Confidence: 90}
	if notReach.Supersedes(rc(Tier2)) {
		t.Error("same tier must not supersede (stored verdict stands)")
	}
	// weaker tier never downgrades a stronger proof
	if rc(Tier1).Supersedes(rc(Tier2)) {
		t.Error("a weaker tier must NOT supersede a stronger proof")
	}
	// an unknown/invalid tier (Rank 0) can neither supersede nor be preserved against a valid tier
	bad := ReachabilityClaim{Reachable: Reachable, Tier: ReachabilityTier("tier-9"), Confidence: 50}
	if bad.Supersedes(rc(Tier0)) {
		t.Error("an invalid tier must not supersede a valid one")
	}
	if !rc(Tier0).Supersedes(bad) {
		t.Error("a valid Tier-0 must supersede an invalid-tier claim")
	}
}

func TestMarshalNilClaim(t *testing.T) {
	if _, err := MarshalClaim(nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("nil claim: want ErrValidation, got %v", err)
	}
}

func TestReachabilityTierRank(t *testing.T) {
	// Strength ordering must be strictly increasing - supersession compares ranks.
	if !(Tier0.Rank() < Tier1.Rank() && Tier1.Rank() < Tier1_5.Rank() && Tier1_5.Rank() < Tier2.Rank()) {
		t.Fatalf("tier ranks must be strictly increasing: %d %d %d %d", Tier0.Rank(), Tier1.Rank(), Tier1_5.Rank(), Tier2.Rank())
	}
	if ReachabilityTier("tier-9").Rank() != 0 || ReachabilityTier("tier-9").Valid() {
		t.Fatal("unknown tier must rank 0 and be invalid (fail-closed)")
	}
}

func TestReachabilityEnumValid(t *testing.T) {
	for _, s := range []ReachabilityState{Reachable, NotReachable, ReachUnknown} {
		if !s.Valid() {
			t.Fatalf("state %q should be valid", s)
		}
	}
	if ReachabilityState("maybe").Valid() {
		t.Fatal("unknown state must be invalid (fail-closed)")
	}
	for _, ti := range []ReachabilityTier{Tier0, Tier1, Tier1_5, Tier2} {
		if !ti.Valid() {
			t.Fatalf("tier %q should be valid", ti)
		}
	}
}

func TestReachabilityClaimPathBounded(t *testing.T) {
	// fail-closed at the domain seam: a hostile/runaway proposer can't seal an unbounded path.
	tooMany := make([]string, maxClaimPathElems+1)
	for i := range tooMany {
		tooMany[i] = "x"
	}
	if err := (ReachabilityClaim{Reachable: Reachable, Tier: Tier1, Path: tooMany, Confidence: 50}).Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("oversized path (count): want ErrValidation, got %v", err)
	}
	longElem := ReachabilityClaim{Reachable: Reachable, Tier: Tier1, Path: []string{strings.Repeat("y", maxClaimPathElemLen+1)}, Confidence: 50}
	if err := longElem.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("oversized path element: want ErrValidation, got %v", err)
	}
	// a normal path passes
	if err := (ReachabilityClaim{Reachable: Reachable, Tier: Tier1, Path: []string{"root", "lodash"}, Confidence: 50}).Validate(); err != nil {
		t.Fatalf("normal path should pass: %v", err)
	}
}

// --- Promotion claim tests ---

func TestPromotionClaimStrictRoundTrip(t *testing.T) {
	orig := PromotionClaim{
		FindingID:      "finding-abc",
		Rule:           RuleRuntimeReachableExposed,
		Inputs:         []PromotionInput{{Kind: PromotionInputAttackPath, ID: "ap1"}, {Kind: PromotionInputReachability, ID: "j1"}},
		Proposed:       PromotionEscalate,
		Fingerprint:    strings.Repeat("b", 64),
		FindingVersion: 2,
		BeforePriority: 3,
		AfterPriority:  2,
	}
	data, err := MarshalClaim(orig)
	if err != nil {
		t.Fatalf("MarshalClaim: %v", err)
	}
	got, err := UnmarshalClaim(data)
	if err != nil {
		t.Fatalf("UnmarshalClaim: %v", err)
	}
	pc, ok := got.(PromotionClaim)
	if !ok {
		t.Fatalf("type = %T, want PromotionClaim", got)
	}
	if pc.FindingID != orig.FindingID {
		t.Errorf("FindingID = %s, want %s", pc.FindingID, orig.FindingID)
	}
	if pc.Rule != orig.Rule {
		t.Errorf("Rule = %s, want %s", pc.Rule, orig.Rule)
	}
	if pc.Proposed != orig.Proposed {
		t.Errorf("Proposed = %s, want %s", pc.Proposed, orig.Proposed)
	}
	if pc.BeforePriority != orig.BeforePriority || pc.AfterPriority != orig.AfterPriority {
		t.Errorf("priority: before=%d,after=%d want %d,%d", pc.BeforePriority, pc.AfterPriority, orig.BeforePriority, orig.AfterPriority)
	}
	if pc.Fingerprint != orig.Fingerprint {
		t.Errorf("Fingerprint mismatch")
	}
}

func TestPromotionClaimMalformed(t *testing.T) {
	fp := strings.Repeat("a", 64)
	cases := []struct {
		name string
		data string
	}{
		{"zero finding id", `{"capability":"promotion","claim":{"finding_id":"","rule":"` + RuleUncertainCorroboration + `","inputs":[{"kind":"reachability_judgment","id":"j1"}],"proposed":"flag_for_review","fingerprint":"` + fp + `","finding_version":1,"before_priority":3,"after_priority":3}}`},
		{"bad rule prefix", `{"capability":"promotion","claim":{"finding_id":"f1","rule":"bad.rule","inputs":[{"kind":"reachability_judgment","id":"j1"}],"proposed":"flag_for_review","fingerprint":"` + fp + `","finding_version":1,"before_priority":3,"after_priority":3}}`},
		{"unknown rule (fail closed)", `{"capability":"promotion","claim":{"finding_id":"f1","rule":RuleUncertainCorroboration,"inputs":[{"kind":"reachability_judgment","id":"j1"}],"proposed":"flag_for_review","fingerprint":"` + fp + `","finding_version":1,"before_priority":3,"after_priority":3}}`},
		{"bad fingerprint", `{"capability":"promotion","claim":{"finding_id":"f1","rule":"` + RuleUncertainCorroboration + `","inputs":[{"kind":"reachability_judgment","id":"j1"}],"proposed":"flag_for_review","fingerprint":"not_hex","finding_version":1,"before_priority":3,"after_priority":3}}`},
		{"no inputs", `{"capability":"promotion","claim":{"finding_id":"f1","rule":"` + RuleUncertainCorroboration + `","inputs":[],"proposed":"flag_for_review","fingerprint":"` + fp + `","finding_version":1,"before_priority":3,"after_priority":3}}`},
		{"rule-effect mismatch: escalate rule with review", `{"capability":"promotion","claim":{"finding_id":"f1","rule":"` + RuleRuntimeReachableExposed + `","inputs":[{"kind":"reachability_judgment","id":"j1"}],"proposed":"flag_for_review","fingerprint":"` + fp + `","finding_version":1,"before_priority":3,"after_priority":3}}`},
		{"rule-effect mismatch: review rule with escalate", `{"capability":"promotion","claim":{"finding_id":"f1","rule":"` + RuleUncertainCorroboration + `","inputs":[{"kind":"reachability_judgment","id":"j1"}],"proposed":"escalate","uncertainty":["inferred_edge"],"fingerprint":"` + fp + `","finding_version":1,"before_priority":3,"after_priority":2}}`},
		{"escalation wrong delta", `{"capability":"promotion","claim":{"finding_id":"f1","rule":"` + RuleRuntimeReachableExposed + `","inputs":[{"kind":"reachability_judgment","id":"j1"}],"proposed":"escalate","fingerprint":"` + fp + `","finding_version":1,"before_priority":3,"after_priority":1}}`},
		{"review changes priority", `{"capability":"promotion","claim":{"finding_id":"f1","rule":"` + RuleUncertainCorroboration + `","inputs":[{"kind":"reachability_judgment","id":"j1"}],"proposed":"flag_for_review","fingerprint":"` + fp + `","finding_version":1,"before_priority":3,"after_priority":2}}`},
		{"smuggled field", `{"capability":"promotion","claim":{"finding_id":"f1","rule":"` + RuleUncertainCorroboration + `","inputs":[{"kind":"reachability_judgment","id":"j1"}],"proposed":"flag_for_review","fingerprint":"` + fp + `","finding_version":1,"before_priority":3,"after_priority":3,"notes":"PROSE LEAK"}}`},
		{"hostile: multi-level de-escalation with deterministic_unreachable rule", `{"capability":"promotion","claim":{"finding_id":"f1","rule":"` + RuleDeterministicUnreachable + `","inputs":[{"kind":"reachability_judgment","id":"j1"}],"proposed":"de_escalate","fingerprint":"` + fp + `","finding_version":1,"before_priority":2,"after_priority":5}}`},
		{"hostile: multi-level de-escalation without prior_promotion input", `{"capability":"promotion","claim":{"finding_id":"f1","rule":"` + RuleCorroboratingSignalLoss + `","inputs":[{"kind":"reachability_judgment","id":"j1"}],"proposed":"de_escalate","fingerprint":"` + fp + `","finding_version":1,"before_priority":2,"after_priority":5}}`},
		{"hostile: de-escalation no movement", `{"capability":"promotion","claim":{"finding_id":"f1","rule":"` + RuleDeterministicUnreachable + `","inputs":[{"kind":"reachability_judgment","id":"j1"}],"proposed":"de_escalate","fingerprint":"` + fp + `","finding_version":1,"before_priority":3,"after_priority":3}}`},
		{"hostile: de-escalation toward P1", `{"capability":"promotion","claim":{"finding_id":"f1","rule":"` + RuleDeterministicUnreachable + `","inputs":[{"kind":"reachability_judgment","id":"j1"}],"proposed":"de_escalate","fingerprint":"` + fp + `","finding_version":1,"before_priority":3,"after_priority":2}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := UnmarshalClaim([]byte(tc.data)); err == nil {
				t.Fatal("want error (fail-closed), got nil")
			} else if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want ErrValidation, got %v", err)
			}
		})
	}
}

func TestPromotionClaimBoundaries(t *testing.T) {
	fp := strings.Repeat("a", 64)
	claim := func(rule string, p PromotionChange, before, after int, inputs ...PromotionInput) PromotionClaim {
		if len(inputs) == 0 {
			inputs = []PromotionInput{{Kind: PromotionInputReachability, ID: "j1"}}
		}
		return PromotionClaim{
			FindingID: "f1", Rule: rule,
			Inputs: inputs, Proposed: p, Fingerprint: fp,
			FindingVersion: 1, BeforePriority: before, AfterPriority: after,
		}
	}

	// Escalation: exactly one level toward P1.
	esc := RuleRuntimeReachableExposed
	if err := claim(esc, PromotionEscalate, 3, 2).Validate(); err != nil {
		t.Errorf("escalate 3->2 should pass: %v", err)
	}
	if err := claim(esc, PromotionEscalate, 3, 1).Validate(); err == nil {
		t.Error("escalate 3->1 (two levels) must fail")
	}
	if err := claim(esc, PromotionEscalate, 1, 0).Validate(); err == nil {
		t.Error("escalate 1->0 must fail (out of range)")
	}

	// De-escalation: ordinary (deterministic_unreachable) must be exactly one level.
	dea := RuleDeterministicUnreachable
	if err := claim(dea, PromotionDeescalate, 3, 4).Validate(); err != nil {
		t.Errorf("de-escalate 3->4 should pass: %v", err)
	}
	if err := claim(dea, PromotionDeescalate, 2, 5).Validate(); err == nil {
		t.Error("ordinary de-escalate 2->5 (multi-level) must fail for deterministic_unreachable")
	}
	if err := claim(dea, PromotionDeescalate, 3, 3).Validate(); err == nil {
		t.Error("de-escalate 3->3 (no movement) must fail")
	}
	if err := claim(dea, PromotionDeescalate, 3, 2).Validate(); err == nil {
		t.Error("de-escalate toward P1 must fail")
	}
	if err := claim(dea, PromotionDeescalate, 3, 6).Validate(); err == nil {
		t.Error("de-escalate past P5 must fail")
	}

	// De-escalation: multi-level reversal (corroborating_signal_loss) with prior_promotion input.
	csl := RuleCorroboratingSignalLoss
	priorInputs := []PromotionInput{
		{Kind: PromotionInputPrior, ID: "evt-1"},
		{Kind: PromotionInputReachability, ID: "j1"},
	}
	if err := claim(csl, PromotionDeescalate, 2, 5, priorInputs...).Validate(); err != nil {
		t.Errorf("signal-loss reversal 2->5 with prior input should pass: %v", err)
	}
	if err := claim(csl, PromotionDeescalate, 2, 5).Validate(); err == nil {
		t.Error("signal-loss reversal without prior_promotion input must fail")
	}

	// Review: same priority only.
	rev := RuleUncertainCorroboration
	if err := claim(rev, PromotionFlagForReview, 3, 3).Validate(); err != nil {
		t.Errorf("review 3->3 should pass: %v", err)
	}
	if err := claim(rev, PromotionFlagForReview, 3, 4).Validate(); err == nil {
		t.Error("review 3->4 must fail")
	}
}

func TestPromotionClaimInputSorting(t *testing.T) {
	fp := strings.Repeat("c", 64)
	sorted := PromotionClaim{
		FindingID: "f1", Rule: RuleUncertainCorroboration,
		Inputs: []PromotionInput{
			{Kind: PromotionInputAttackPath, ID: "ap-1"},
			{Kind: PromotionInputDetection, ID: "det-1"},
			{Kind: PromotionInputReachability, ID: "j1"},
		},
		Proposed: PromotionFlagForReview, Fingerprint: fp,
		FindingVersion: 1, BeforePriority: 3, AfterPriority: 3,
	}
	if err := sorted.Validate(); err != nil {
		t.Errorf("sorted inputs should pass: %v", err)
	}
	unsorted := PromotionClaim{
		FindingID: "f1", Rule: RuleUncertainCorroboration,
		Inputs: []PromotionInput{
			{Kind: PromotionInputDetection, ID: "det-1"},
			{Kind: PromotionInputAttackPath, ID: "ap-1"},
		},
		Proposed: PromotionFlagForReview, Fingerprint: fp,
		FindingVersion: 1, BeforePriority: 3, AfterPriority: 3,
	}
	if err := unsorted.Validate(); err == nil {
		t.Error("unsorted inputs must be rejected")
	}
	dup := PromotionClaim{
		FindingID: "f1", Rule: RuleUncertainCorroboration,
		Inputs: []PromotionInput{
			{Kind: PromotionInputReachability, ID: "j1"},
			{Kind: PromotionInputReachability, ID: "j1"},
		},
		Proposed: PromotionFlagForReview, Fingerprint: fp,
		FindingVersion: 1, BeforePriority: 3, AfterPriority: 3,
	}
	if err := dup.Validate(); err == nil {
		t.Error("duplicate inputs must be rejected")
	}
}

func TestPromotionClaimUncertaintyTokens(t *testing.T) {
	fp := strings.Repeat("d", 64)
	base := PromotionClaim{
		FindingID: "f1", Rule: RuleUncertainCorroboration,
		Inputs:      []PromotionInput{{Kind: PromotionInputReachability, ID: "j1"}},
		Fingerprint: fp, FindingVersion: 1, BeforePriority: 3, AfterPriority: 3,
	}
	sorted := base
	sorted.Proposed = PromotionFlagForReview
	sorted.Uncertainty = []string{"inferred_edge", "unknown_reachability"}
	if err := sorted.Validate(); err != nil {
		t.Errorf("sorted uncertainty + review should pass: %v", err)
	}
	unsorted := base
	unsorted.Proposed = PromotionFlagForReview
	unsorted.Uncertainty = []string{"unknown_reachability", "inferred_edge"}
	if err := unsorted.Validate(); err == nil {
		t.Error("unsorted uncertainty must be rejected")
	}
	escWithUncertainty := base
	escWithUncertainty.Proposed = PromotionEscalate
	escWithUncertainty.AfterPriority = 2
	escWithUncertainty.Uncertainty = []string{"inferred_edge"}
	if err := escWithUncertainty.Validate(); err == nil {
		t.Error("uncertain escalation must be rejected")
	}
}

func TestPromotionClaimJsonEnvelope(t *testing.T) {
	pc := PromotionClaim{
		FindingID: "f1", Rule: RuleUncertainCorroboration,
		Inputs:   []PromotionInput{{Kind: PromotionInputReachability, ID: "j1"}},
		Proposed: PromotionFlagForReview, Fingerprint: strings.Repeat("e", 64),
		FindingVersion: 1, BeforePriority: 3, AfterPriority: 3,
	}
	data, err := MarshalClaim(pc)
	if err != nil {
		t.Fatalf("MarshalClaim: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	var cap string
	if err := json.Unmarshal(raw["capability"], &cap); err != nil {
		t.Fatalf("unmarshal capability: %v", err)
	}
	if cap != "promotion" {
		t.Errorf("capability = %q, want %q", cap, "promotion")
	}
}
