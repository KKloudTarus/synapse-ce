package judgment

import (
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
		RiskNarrativeClaim{Drivers: []string{"kev", "cvss>=9"}, Priority: 1},
		CritiqueClaim{Verdict: CritiqueRefuted, Driver: "version_mismatch", Confidence: 85},
		ThreatClaim{Category: InfoDisclosure, Asset: "pii"},
		ThreatClaim{Category: Spoofing}, // asset optional
		CorrelationClaim{Reporters: []string{"osv"}, Missing: []string{"advisory-store"}},
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
		t.Error("no missing source → not a disagreement → must be rejected")
	}
	if err := (CorrelationClaim{Missing: []string{"owned"}}).Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Error("no reporters → must be rejected")
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
	// same tier does NOT supersede (no churn) – even if the new verdict disagrees
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
	// Strength ordering must be strictly increasing – supersession compares ranks.
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
