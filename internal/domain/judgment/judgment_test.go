package judgment

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/verdict"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vex"
)

var t0 = time.Unix(0, 0).UTC()

func reach() Claim {
	return ReachabilityClaim{Reachable: "not_reachable", Tier: "tier-1.5", Confidence: 90}
}
func narr() Claim { return RiskNarrativeClaim{Drivers: []string{"kev"}, Priority: 1} }

func TestNew(t *testing.T) {
	j, err := New("j1", "e1", CapReachability, SubjectFinding, "f1", reach(), "agent:s1", t0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if j.State != StateProposed || j.EvidenceScore != 0 {
		t.Fatalf("want proposed/score0, got %s/%d", j.State, j.EvidenceScore)
	}
	if j.ProposedBy != "agent:s1" || j.Version != 1 {
		t.Fatalf("attribution/version not set: %+v", j)
	}

	bad := []struct {
		name string
		fn   func() (Judgment, error)
	}{
		{"no id", func() (Judgment, error) {
			return New("", "e1", CapReachability, SubjectFinding, "f1", reach(), "a", t0)
		}},
		{"bad capability", func() (Judgment, error) {
			return New("j1", "e1", Capability("bogus"), SubjectFinding, "f1", reach(), "a", t0)
		}},
		{"bad subject kind", func() (Judgment, error) {
			return New("j1", "e1", CapReachability, SubjectKind("bogus"), "f1", reach(), "a", t0)
		}},
		{"no subject id", func() (Judgment, error) {
			return New("j1", "e1", CapReachability, SubjectFinding, "", reach(), "a", t0)
		}},
		{"nil claim", func() (Judgment, error) { return New("j1", "e1", CapReachability, SubjectFinding, "f1", nil, "a", t0) }},
		{"claim/capability mismatch", func() (Judgment, error) { return New("j1", "e1", CapSAST, SubjectFinding, "f1", reach(), "a", t0) }},
		{"invalid claim", func() (Judgment, error) {
			return New("j1", "e1", CapReachability, SubjectFinding, "f1", ReachabilityClaim{Reachable: "x", Tier: "tier-0"}, "a", t0)
		}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.fn(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want ErrValidation, got %v", err)
			}
		})
	}
}

func TestApplyVerdict(t *testing.T) {
	base, _ := New("j1", "e1", CapReachability, SubjectFinding, "f1", reach(), "agent:s1", t0)

	got, err := base.ApplyVerdict(verdict.Verdict{Verifier: "human:bob", Score: 80, Rationale: "holds"}, t0)
	if err != nil {
		t.Fatalf("ApplyVerdict: %v", err)
	}
	if got.State != StateConfirmed || got.EvidenceScore != 80 || !got.Publishable() {
		t.Fatalf("want confirmed/80/publishable, got %s/%d/%v", got.State, got.EvidenceScore, got.Publishable())
	}

	got, err = base.ApplyVerdict(verdict.Verdict{Verifier: "human:bob", Score: 40, Rationale: "weak"}, t0)
	if err != nil {
		t.Fatalf("ApplyVerdict: %v", err)
	}
	if got.State != StateRefuted || got.Publishable() {
		t.Fatalf("want refuted/not-publishable, got %s/%v", got.State, got.Publishable())
	}

	if _, err := base.ApplyVerdict(verdict.Verdict{Verifier: "agent:s1", Score: 90, Rationale: "x"}, t0); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("self-confirm: want ErrValidation, got %v", err)
	}
	if _, err := base.ApplyVerdict(verdict.Verdict{Verifier: "", Score: 90, Rationale: "x"}, t0); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("invalid verdict: want ErrValidation, got %v", err)
	}

	ung, _ := New("j2", "e1", CapRiskNarrative, SubjectFinding, "f1", narr(), "agent:s1", t0)
	if _, err := ung.ApplyVerdict(verdict.Verdict{Verifier: "human:bob", Score: 90, Rationale: "x"}, t0); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("ungated ApplyVerdict: want ErrValidation, got %v", err)
	}
}

func TestAccept(t *testing.T) {
	ung, _ := New("j2", "e1", CapRiskNarrative, SubjectFinding, "f1", narr(), "agent:s1", t0)
	got, err := ung.Accept("human:bob", t0)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if got.State != StateConfirmed || !got.Publishable() {
		t.Fatalf("want confirmed/publishable, got %s/%v", got.State, got.Publishable())
	}

	if _, err := ung.Accept("agent:s1", t0); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("self-accept: want ErrValidation, got %v", err)
	}
	gat, _ := New("j1", "e1", CapReachability, SubjectFinding, "f1", reach(), "agent:s1", t0)
	if _, err := gat.Accept("human:bob", t0); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("gated Accept: want ErrValidation, got %v", err)
	}
}

func TestPublishableGate(t *testing.T) {
	// gated + confirmed but below bar must NOT publish (the gate check, not just the state).
	if (Judgment{Capability: CapReachability, State: StateConfirmed, EvidenceScore: 50}).Publishable() {
		t.Fatal("gated confirmed below bar must not be publishable")
	}
	if !(Judgment{Capability: CapReachability, State: StateConfirmed, EvidenceScore: 75}).Publishable() {
		t.Fatal("gated confirmed at bar must be publishable")
	}
	if (Judgment{Capability: CapRiskNarrative, State: StateProposed}).Publishable() {
		t.Fatal("proposed must not be publishable")
	}
}

// TestVerdictOnlyOnProposed: a settled judgment cannot be silently re-opened (MED-2).
func TestVerdictOnlyOnProposed(t *testing.T) {
	base, _ := New("j1", "e1", CapReachability, SubjectFinding, "f1", reach(), "agent:s1", t0)
	confirmed, err := base.ApplyVerdict(verdict.Verdict{Verifier: "human:bob", Score: 90, Rationale: "ok"}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := confirmed.ApplyVerdict(verdict.Verdict{Verifier: "human:eve", Score: 10, Rationale: "flip"}, t0); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("re-verdict a confirmed judgment: want ErrValidation, got %v", err)
	}
	ung, _ := New("j2", "e1", CapRiskNarrative, SubjectFinding, "f1", narr(), "agent:s1", t0)
	acc, _ := ung.Accept("human:bob", t0)
	if _, err := acc.Accept("human:eve", t0); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("re-accept an accepted judgment: want ErrValidation, got %v", err)
	}
}

// TestCapabilityContractExhaustive: insurance against fail-OPEN drift – every capability in the
// closed set must be Valid, have a decoder (a sample claim round-trips), and an explicit gated
// decision. Add new capabilities to this table when you add them.
func TestCapabilityContractExhaustive(t *testing.T) {
	type row struct {
		c      Capability
		sample Claim
		gated  bool
	}
	all := []row{
		{CapReachability, ReachabilityClaim{Reachable: "unknown", Tier: "tier-0", Confidence: 0}, true},
		{CapSAST, SASTClaim{CWE: "CWE-1", Location: "a:1", Rule: "r"}, true},
		{CapCritique, CritiqueClaim{Verdict: CritiqueRefuted, Driver: "version_mismatch", Confidence: 85}, true},
		{CapRiskNarrative, RiskNarrativeClaim{Drivers: []string{"kev"}, Priority: 3}, false},
		{CapThreat, ThreatClaim{Category: Tampering}, true},
		{CapCorrelation, CorrelationClaim{Reporters: []string{"osv"}, Missing: []string{"owned"}}, false},
		{CapVexJustification, VexJustificationClaim{Justification: vex.VulnerableCodeNotPresent}, true},
	}
	for _, tc := range all {
		if !tc.c.Valid() {
			t.Errorf("%s is not Valid()", tc.c)
		}
		if tc.c.Gated() != tc.gated {
			t.Errorf("%s Gated()=%v want %v", tc.c, tc.c.Gated(), tc.gated)
		}
		data, err := MarshalClaim(tc.sample)
		if err != nil {
			t.Errorf("%s has no working encoder: %v", tc.c, err)
			continue
		}
		if _, err := UnmarshalClaim(data); err != nil {
			t.Errorf("%s has no working decoder: %v", tc.c, err)
		}
	}
}
