package riskassessment

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func valid() RiskAssessment {
	return RiskAssessment{
		AssessmentID: "ra-1", ScorerVersion: "v1", PolicyVersion: "p1",
		Risk: 88, Confidence: 61, Coverage: 43,
		CoverageVector: CoverageVector{Process: 90, Network: 43, File: 80, Privilege: 70, Reasons: []string{"network sampled"}},
		Context:        RiskContext{Threat: 88, Exposure: 0, Behavior: 0},
	}
}

func TestRiskAssessmentValidate(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatalf("valid assessment rejected: %v", err)
	}
	mut := func(f func(*RiskAssessment)) RiskAssessment { r := valid(); f(&r); return r }
	bad := map[string]RiskAssessment{
		"no id":        mut(func(r *RiskAssessment) { r.AssessmentID = "" }),
		"no scorer":    mut(func(r *RiskAssessment) { r.ScorerVersion = "" }),
		"no policy":    mut(func(r *RiskAssessment) { r.PolicyVersion = "" }),
		"risk oob":     mut(func(r *RiskAssessment) { r.Risk = 101 }),
		"coverage oob": mut(func(r *RiskAssessment) { r.Coverage = -1 }),
		"vector oob":   mut(func(r *RiskAssessment) { r.CoverageVector.Network = 200 }),
		"context oob":  mut(func(r *RiskAssessment) { r.Context.Exposure = 500 }),
	}
	for name, r := range bad {
		if err := r.Validate(); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("%s must be rejected, got %v", name, err)
		}
	}
}

// TestTriScoreSeparation is the core discipline: a genuinely dangerous situation seen through a partial
// sensor is high Risk / lower Confidence / low Coverage — the low coverage does NOT force Risk down. The
// value type permits (and validates) that combination.
func TestTriScoreSeparation(t *testing.T) {
	r := valid() // Risk 88, Confidence 61, Coverage 43
	if err := r.Validate(); err != nil {
		t.Fatalf("high-risk low-coverage must be valid: %v", err)
	}
	if r.Risk != 88 || r.Coverage != 43 {
		t.Fatal("Risk and Coverage must be independent fields")
	}
}

func TestCoverageVectorFloor(t *testing.T) {
	v := CoverageVector{Process: 90, Network: 43, File: 80, Privilege: 70}
	if v.Floor() != 43 {
		t.Fatalf("floor must be the weakest class, got %d", v.Floor())
	}
}

func TestRiskAssessmentCloneIsDeep(t *testing.T) {
	r := valid()
	r.ReasonCodes = []string{"kev"}
	r.FactorContributions = []FactorContribution{{Factor: "threat", Points: 88, Reason: "detection"}}
	c := r.Clone()
	c.CoverageVector.Reasons[0] = "mutated"
	c.ReasonCodes[0] = "mutated"
	c.FactorContributions[0].Reason = "mutated"
	if r.CoverageVector.Reasons[0] == "mutated" || r.ReasonCodes[0] == "mutated" || r.FactorContributions[0].Reason == "mutated" {
		t.Fatal("Clone must deep-copy slices")
	}
}
