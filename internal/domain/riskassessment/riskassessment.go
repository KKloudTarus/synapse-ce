// Package riskassessment is the pure-domain tri-score risk model for Phase C of the EDR data plane
// (#594, C3 #677). Its central discipline: Risk, Confidence, and Coverage are THREE DIFFERENT THINGS and
// are carried as separate fields — Risk is how dangerous the situation is if real, Confidence is how
// strong/consistent the evidence is, and Coverage is how much of the data needed to judge it was actually
// observed. Missing coverage lowers Coverage (and may lower Confidence) but must NEVER silently lower
// Risk: a high-risk situation seen through a partial sensor is (Risk 88 / Confidence 61 / Coverage 43),
// never a diluted Risk 47.
//
// This package defines the value types (RiskContext, CoverageVector, RiskAssessment) and their validation.
// The deterministic scorer that produces a RiskAssessment from inputs is C3, built on top of these types.
package riskassessment

import (
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Score is a normalized 0..100 factor. It is deliberately not a float: risk scoring here is deterministic
// and reproducible, and integer points avoid float non-determinism in hashing/equality.
type Score int

// Valid reports whether the score is within 0..100.
func (s Score) Valid() bool { return s >= 0 && s <= 100 }

// RiskContext carries the three independent RISK factors that feed a RiskAssessment. Each is owned by a
// different pillar: Threat by Phase C runtime detection/correlation, Exposure by continuous-exposure
// fusion (X5 #634), Behavior by behavioral EDR (D #639). Exposure/Behavior are zero until those pillars
// fill them — which lowers Coverage (a factor was not observed), never Risk.
type RiskContext struct {
	Threat   Score
	Exposure Score
	Behavior Score
}

// namedScore pairs a field name with its score for fixed-order validation (so the error message is
// deterministic when more than one field is out of range).
type namedScore struct {
	name  string
	score Score
}

func validateScores(scores []namedScore, subject string) error {
	for _, ns := range scores {
		if !ns.score.Valid() {
			return fmt.Errorf("%w: %s %s score %d out of range", shared.ErrValidation, subject, ns.name, ns.score)
		}
	}
	return nil
}

// Validate enforces in-range factor scores.
func (c RiskContext) Validate() error {
	return validateScores([]namedScore{
		{"threat", c.Threat}, {"exposure", c.Exposure}, {"behavior", c.Behavior},
	}, "risk context")
}

// CoverageVector is coverage as a VECTOR, per telemetry class, not a scalar — so "we saw all the process
// events but no network events" is representable and not averaged away. Reasons carries WHY coverage is
// below full (a gap, a sampled window, staleness); uncertainty is carried, never flattened.
type CoverageVector struct {
	Process   Score
	Network   Score
	File      Score
	Privilege Score
	Reasons   []string
}

// Validate enforces in-range per-class coverage.
func (v CoverageVector) Validate() error {
	return validateScores([]namedScore{
		{"process", v.Process}, {"network", v.Network}, {"file", v.File}, {"privilege", v.Privilege},
	}, "coverage")
}

// Floor returns the minimum per-class coverage — the honest scalar summary of the vector (the weakest
// class bounds how much of the picture was observed). It never inflates coverage by averaging.
func (v CoverageVector) Floor() Score {
	floor := v.Process
	for _, s := range []Score{v.Network, v.File, v.Privilege} {
		if s < floor {
			floor = s
		}
	}
	return floor
}

// FactorContribution is one weighted input to the Risk score, with a human reason — so a Risk value is
// always explainable back to what drove it.
type FactorContribution struct {
	Factor string
	Points Score
	Reason string
}

// RiskAssessment is a versioned, reproducible tri-score risk judgment for an incident revision. It is
// produced by the C3 scorer and carried on the incident via a RiskReassessed event. InputSnapshotHash +
// ScorerVersion + PolicyVersion make it reproducible and auditable; a weight change is a version change,
// preserving cross-tenant comparability.
type RiskAssessment struct {
	AssessmentID        shared.ID
	IncidentRevision    int
	ScorerVersion       string
	PolicyVersion       string
	InputSnapshotHash   string
	Risk                Score
	Confidence          Score
	Coverage            Score
	CoverageVector      CoverageVector
	Context             RiskContext
	FactorContributions []FactorContribution
	ReasonCodes         []string
	CreatedAt           time.Time
}

// Validate enforces a well-formed assessment: an id, in-range tri-scores, a valid context + coverage
// vector, and version metadata.
func (r RiskAssessment) Validate() error {
	if r.AssessmentID.IsZero() {
		return fmt.Errorf("%w: risk assessment has no id", shared.ErrValidation)
	}
	if r.ScorerVersion == "" || r.PolicyVersion == "" {
		return fmt.Errorf("%w: risk assessment must record scorer and policy versions", shared.ErrValidation)
	}
	if err := validateScores([]namedScore{
		{"risk", r.Risk}, {"confidence", r.Confidence}, {"coverage", r.Coverage},
	}, "risk assessment"); err != nil {
		return err
	}
	if err := r.Context.Validate(); err != nil {
		return err
	}
	if err := r.CoverageVector.Validate(); err != nil {
		return err
	}
	for _, fc := range r.FactorContributions {
		if !fc.Points.Valid() {
			return fmt.Errorf("%w: factor %q points %d out of range", shared.ErrValidation, fc.Factor, fc.Points)
		}
	}
	return nil
}

// Clone returns a deep copy so a caller cannot mutate the assessment held on an incident projection.
func (r RiskAssessment) Clone() RiskAssessment {
	c := r
	c.CoverageVector.Reasons = append([]string(nil), r.CoverageVector.Reasons...)
	c.FactorContributions = append([]FactorContribution(nil), r.FactorContributions...)
	c.ReasonCodes = append([]string(nil), r.ReasonCodes...)
	return c
}
