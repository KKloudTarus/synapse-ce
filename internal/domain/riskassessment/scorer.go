package riskassessment

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Policy is the versioned weighting the scorer applies. Its Version travels on every RiskAssessment so a
// weight change is auditable and cross-tenant comparability is preserved (a score is only comparable
// within one policy version). Weights are the relative contribution of each RISK factor toward Risk.
type Policy struct {
	Version        string
	ThreatWeight   Score
	ExposureWeight Score
	BehaviorWeight Score
}

// DefaultPolicy is threat-dominant: a runtime threat drives Risk on its own, with exposure and behavior
// corroborating. Tuning is a versioned change (bump Version).
func DefaultPolicy() Policy {
	return Policy{Version: "c3-risk-v1", ThreatWeight: 100, ExposureWeight: 60, BehaviorWeight: 60}
}

// Validate enforces a named policy with in-range weights.
func (p Policy) Validate() error {
	if p.Version == "" {
		return fmt.Errorf("%w: risk policy has no version", shared.ErrValidation)
	}
	return validateScores([]namedScore{
		{"threat weight", p.ThreatWeight}, {"exposure weight", p.ExposureWeight}, {"behavior weight", p.BehaviorWeight},
	}, "risk policy")
}

// ScoreInput is the reproducible input to one scoring run.
type ScoreInput struct {
	AssessmentID     shared.ID
	IncidentRevision int
	Context          RiskContext
	Coverage         CoverageVector
	CreatedAt        time.Time
}

// scorerVersion identifies the scoring ALGORITHM (separate from the Policy weights). Bump it when the
// formula changes, so a stored assessment records exactly how it was computed.
const scorerVersion = "c3-scorer-v1"

// minCorroboration is the floor a factor must reach to count as CORROBORATING evidence for the Confidence
// agreement term. A near-zero factor still contributes to Risk (every non-zero factor does) but must not
// inflate confidence — otherwise a trivially small signal would fake corroboration.
const minCorroboration Score = 10

// Scorer turns runtime signal (a RiskContext) plus observed coverage into a versioned, reproducible
// tri-score RiskAssessment. Its defining discipline: Risk is computed from the RISK factors ONLY —
// coverage never enters the Risk term — so a genuinely dangerous situation seen through a partial sensor
// stays high Risk while its Coverage and Confidence fall. Confidence is bounded by coverage (you cannot be
// confident about data you did not observe); Coverage is the weakest observed class. Fully deterministic:
// the same input + policy always yields the same assessment (captured by InputSnapshotHash).
type Scorer struct {
	policy Policy
}

// NewScorer constructs a scorer over a validated policy.
func NewScorer(policy Policy) (*Scorer, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	return &Scorer{policy: policy}, nil
}

// Score computes the RiskAssessment for one input.
func (s *Scorer) Score(in ScoreInput) (RiskAssessment, error) {
	if in.AssessmentID.IsZero() {
		return RiskAssessment{}, fmt.Errorf("%w: score input has no assessment id", shared.ErrValidation)
	}
	if err := in.Context.Validate(); err != nil {
		return RiskAssessment{}, err
	}
	if err := in.Coverage.Validate(); err != nil {
		return RiskAssessment{}, err
	}

	// Risk: a saturating sum of each factor scaled by its policy weight. A single high factor already
	// yields high Risk (never diluted by an averaging denominator); corroborating factors push toward the
	// 100 ceiling. Coverage is deliberately NOT a term here.
	factors := []struct {
		name   string
		value  Score
		weight Score
	}{
		{"threat", in.Context.Threat, s.policy.ThreatWeight},
		{"exposure", in.Context.Exposure, s.policy.ExposureWeight},
		{"behavior", in.Context.Behavior, s.policy.BehaviorWeight},
	}
	// Each non-zero factor contributes to Risk (recorded for explainability). Note: because Risk saturates
	// at 100, the sum of per-factor Points can exceed the final Risk once saturated — each Point is still a
	// valid explanation of its factor, but an auditor cannot re-derive a saturated Risk by summing them.
	var contributions []FactorContribution
	risk := 0
	corroborating := 0 // factors strong enough to count as corroborating evidence (for Confidence)
	for _, f := range factors {
		pts := int(f.value) * int(f.weight) / 100
		if f.value > 0 {
			contributions = append(contributions, FactorContribution{
				Factor: f.name, Points: clampScore(pts),
				Reason: fmt.Sprintf("%s %d at weight %d", f.name, f.value, f.weight),
			})
		}
		if f.value >= minCorroboration {
			corroborating++
		}
		risk += pts
	}
	riskScore := clampScore(risk)

	// Coverage: the weakest observed class (honest scalar of the vector).
	coverage := in.Coverage.Floor()

	// Confidence: bounded by coverage (no data -> no confidence), scaled by CORROBORATION BREADTH — the
	// number of independent factors strong enough to count (not their agreement in magnitude). One factor
	// is weaker evidence than several corroborating: 1 -> 50%, 2 -> 75%, 3 -> 100%.
	breadth := 50 + 25*(min(corroborating, 3)-1)
	if corroborating == 0 {
		breadth = 0
	}
	confidence := clampScore(int(coverage) * breadth / 100)

	reasons := append([]string(nil), in.Coverage.Reasons...)
	for _, c := range contributions {
		reasons = append(reasons, c.Factor)
	}

	ra := RiskAssessment{
		AssessmentID:        in.AssessmentID,
		IncidentRevision:    in.IncidentRevision,
		ScorerVersion:       scorerVersion,
		PolicyVersion:       s.policy.Version,
		InputSnapshotHash:   s.snapshotHash(in),
		Risk:                riskScore,
		Confidence:          confidence,
		Coverage:            coverage,
		CoverageVector:      in.Coverage,
		Context:             in.Context,
		FactorContributions: contributions,
		ReasonCodes:         reasons,
		CreatedAt:           in.CreatedAt,
	}
	if err := ra.Validate(); err != nil {
		return RiskAssessment{}, err
	}
	return ra, nil
}

// snapshotHash is a deterministic digest of everything that determines the produced assessment's content:
// the algorithm + policy versions and weights, the three factors, the four coverage classes, the incident
// revision the assessment is bound to, and the coverage reasons (which flow into ReasonCodes). It is
// domain-separated and length-prefixed (no concatenation collision). It deliberately EXCLUDES AssessmentID
// and CreatedAt so that re-scoring the same inputs reproduces the same hash (the point of a reproducibility
// digest); the tamper-evidence of the identity/timestamp is the append-only incident event log's job (C7),
// not this hash.
func (s *Scorer) snapshotHash(in ScoreInput) string {
	h := sha256.New()
	write := func(p string) {
		var lp [8]byte
		binary.BigEndian.PutUint64(lp[:], uint64(len(p)))
		_, _ = h.Write(lp[:])
		_, _ = io.WriteString(h, p)
	}
	for _, p := range []string{
		"riskassessment:snapshot:v1", scorerVersion, s.policy.Version,
		strconv.Itoa(int(s.policy.ThreatWeight)), strconv.Itoa(int(s.policy.ExposureWeight)), strconv.Itoa(int(s.policy.BehaviorWeight)),
		strconv.Itoa(int(in.Context.Threat)), strconv.Itoa(int(in.Context.Exposure)), strconv.Itoa(int(in.Context.Behavior)),
		strconv.Itoa(int(in.Coverage.Process)), strconv.Itoa(int(in.Coverage.Network)), strconv.Itoa(int(in.Coverage.File)), strconv.Itoa(int(in.Coverage.Privilege)),
		strconv.Itoa(in.IncidentRevision),
	} {
		write(p)
	}
	// Coverage reasons affect the assessment's ReasonCodes, so they are part of the content: count-prefixed
	// then each length-prefixed, so a different set of reasons yields a different hash.
	write(strconv.Itoa(len(in.Coverage.Reasons)))
	for _, r := range in.Coverage.Reasons {
		write(r)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func clampScore(v int) Score {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return Score(v)
}
