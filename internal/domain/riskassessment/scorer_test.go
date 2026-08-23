package riskassessment

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func mustScorer(t *testing.T) *Scorer {
	t.Helper()
	s, err := NewScorer(DefaultPolicy())
	if err != nil {
		t.Fatalf("new scorer: %v", err)
	}
	return s
}

func input(threat, exposure, behavior Score, cov CoverageVector) ScoreInput {
	return ScoreInput{AssessmentID: "ra-1", IncidentRevision: 1, Context: RiskContext{threat, exposure, behavior}, Coverage: cov, CreatedAt: time.Unix(1_800_000_000, 0).UTC()}
}

func fullCoverage() CoverageVector {
	return CoverageVector{Process: 100, Network: 100, File: 100, Privilege: 100}
}

// TestScoreRiskIndependentOfCoverage is the central discipline: a high-threat situation seen through a
// partial sensor keeps its high Risk; only Coverage and Confidence fall.
func TestScoreRiskIndependentOfCoverage(t *testing.T) {
	s := mustScorer(t)
	full, err := s.Score(input(90, 0, 0, fullCoverage()))
	if err != nil {
		t.Fatal(err)
	}
	partial, err := s.Score(input(90, 0, 0, CoverageVector{Process: 100, Network: 20, File: 100, Privilege: 100, Reasons: []string{"network sampled"}}))
	if err != nil {
		t.Fatal(err)
	}
	if full.Risk != partial.Risk {
		t.Fatalf("coverage must NOT change Risk: full=%d partial=%d", full.Risk, partial.Risk)
	}
	if partial.Coverage != 20 {
		t.Fatalf("coverage must be the weakest class (20), got %d", partial.Coverage)
	}
	if partial.Confidence >= full.Confidence {
		t.Fatalf("lower coverage must lower Confidence: full=%d partial=%d", full.Confidence, partial.Confidence)
	}
}

func TestScoreThreatDominantNotDiluted(t *testing.T) {
	s := mustScorer(t)
	// Threat 80 alone (weight 100) -> Risk 80, not diluted by zero exposure/behavior.
	got, err := s.Score(input(80, 0, 0, fullCoverage()))
	if err != nil {
		t.Fatal(err)
	}
	if got.Risk != 80 {
		t.Fatalf("threat 80 alone must give Risk 80, got %d", got.Risk)
	}
	// Corroborating factors push Risk up (saturating toward 100).
	more, _ := s.Score(input(80, 50, 50, fullCoverage()))
	if more.Risk <= got.Risk {
		t.Fatalf("corroboration must raise Risk: %d -> %d", got.Risk, more.Risk)
	}
	if more.Risk > 100 {
		t.Fatalf("Risk must clamp at 100, got %d", more.Risk)
	}
}

func TestScoreConfidenceBoundedByCoverage(t *testing.T) {
	s := mustScorer(t)
	// Zero coverage -> zero confidence even with a strong factor.
	zero, err := s.Score(input(90, 0, 0, CoverageVector{}))
	if err != nil {
		t.Fatal(err)
	}
	if zero.Confidence != 0 {
		t.Fatalf("zero coverage must yield zero confidence, got %d", zero.Confidence)
	}
	if zero.Risk == 0 {
		t.Fatal("zero coverage must NOT zero the Risk")
	}
	// Confidence never exceeds coverage floor.
	c, _ := s.Score(input(90, 90, 90, CoverageVector{Process: 40, Network: 40, File: 40, Privilege: 40}))
	if c.Confidence > c.Coverage {
		t.Fatalf("confidence %d must not exceed coverage %d", c.Confidence, c.Coverage)
	}
}

func TestScoreIsDeterministic(t *testing.T) {
	s := mustScorer(t)
	in := input(70, 40, 10, CoverageVector{Process: 80, Network: 60, File: 90, Privilege: 70, Reasons: []string{"stale"}})
	a, err := s.Score(in)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := s.Score(in)
	if a.InputSnapshotHash != b.InputSnapshotHash || a.InputSnapshotHash == "" {
		t.Fatalf("snapshot hash must be deterministic + non-empty: %q vs %q", a.InputSnapshotHash, b.InputSnapshotHash)
	}
	if a.Risk != b.Risk || a.Confidence != b.Confidence || a.Coverage != b.Coverage {
		t.Fatal("scoring must be deterministic")
	}
	if a.ScorerVersion != scorerVersion || a.PolicyVersion != DefaultPolicy().Version {
		t.Fatalf("versions not recorded: scorer=%q policy=%q", a.ScorerVersion, a.PolicyVersion)
	}
	// A different input yields a different snapshot hash.
	other, _ := s.Score(input(71, 40, 10, CoverageVector{Process: 80, Network: 60, File: 90, Privilege: 70}))
	if other.InputSnapshotHash == a.InputSnapshotHash {
		t.Fatal("different input must yield a different snapshot hash")
	}
}

func TestScoreRecordsFactorContributions(t *testing.T) {
	s := mustScorer(t)
	got, _ := s.Score(input(80, 50, 0, fullCoverage()))
	if len(got.FactorContributions) != 2 { // threat + exposure non-zero; behavior 0 omitted
		t.Fatalf("expected 2 factor contributions, got %+v", got.FactorContributions)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("scored assessment must validate: %v", err)
	}
}

func TestScorerValidatesPolicyAndInput(t *testing.T) {
	if _, err := NewScorer(Policy{Version: "", ThreatWeight: 100}); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("policy without version must be rejected")
	}
	if _, err := NewScorer(Policy{Version: "p", ThreatWeight: 200}); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("out-of-range weight must be rejected")
	}
	s := mustScorer(t)
	if _, err := s.Score(ScoreInput{Context: RiskContext{Threat: 50}, Coverage: fullCoverage()}); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("missing assessment id must be rejected")
	}
	if _, err := s.Score(input(200, 0, 0, fullCoverage())); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("out-of-range context must be rejected")
	}
}

func TestSnapshotHashCoversContentButNotIdentityOrClock(t *testing.T) {
	s := mustScorer(t)
	cov := CoverageVector{Process: 80, Network: 60, File: 90, Privilege: 70, Reasons: []string{"stale"}}
	base := ScoreInput{AssessmentID: "ra-1", IncidentRevision: 1, Context: RiskContext{70, 40, 10}, Coverage: cov, CreatedAt: time.Unix(1_800_000_000, 0).UTC()}
	h0, _ := s.Score(base)

	// IncidentRevision is content (bound onto the assessment) -> hash must change.
	rev := base
	rev.IncidentRevision = 2
	if hr, _ := s.Score(rev); hr.InputSnapshotHash == h0.InputSnapshotHash {
		t.Fatal("a different incident revision must change the snapshot hash")
	}
	// Coverage reasons flow into ReasonCodes -> hash must change.
	reasons := base
	reasons.Coverage = CoverageVector{Process: 80, Network: 60, File: 90, Privilege: 70, Reasons: []string{"sampled"}}
	if hr, _ := s.Score(reasons); hr.InputSnapshotHash == h0.InputSnapshotHash {
		t.Fatal("different coverage reasons must change the snapshot hash")
	}
	// AssessmentID and CreatedAt are NOT scoring content -> hash must be reproducible (unchanged).
	repro := base
	repro.AssessmentID = "ra-2"
	repro.CreatedAt = base.CreatedAt.Add(time.Hour)
	if hr, _ := s.Score(repro); hr.InputSnapshotHash != h0.InputSnapshotHash {
		t.Fatal("re-scoring the same inputs (different id/time) must reproduce the same hash")
	}
}

func TestConfidenceCorroborationThreshold(t *testing.T) {
	s := mustScorer(t)
	cov := fullCoverage()
	// A single strong factor.
	one, _ := s.Score(input(80, 0, 0, cov))
	// A near-zero second factor (below minCorroboration) must NOT inflate confidence.
	nearZero, _ := s.Score(input(80, 5, 0, cov))
	if nearZero.Confidence != one.Confidence {
		t.Fatalf("a below-threshold factor must not raise confidence: %d vs %d", one.Confidence, nearZero.Confidence)
	}
	// A genuinely corroborating second factor (>= threshold) raises confidence.
	real, _ := s.Score(input(80, 40, 0, cov))
	if real.Confidence <= one.Confidence {
		t.Fatalf("a real corroborating factor must raise confidence: %d -> %d", one.Confidence, real.Confidence)
	}
}
