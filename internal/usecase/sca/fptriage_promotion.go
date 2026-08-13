package sca

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"reflect"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
)

const aiEvaluationComparisonSchema = "synapse-ai-triage-comparison-v1"

// AIEvaluationPromotionPolicy is an operator-approved, deterministic quality gate for comparing a
// candidate shadow run with a baseline run. Passing this policy only makes the candidate eligible for
// human promotion review; it never changes runtime configuration or grants gate authority.
type AIEvaluationPromotionPolicy struct {
	MinimumPrecisionBasisPoints               int `json:"minimum_precision_basis_points"`
	MaximumFalseNegativeEscapeRateBasisPoints int `json:"maximum_false_negative_escape_rate_basis_points"`
	MaximumPrecisionDropBasisPoints           int `json:"maximum_precision_drop_basis_points"`
	MaximumRecallDropBasisPoints              int `json:"maximum_recall_drop_basis_points"`
	MaximumCoverageDropBasisPoints            int `json:"maximum_coverage_drop_basis_points"`
	MaximumVerifierCoverageDropBasisPoints    int `json:"maximum_verifier_coverage_drop_basis_points"`
	MaximumDisagreementIncreaseBasisPoints    int `json:"maximum_disagreement_increase_basis_points"`
}

// DefaultAIEvaluationPromotionPolicy returns the conservative proposed threshold from the AI-triage
// epic: at least 95% precision, zero true-positive escapes, and no regression versus the baseline.
// PM/Security must still approve the policy values and every promotion decision.
func DefaultAIEvaluationPromotionPolicy() AIEvaluationPromotionPolicy {
	return AIEvaluationPromotionPolicy{MinimumPrecisionBasisPoints: 9500}
}

// Validate rejects ambiguous or impossible basis-point thresholds.
func (p AIEvaluationPromotionPolicy) Validate() error {
	values := []struct {
		name  string
		value int
	}{
		{"minimum precision", p.MinimumPrecisionBasisPoints},
		{"maximum false-negative escape rate", p.MaximumFalseNegativeEscapeRateBasisPoints},
		{"maximum precision drop", p.MaximumPrecisionDropBasisPoints},
		{"maximum recall drop", p.MaximumRecallDropBasisPoints},
		{"maximum coverage drop", p.MaximumCoverageDropBasisPoints},
		{"maximum verifier coverage drop", p.MaximumVerifierCoverageDropBasisPoints},
		{"maximum disagreement increase", p.MaximumDisagreementIncreaseBasisPoints},
	}
	for _, item := range values {
		if item.value < 0 || item.value > 10_000 {
			return fmt.Errorf("AI evaluation promotion policy %s must be between 0 and 10000 basis points", item.name)
		}
	}
	return nil
}

// AIEvaluationMetricComparison records exact counters plus integer basis-point deltas. Integer deltas
// avoid float-tolerance ambiguity in CI and promotion approval records.
type AIEvaluationMetricComparison struct {
	Baseline                            AIEvaluationMetrics `json:"baseline"`
	Candidate                           AIEvaluationMetrics `json:"candidate"`
	PrecisionDeltaBasisPoints           int                 `json:"precision_delta_basis_points"`
	RecallDeltaBasisPoints              int                 `json:"recall_delta_basis_points"`
	FalseNegativeEscapeDeltaBasisPoints int                 `json:"false_negative_escape_delta_basis_points"`
	DisagreementDeltaBasisPoints        int                 `json:"disagreement_delta_basis_points"`
	CoverageDeltaBasisPoints            int                 `json:"coverage_delta_basis_points"`
	VerifierCoverageDeltaBasisPoints    int                 `json:"verifier_coverage_delta_basis_points"`
}

// AIEvaluationCaseOutcome is the source-free typed behavior exposed for one changed golden case.
type AIEvaluationCaseOutcome struct {
	Covered                bool   `json:"covered"`
	ConsensusFalsePositive bool   `json:"consensus_false_positive"`
	WouldGateExempt        bool   `json:"would_gate_exempt"`
	Verdict                string `json:"verdict,omitempty"`
	Driver                 string `json:"driver,omitempty"`
	Confidence             int    `json:"confidence,omitempty"`
	VerifierVerdict        string `json:"verifier_verdict,omitempty"`
	VerifierDriver         string `json:"verifier_driver,omitempty"`
	VerifierConfidence     int    `json:"verifier_confidence,omitempty"`
}

// AIEvaluationCaseChange makes model behavior changes reviewable without copying source or prompt text
// into the comparison artifact.
type AIEvaluationCaseChange struct {
	CaseID    string                  `json:"case_id"`
	Label     AIEvaluationLabel       `json:"label"`
	Language  string                  `json:"language"`
	CWE       string                  `json:"cwe"`
	Baseline  AIEvaluationCaseOutcome `json:"baseline"`
	Candidate AIEvaluationCaseOutcome `json:"candidate"`
}

// AIEvaluationPromotionFailure is a stable machine-readable reason a candidate cannot proceed to
// human promotion review. Scope is "overall", "case", or a report breakdown dimension.
type AIEvaluationPromotionFailure struct {
	Rule                 string `json:"rule"`
	Scope                string `json:"scope"`
	Segment              string `json:"segment,omitempty"`
	CaseID               string `json:"case_id,omitempty"`
	BaselineBasisPoints  int    `json:"baseline_basis_points"`
	CandidateBasisPoints int    `json:"candidate_basis_points"`
	LimitBasisPoints     int    `json:"limit_basis_points"`
}

// AIEvaluationComparison is deterministic CI evidence for a candidate-vs-baseline decision. A clean
// comparison has status review_required: automatic promotion is deliberately not represented.
type AIEvaluationComparison struct {
	SchemaVersion    string                                             `json:"schema_version"`
	ComparisonID     string                                             `json:"comparison_id"`
	Status           string                                             `json:"status"`
	ApprovalRequired bool                                               `json:"approval_required"`
	DatasetVersion   string                                             `json:"dataset_version"`
	DatasetSHA256    string                                             `json:"dataset_sha256"`
	Provenance       string                                             `json:"provenance"`
	Reviewer         string                                             `json:"reviewer"`
	BaselineRunID    string                                             `json:"baseline_run_id"`
	CandidateRunID   string                                             `json:"candidate_run_id"`
	BaselineRun      AIEvaluationRun                                    `json:"baseline_run"`
	CandidateRun     AIEvaluationRun                                    `json:"candidate_run"`
	Policy           AIEvaluationPromotionPolicy                        `json:"policy"`
	Metrics          AIEvaluationMetricComparison                       `json:"metrics"`
	Breakdowns       map[string]map[string]AIEvaluationMetricComparison `json:"breakdowns"`
	CaseChanges      []AIEvaluationCaseChange                           `json:"case_changes"`
	Failures         []AIEvaluationPromotionFailure                     `json:"failures"`
}

// LoadAIEvaluationReport strictly decodes and revalidates a report before it is used for a promotion
// decision. Metrics, breakdowns, shadow invariants, model identity, and run ID are all recomputed.
func LoadAIEvaluationReport(data []byte) (AIEvaluationReport, error) {
	var report AIEvaluationReport
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil {
		return report, fmt.Errorf("decode AI evaluation report: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return report, fmt.Errorf("decode AI evaluation report: trailing JSON content")
	}
	if err := report.Validate(); err != nil {
		return report, err
	}
	return report, nil
}

// Validate checks that an evaluation report is internally consistent and remains a shadow-only
// artifact. It is intentionally strict because the comparison can become promotion evidence.
func (r AIEvaluationReport) Validate() error {
	if r.SchemaVersion != aiEvaluationReportSchema || strings.TrimSpace(r.RunID) == "" ||
		strings.TrimSpace(r.DatasetVersion) == "" || r.DatasetVersion != strings.TrimSpace(r.DatasetVersion) ||
		!validEvaluationSHA256(r.DatasetSHA256) || strings.TrimSpace(r.Provenance) == "" ||
		r.Provenance != strings.TrimSpace(r.Provenance) || strings.TrimSpace(r.Reviewer) == "" ||
		r.Reviewer != strings.TrimSpace(r.Reviewer) || len(r.Results) == 0 {
		return fmt.Errorf("AI evaluation report requires the v2 schema, run/dataset identity, provenance, reviewer, and results")
	}
	if r.Run.ProposerProvider == "" || r.Run.ProposerProvider != agent.CanonicalProviderID(r.Run.ProposerProvider) ||
		strings.TrimSpace(r.Run.ProposerModel) == "" || r.Run.ProposerModel != strings.TrimSpace(r.Run.ProposerModel) ||
		r.Run.VerifierProvider == "" || r.Run.VerifierProvider != agent.CanonicalProviderID(r.Run.VerifierProvider) ||
		strings.TrimSpace(r.Run.VerifierModel) == "" || r.Run.VerifierModel != strings.TrimSpace(r.Run.VerifierModel) ||
		strings.TrimSpace(r.Run.PromptVersion) == "" || r.Run.PromptVersion != strings.TrimSpace(r.Run.PromptVersion) ||
		strings.TrimSpace(r.Run.PolicyVersion) == "" || r.Run.PolicyVersion != strings.TrimSpace(r.Run.PolicyVersion) ||
		!agent.IndependentLLMs(r.Run.ProposerProvider, r.Run.ProposerModel, r.Run.VerifierProvider, r.Run.VerifierModel, string(r.Run.IndependencePolicy)) {
		return fmt.Errorf("AI evaluation report has an incomplete or non-independent run identity")
	}
	seen := make(map[string]struct{}, len(r.Results))
	for i, result := range r.Results {
		caseID := strings.TrimSpace(result.CaseID)
		if caseID == "" || caseID != result.CaseID {
			return fmt.Errorf("AI evaluation report result %d has an invalid case id", i)
		}
		if _, exists := seen[caseID]; exists {
			return fmt.Errorf("AI evaluation report case %q is duplicated", caseID)
		}
		seen[caseID] = struct{}{}
		if result.Label != AIEvaluationTruePositive && result.Label != AIEvaluationFalsePositive && result.Label != AIEvaluationUncertain {
			return fmt.Errorf("AI evaluation report case %q has invalid label %q", caseID, result.Label)
		}
		if (result.Kind != finding.KindSAST && result.Kind != finding.KindMisconfig) || !result.Severity.Valid() ||
			strings.TrimSpace(result.Language) == "" || strings.TrimSpace(result.Framework) == "" {
			return fmt.Errorf("AI evaluation report case %q has incomplete dimensions", caseID)
		}
		if result.GateExempt || result.Critique.GateExempt {
			return fmt.Errorf("AI evaluation report case %q is not shadow-only", caseID)
		}
		if !result.Covered {
			if result.ConsensusFalsePositive || result.WouldGateExempt || strings.TrimSpace(result.Critique.DedupKey) != "" {
				return fmt.Errorf("AI evaluation report uncovered case %q contains a model decision", caseID)
			}
			continue
		}
		critique := result.Critique
		if critique.DedupKey != "ai-eval:"+caseID || !critique.Shadow ||
			!agent.SameModel(critique.ProposerModel, r.Run.ProposerModel) ||
			!agent.SameModel(critique.VerifierModel, r.Run.VerifierModel) ||
			critique.ProposerProvider != agent.CanonicalProviderID(r.Run.ProposerProvider) ||
			critique.VerifierProvider != agent.CanonicalProviderID(r.Run.VerifierProvider) ||
			critique.ProposerModelFamily != agent.CanonicalModelID(r.Run.ProposerModel) ||
			critique.VerifierModelFamily != agent.CanonicalModelID(r.Run.VerifierModel) ||
			critique.IndependencePolicy != r.Run.IndependencePolicy || critique.PromptVersion != r.Run.PromptVersion ||
			critique.PolicyVersion != r.Run.PolicyVersion || result.ConsensusFalsePositive != hasVerifiedConsensus(critique) ||
			result.WouldGateExempt != critique.WouldGateExempt {
			return fmt.Errorf("AI evaluation report case %q has inconsistent model or policy metadata", caseID)
		}
	}
	if want := evaluationMetrics(r.Results); !reflect.DeepEqual(r.Metrics, want) {
		return fmt.Errorf("AI evaluation report aggregate metrics do not match its results")
	}
	if want := evaluationBreakdowns(r.Results); !reflect.DeepEqual(r.Breakdowns, want) {
		return fmt.Errorf("AI evaluation report breakdowns do not match its results")
	}
	if want := evaluationRunID(r); r.RunID != want {
		return fmt.Errorf("AI evaluation report run id does not match its canonical content")
	}
	return nil
}

// CompareAIEvaluationReports compares a candidate against the exact same golden corpus and policy.
// It rejects apples-to-oranges inputs and returns a deterministic blocked/review_required artifact.
func CompareAIEvaluationReports(baseline, candidate AIEvaluationReport, policy AIEvaluationPromotionPolicy) (AIEvaluationComparison, error) {
	if err := policy.Validate(); err != nil {
		return AIEvaluationComparison{}, err
	}
	if err := baseline.Validate(); err != nil {
		return AIEvaluationComparison{}, fmt.Errorf("baseline: %w", err)
	}
	if err := candidate.Validate(); err != nil {
		return AIEvaluationComparison{}, fmt.Errorf("candidate: %w", err)
	}
	if baseline.DatasetVersion != candidate.DatasetVersion || baseline.DatasetSHA256 != candidate.DatasetSHA256 ||
		baseline.Provenance != candidate.Provenance || baseline.Reviewer != candidate.Reviewer {
		return AIEvaluationComparison{}, fmt.Errorf("AI evaluation comparison requires the exact same reviewed dataset")
	}
	if baseline.Run.PolicyVersion != candidate.Run.PolicyVersion || baseline.Run.IndependencePolicy != candidate.Run.IndependencePolicy {
		return AIEvaluationComparison{}, fmt.Errorf("AI evaluation comparison requires the same gate policy and independence policy")
	}
	if sameEvaluationConfiguration(baseline.Run, candidate.Run) {
		return AIEvaluationComparison{}, fmt.Errorf("AI evaluation candidate must change a provider, model family, or prompt version")
	}

	baselineCases := make(map[string]AIEvaluationResult, len(baseline.Results))
	for _, result := range baseline.Results {
		baselineCases[result.CaseID] = result
	}
	for _, result := range candidate.Results {
		before, ok := baselineCases[result.CaseID]
		if !ok || !sameEvaluationCase(before, result) {
			return AIEvaluationComparison{}, fmt.Errorf("AI evaluation candidate case %q does not match the baseline corpus", result.CaseID)
		}
		delete(baselineCases, result.CaseID)
	}
	if len(baselineCases) != 0 {
		return AIEvaluationComparison{}, fmt.Errorf("AI evaluation candidate is missing baseline cases")
	}

	comparison := AIEvaluationComparison{
		SchemaVersion: aiEvaluationComparisonSchema, Status: "review_required", ApprovalRequired: true,
		DatasetVersion: baseline.DatasetVersion, DatasetSHA256: baseline.DatasetSHA256,
		Provenance: baseline.Provenance, Reviewer: baseline.Reviewer,
		BaselineRunID: baseline.RunID, CandidateRunID: candidate.RunID,
		BaselineRun: baseline.Run, CandidateRun: candidate.Run, Policy: policy,
		Metrics:     metricComparison(baseline.Metrics, candidate.Metrics),
		Breakdowns:  make(map[string]map[string]AIEvaluationMetricComparison, len(baseline.Breakdowns)),
		CaseChanges: []AIEvaluationCaseChange{}, Failures: []AIEvaluationPromotionFailure{},
	}
	comparison.Failures = appendOverallPromotionFailures(comparison.Failures, comparison.Metrics, policy)

	dimensions := sortedKeys(baseline.Breakdowns)
	for _, dimension := range dimensions {
		baselineSegments := baseline.Breakdowns[dimension]
		candidateSegments, ok := candidate.Breakdowns[dimension]
		if !ok || len(candidateSegments) != len(baselineSegments) {
			return AIEvaluationComparison{}, fmt.Errorf("AI evaluation candidate breakdown %q does not match the baseline", dimension)
		}
		comparison.Breakdowns[dimension] = make(map[string]AIEvaluationMetricComparison, len(baselineSegments))
		for _, segment := range sortedKeys(baselineSegments) {
			candidateMetrics, exists := candidateSegments[segment]
			if !exists {
				return AIEvaluationComparison{}, fmt.Errorf("AI evaluation candidate breakdown %q/%q is missing", dimension, segment)
			}
			metrics := metricComparison(baselineSegments[segment], candidateMetrics)
			comparison.Breakdowns[dimension][segment] = metrics
			comparison.Failures = appendRegressionFailures(comparison.Failures, dimension, segment, metrics, policy)
		}
	}

	candidateByID := make(map[string]AIEvaluationResult, len(candidate.Results))
	for _, result := range candidate.Results {
		candidateByID[result.CaseID] = result
	}
	baselineIDs := make([]string, 0, len(baseline.Results))
	for _, result := range baseline.Results {
		baselineIDs = append(baselineIDs, result.CaseID)
	}
	sort.Strings(baselineIDs)
	for _, caseID := range baselineIDs {
		before, after := baselineResult(baseline.Results, caseID), candidateByID[caseID]
		beforeOutcome, afterOutcome := evaluationCaseOutcome(before), evaluationCaseOutcome(after)
		if beforeOutcome != afterOutcome {
			comparison.CaseChanges = append(comparison.CaseChanges, AIEvaluationCaseChange{
				CaseID: caseID, Label: before.Label, Language: before.Language, CWE: before.CWE,
				Baseline: beforeOutcome, Candidate: afterOutcome,
			})
		}
		if after.Label == AIEvaluationTruePositive && after.WouldGateExempt && !before.WouldGateExempt {
			comparison.Failures = append(comparison.Failures, AIEvaluationPromotionFailure{
				Rule: "new_true_positive_escape", Scope: "case", CaseID: caseID,
				BaselineBasisPoints:  boolBasisPoints(before.WouldGateExempt),
				CandidateBasisPoints: boolBasisPoints(after.WouldGateExempt), LimitBasisPoints: 0,
			})
		}
	}
	if len(comparison.Failures) != 0 {
		comparison.Status = "blocked"
	}
	comparison.ComparisonID = evaluationComparisonID(comparison)
	return comparison, nil
}

func appendOverallPromotionFailures(failures []AIEvaluationPromotionFailure, metrics AIEvaluationMetricComparison, policy AIEvaluationPromotionPolicy) []AIEvaluationPromotionFailure {
	candidatePrecision := ratioToBasisPoints(metrics.Candidate.Precision)
	if belowBasisPointMinimum(metrics.Candidate.CorrectFalsePositives, metrics.Candidate.ConsensusFalsePositives, policy.MinimumPrecisionBasisPoints) {
		failures = append(failures, AIEvaluationPromotionFailure{Rule: "minimum_precision", Scope: "overall", BaselineBasisPoints: ratioToBasisPoints(metrics.Baseline.Precision), CandidateBasisPoints: candidatePrecision, LimitBasisPoints: policy.MinimumPrecisionBasisPoints})
	}
	candidateEscape := ratioToBasisPoints(metrics.Candidate.FalseNegativeEscapeRate)
	if aboveBasisPointMaximum(metrics.Candidate.TruePositiveEscapes, metrics.Candidate.HumanTruePositives, policy.MaximumFalseNegativeEscapeRateBasisPoints) {
		failures = append(failures, AIEvaluationPromotionFailure{Rule: "maximum_false_negative_escape_rate", Scope: "overall", BaselineBasisPoints: ratioToBasisPoints(metrics.Baseline.FalseNegativeEscapeRate), CandidateBasisPoints: candidateEscape, LimitBasisPoints: policy.MaximumFalseNegativeEscapeRateBasisPoints})
	}
	return appendRegressionFailures(failures, "overall", "", metrics, policy)
}

func appendRegressionFailures(failures []AIEvaluationPromotionFailure, scope, segment string, metrics AIEvaluationMetricComparison, policy AIEvaluationPromotionPolicy) []AIEvaluationPromotionFailure {
	tests := []struct {
		rule      string
		baseline  int
		candidate int
		limit     int
		regressed bool
	}{
		{"precision_regression", ratioToBasisPoints(metrics.Baseline.Precision), ratioToBasisPoints(metrics.Candidate.Precision), policy.MaximumPrecisionDropBasisPoints, basisPointDropExceeds(metrics.Baseline.CorrectFalsePositives, metrics.Baseline.ConsensusFalsePositives, metrics.Candidate.CorrectFalsePositives, metrics.Candidate.ConsensusFalsePositives, policy.MaximumPrecisionDropBasisPoints)},
		{"recall_regression", ratioToBasisPoints(metrics.Baseline.Recall), ratioToBasisPoints(metrics.Candidate.Recall), policy.MaximumRecallDropBasisPoints, basisPointDropExceeds(metrics.Baseline.CorrectFalsePositives, metrics.Baseline.HumanFalsePositives, metrics.Candidate.CorrectFalsePositives, metrics.Candidate.HumanFalsePositives, policy.MaximumRecallDropBasisPoints)},
		{"coverage_regression", ratioToBasisPoints(metrics.Baseline.Coverage), ratioToBasisPoints(metrics.Candidate.Coverage), policy.MaximumCoverageDropBasisPoints, basisPointDropExceeds(metrics.Baseline.Covered, metrics.Baseline.Total, metrics.Candidate.Covered, metrics.Candidate.Total, policy.MaximumCoverageDropBasisPoints)},
		{"verifier_coverage_regression", verifierCoverageBasisPoints(metrics.Baseline), verifierCoverageBasisPoints(metrics.Candidate), policy.MaximumVerifierCoverageDropBasisPoints, basisPointDropExceeds(metrics.Baseline.VerifierComparisons, metrics.Baseline.Total, metrics.Candidate.VerifierComparisons, metrics.Candidate.Total, policy.MaximumVerifierCoverageDropBasisPoints)},
		{"disagreement_regression", ratioToBasisPoints(metrics.Baseline.DisagreementRate), ratioToBasisPoints(metrics.Candidate.DisagreementRate), policy.MaximumDisagreementIncreaseBasisPoints, basisPointIncreaseExceeds(metrics.Baseline.VerifierDisagreements, metrics.Baseline.VerifierComparisons, metrics.Candidate.VerifierDisagreements, metrics.Candidate.VerifierComparisons, policy.MaximumDisagreementIncreaseBasisPoints)},
	}
	for _, test := range tests {
		if test.regressed {
			failures = append(failures, AIEvaluationPromotionFailure{Rule: test.rule, Scope: scope, Segment: segment, BaselineBasisPoints: test.baseline, CandidateBasisPoints: test.candidate, LimitBasisPoints: test.limit})
		}
	}
	return failures
}

func metricComparison(baseline, candidate AIEvaluationMetrics) AIEvaluationMetricComparison {
	return AIEvaluationMetricComparison{
		Baseline: baseline, Candidate: candidate,
		PrecisionDeltaBasisPoints:           ratioToBasisPoints(candidate.Precision) - ratioToBasisPoints(baseline.Precision),
		RecallDeltaBasisPoints:              ratioToBasisPoints(candidate.Recall) - ratioToBasisPoints(baseline.Recall),
		FalseNegativeEscapeDeltaBasisPoints: ratioToBasisPoints(candidate.FalseNegativeEscapeRate) - ratioToBasisPoints(baseline.FalseNegativeEscapeRate),
		DisagreementDeltaBasisPoints:        ratioToBasisPoints(candidate.DisagreementRate) - ratioToBasisPoints(baseline.DisagreementRate),
		CoverageDeltaBasisPoints:            ratioToBasisPoints(candidate.Coverage) - ratioToBasisPoints(baseline.Coverage),
		VerifierCoverageDeltaBasisPoints:    verifierCoverageBasisPoints(candidate) - verifierCoverageBasisPoints(baseline),
	}
}

func sameEvaluationConfiguration(a, b AIEvaluationRun) bool {
	return agent.CanonicalProviderID(a.ProposerProvider) == agent.CanonicalProviderID(b.ProposerProvider) &&
		agent.SameModel(a.ProposerModel, b.ProposerModel) &&
		agent.CanonicalProviderID(a.VerifierProvider) == agent.CanonicalProviderID(b.VerifierProvider) &&
		agent.SameModel(a.VerifierModel, b.VerifierModel) && a.PromptVersion == b.PromptVersion
}

func sameEvaluationCase(a, b AIEvaluationResult) bool {
	return a.CaseID == b.CaseID && a.Label == b.Label && a.Language == b.Language &&
		a.Framework == b.Framework && a.Kind == b.Kind && a.Severity == b.Severity &&
		a.CWE == b.CWE && a.Adversarial == b.Adversarial
}

func evaluationCaseOutcome(result AIEvaluationResult) AIEvaluationCaseOutcome {
	return AIEvaluationCaseOutcome{
		Covered: result.Covered, ConsensusFalsePositive: result.ConsensusFalsePositive, WouldGateExempt: result.WouldGateExempt,
		Verdict: result.Critique.Verdict, Driver: result.Critique.Driver, Confidence: result.Critique.Confidence,
		VerifierVerdict: result.Critique.VerifierVerdict, VerifierDriver: result.Critique.VerifierDriver,
		VerifierConfidence: result.Critique.VerifierConfidence,
	}
}

func baselineResult(results []AIEvaluationResult, caseID string) AIEvaluationResult {
	for _, result := range results {
		if result.CaseID == caseID {
			return result
		}
	}
	return AIEvaluationResult{}
}

func ratioToBasisPoints(rate float64) int {
	return int(math.Round(rate * 10_000))
}

func verifierCoverageBasisPoints(metrics AIEvaluationMetrics) int {
	return ratioToBasisPoints(verifierCoverage(metrics))
}

func verifierCoverage(metrics AIEvaluationMetrics) float64 {
	return ratio(metrics.VerifierComparisons, metrics.Total)
}

func belowBasisPointMinimum(numerator, denominator, minimum int) bool {
	return scaledRate(numerator, denominator).Cmp(big.NewRat(int64(minimum), 1)) < 0
}

func aboveBasisPointMaximum(numerator, denominator, maximum int) bool {
	return scaledRate(numerator, denominator).Cmp(big.NewRat(int64(maximum), 1)) > 0
}

func basisPointDropExceeds(baselineNumerator, baselineDenominator, candidateNumerator, candidateDenominator, maximum int) bool {
	delta := new(big.Rat).Sub(exactRate(baselineNumerator, baselineDenominator), exactRate(candidateNumerator, candidateDenominator))
	delta.Mul(delta, big.NewRat(10_000, 1))
	return delta.Cmp(big.NewRat(int64(maximum), 1)) > 0
}

func basisPointIncreaseExceeds(baselineNumerator, baselineDenominator, candidateNumerator, candidateDenominator, maximum int) bool {
	delta := new(big.Rat).Sub(exactRate(candidateNumerator, candidateDenominator), exactRate(baselineNumerator, baselineDenominator))
	delta.Mul(delta, big.NewRat(10_000, 1))
	return delta.Cmp(big.NewRat(int64(maximum), 1)) > 0
}

func scaledRate(numerator, denominator int) *big.Rat {
	return new(big.Rat).Mul(exactRate(numerator, denominator), big.NewRat(10_000, 1))
}

func exactRate(numerator, denominator int) *big.Rat {
	if denominator <= 0 {
		return new(big.Rat)
	}
	return new(big.Rat).SetFrac64(int64(numerator), int64(denominator))
}

func boolBasisPoints(value bool) int {
	if value {
		return 10_000
	}
	return 0
}

func validEvaluationSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func evaluationComparisonID(comparison AIEvaluationComparison) string {
	copyComparison := comparison
	copyComparison.ComparisonID = ""
	b, _ := json.Marshal(copyComparison)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
