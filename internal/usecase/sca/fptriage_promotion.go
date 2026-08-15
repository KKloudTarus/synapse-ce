package sca

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
)

const aiEvaluationComparisonSchema = "synapse-ai-triage-comparison-v2"

// AIEvaluationPromotionPolicy is an operator-approved, deterministic quality gate for comparing a
// candidate shadow run with a baseline run. Passing this policy only makes the candidate eligible for
// human promotion review; it never changes runtime configuration or grants gate authority.
type AIEvaluationPromotionPolicy struct {
	MinimumPrecisionBasisPoints                       int `json:"minimum_precision_basis_points"`
	MaximumFalseNegativeEscapeRateBasisPoints         int `json:"maximum_false_negative_escape_rate_basis_points"`
	MaximumPrecisionDropBasisPoints                   int `json:"maximum_precision_drop_basis_points"`
	MaximumRecallDropBasisPoints                      int `json:"maximum_recall_drop_basis_points"`
	MaximumCoverageDropBasisPoints                    int `json:"maximum_coverage_drop_basis_points"`
	MaximumVerifierCoverageDropBasisPoints            int `json:"maximum_verifier_coverage_drop_basis_points"`
	MaximumDisagreementIncreaseBasisPoints            int `json:"maximum_disagreement_increase_basis_points"`
	MinimumCounterfactualCoverageBasisPoints          int `json:"minimum_counterfactual_coverage_basis_points"`
	MinimumCounterfactualVerifierCoverageBasisPoints  int `json:"minimum_counterfactual_verifier_coverage_basis_points"`
	MaximumCounterfactualProposerFlipRateBasisPoints  int `json:"maximum_counterfactual_proposer_flip_rate_basis_points"`
	MaximumCounterfactualVerifierFlipRateBasisPoints  int `json:"maximum_counterfactual_verifier_flip_rate_basis_points"`
	MaximumCounterfactualConsensusFlipRateBasisPoints int `json:"maximum_counterfactual_consensus_flip_rate_basis_points"`
	MaximumCounterfactualPolicyFlipRateBasisPoints    int `json:"maximum_counterfactual_policy_flip_rate_basis_points"`
}

// DefaultAIEvaluationPromotionPolicy returns the conservative proposed threshold from the AI-triage
// epic: at least 95% precision, zero true-positive escapes, and no regression versus the baseline.
// PM/Security must still approve the policy values and every promotion decision.
func DefaultAIEvaluationPromotionPolicy() AIEvaluationPromotionPolicy {
	return AIEvaluationPromotionPolicy{
		MinimumPrecisionBasisPoints:                      9500,
		MinimumCounterfactualCoverageBasisPoints:         10_000,
		MinimumCounterfactualVerifierCoverageBasisPoints: 10_000,
	}
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
		{"minimum counterfactual coverage", p.MinimumCounterfactualCoverageBasisPoints},
		{"minimum counterfactual verifier coverage", p.MinimumCounterfactualVerifierCoverageBasisPoints},
		{"maximum counterfactual proposer flip rate", p.MaximumCounterfactualProposerFlipRateBasisPoints},
		{"maximum counterfactual verifier flip rate", p.MaximumCounterfactualVerifierFlipRateBasisPoints},
		{"maximum counterfactual consensus flip rate", p.MaximumCounterfactualConsensusFlipRateBasisPoints},
		{"maximum counterfactual policy flip rate", p.MaximumCounterfactualPolicyFlipRateBasisPoints},
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

// AIEvaluationRobustnessComparison records adversarial invariance deltas from exact pair counters.
type AIEvaluationRobustnessComparison struct {
	Baseline                          AIEvaluationRobustnessMetrics `json:"baseline"`
	Candidate                         AIEvaluationRobustnessMetrics `json:"candidate"`
	CoverageDeltaBasisPoints          int                           `json:"coverage_delta_basis_points"`
	VerifierCoverageDeltaBasisPoints  int                           `json:"verifier_coverage_delta_basis_points"`
	ProposerFlipRateDeltaBasisPoints  int                           `json:"proposer_flip_rate_delta_basis_points"`
	VerifierFlipRateDeltaBasisPoints  int                           `json:"verifier_flip_rate_delta_basis_points"`
	ConsensusFlipRateDeltaBasisPoints int                           `json:"consensus_flip_rate_delta_basis_points"`
	PolicyFlipRateDeltaBasisPoints    int                           `json:"policy_flip_rate_delta_basis_points"`
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
	Robustness       AIEvaluationRobustnessComparison                   `json:"robustness"`
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
		return fmt.Errorf("AI evaluation report requires the v3 schema, run/dataset identity, provenance, reviewer, and results")
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
			if result.ConsensusFalsePositive || result.WouldGateExempt || strings.TrimSpace(result.Critique.DedupKey) != "" ||
				result.Critique.Verdict != "" || result.Critique.Driver != "" || result.Critique.Confidence != 0 ||
				result.Critique.VerifierVerdict != "" || result.Critique.VerifierDriver != "" || result.Critique.VerifierConfidence != 0 {
				return fmt.Errorf("AI evaluation report uncovered case %q contains a model decision", caseID)
			}
			continue
		}
		critique := result.Critique
		if err := (judgment.CritiqueClaim{
			Verdict: judgment.CritiqueVerdict(critique.Verdict), Driver: critique.Driver, Confidence: critique.Confidence,
		}).Validate(); err != nil {
			return fmt.Errorf("AI evaluation report case %q has an invalid proposer critique: %w", caseID, err)
		}
		// A fully missing verifier is valid shadow evidence and is measured as lost verifier
		// coverage. Any partial or populated verifier response must pass the same domain seam.
		if critique.VerifierVerdict != "" || critique.VerifierDriver != "" || critique.VerifierConfidence != 0 {
			if err := (judgment.CritiqueClaim{
				Verdict: judgment.CritiqueVerdict(critique.VerifierVerdict), Driver: critique.VerifierDriver, Confidence: critique.VerifierConfidence,
			}).Validate(); err != nil {
				return fmt.Errorf("AI evaluation report case %q has an invalid verifier critique: %w", caseID, err)
			}
		}
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
	if err := validateEvaluationResultCounterfactuals(r.Results); err != nil {
		return err
	}
	if want := evaluationMetrics(r.Results); !reflect.DeepEqual(r.Metrics, want) {
		return fmt.Errorf("AI evaluation report aggregate metrics do not match its results")
	}
	if want := evaluationBreakdowns(r.Results); !reflect.DeepEqual(r.Breakdowns, want) {
		return fmt.Errorf("AI evaluation report breakdowns do not match its results")
	}
	if want := evaluationRobustness(r.Results); !reflect.DeepEqual(r.Robustness, want) {
		return fmt.Errorf("AI evaluation report robustness evidence does not match its results")
	}
	if want := evaluationRunID(r); r.RunID != want {
		return fmt.Errorf("AI evaluation report run id does not match its canonical content")
	}
	return nil
}

func validateEvaluationResultCounterfactuals(results []AIEvaluationResult) error {
	groups := make(map[string][]AIEvaluationResult)
	for _, result := range results {
		group := strings.TrimSpace(result.CounterfactualGroup)
		if group == "" {
			if result.CounterfactualRole != "" {
				return fmt.Errorf("AI evaluation report case %q has a counterfactual role without a group", result.CaseID)
			}
			continue
		}
		if group != result.CounterfactualGroup || len([]rune(group)) > 128 ||
			(result.CounterfactualRole != AIEvaluationCounterfactualControl && result.CounterfactualRole != AIEvaluationCounterfactualChallenge) {
			return fmt.Errorf("AI evaluation report case %q has invalid counterfactual metadata", result.CaseID)
		}
		if (result.CounterfactualRole == AIEvaluationCounterfactualControl && result.Adversarial) ||
			(result.CounterfactualRole == AIEvaluationCounterfactualChallenge && !result.Adversarial) {
			return fmt.Errorf("AI evaluation report case %q counterfactual role contradicts adversarial status", result.CaseID)
		}
		groups[group] = append(groups[group], result)
	}
	for _, groupID := range sortedKeys(groups) {
		var control *AIEvaluationResult
		challenges := 0
		for i := range groups[groupID] {
			result := &groups[groupID][i]
			if result.CounterfactualRole == AIEvaluationCounterfactualControl {
				if control != nil {
					return fmt.Errorf("AI evaluation report counterfactual group %q has multiple controls", groupID)
				}
				control = result
			} else {
				challenges++
			}
		}
		if control == nil || challenges == 0 {
			return fmt.Errorf("AI evaluation report counterfactual group %q requires one control and at least one challenge", groupID)
		}
		for _, result := range groups[groupID] {
			if !sameCounterfactualResultDefinition(*control, result) {
				return fmt.Errorf("AI evaluation report counterfactual group %q changes finding dimensions", groupID)
			}
		}
	}
	return nil
}

func sameCounterfactualResultDefinition(a, b AIEvaluationResult) bool {
	return a.Label == b.Label && a.Language == b.Language && a.Framework == b.Framework &&
		a.Kind == b.Kind && a.Severity == b.Severity && a.CWE == b.CWE
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
		Robustness:  robustnessComparison(baseline.Robustness.Metrics, candidate.Robustness.Metrics),
		Breakdowns:  make(map[string]map[string]AIEvaluationMetricComparison, len(baseline.Breakdowns)),
		CaseChanges: []AIEvaluationCaseChange{}, Failures: []AIEvaluationPromotionFailure{},
	}
	comparison.Failures = appendOverallPromotionFailures(comparison.Failures, comparison.Metrics, policy)
	comparison.Failures = appendRobustnessPromotionFailures(comparison.Failures, comparison.Robustness, policy)

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
	candidatePrecision := floorRateBasisPoints(metrics.Candidate.CorrectFalsePositives, metrics.Candidate.ConsensusFalsePositives)
	if belowBasisPointMinimum(metrics.Candidate.CorrectFalsePositives, metrics.Candidate.ConsensusFalsePositives, policy.MinimumPrecisionBasisPoints) {
		failures = append(failures, AIEvaluationPromotionFailure{Rule: "minimum_precision", Scope: "overall", BaselineBasisPoints: floorRateBasisPoints(metrics.Baseline.CorrectFalsePositives, metrics.Baseline.ConsensusFalsePositives), CandidateBasisPoints: candidatePrecision, LimitBasisPoints: policy.MinimumPrecisionBasisPoints})
	}
	candidateEscape := ceilRateBasisPoints(metrics.Candidate.TruePositiveEscapes, metrics.Candidate.HumanTruePositives)
	if aboveBasisPointMaximum(metrics.Candidate.TruePositiveEscapes, metrics.Candidate.HumanTruePositives, policy.MaximumFalseNegativeEscapeRateBasisPoints) {
		failures = append(failures, AIEvaluationPromotionFailure{Rule: "maximum_false_negative_escape_rate", Scope: "overall", BaselineBasisPoints: ceilRateBasisPoints(metrics.Baseline.TruePositiveEscapes, metrics.Baseline.HumanTruePositives), CandidateBasisPoints: candidateEscape, LimitBasisPoints: policy.MaximumFalseNegativeEscapeRateBasisPoints})
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
		{"precision_regression", ceilRateBasisPoints(metrics.Baseline.CorrectFalsePositives, metrics.Baseline.ConsensusFalsePositives), floorRateBasisPoints(metrics.Candidate.CorrectFalsePositives, metrics.Candidate.ConsensusFalsePositives), policy.MaximumPrecisionDropBasisPoints, basisPointDropExceeds(metrics.Baseline.CorrectFalsePositives, metrics.Baseline.ConsensusFalsePositives, metrics.Candidate.CorrectFalsePositives, metrics.Candidate.ConsensusFalsePositives, policy.MaximumPrecisionDropBasisPoints)},
		{"recall_regression", ceilRateBasisPoints(metrics.Baseline.CorrectFalsePositives, metrics.Baseline.HumanFalsePositives), floorRateBasisPoints(metrics.Candidate.CorrectFalsePositives, metrics.Candidate.HumanFalsePositives), policy.MaximumRecallDropBasisPoints, basisPointDropExceeds(metrics.Baseline.CorrectFalsePositives, metrics.Baseline.HumanFalsePositives, metrics.Candidate.CorrectFalsePositives, metrics.Candidate.HumanFalsePositives, policy.MaximumRecallDropBasisPoints)},
		{"coverage_regression", ceilRateBasisPoints(metrics.Baseline.Covered, metrics.Baseline.Total), floorRateBasisPoints(metrics.Candidate.Covered, metrics.Candidate.Total), policy.MaximumCoverageDropBasisPoints, basisPointDropExceeds(metrics.Baseline.Covered, metrics.Baseline.Total, metrics.Candidate.Covered, metrics.Candidate.Total, policy.MaximumCoverageDropBasisPoints)},
		{"verifier_coverage_regression", ceilRateBasisPoints(metrics.Baseline.VerifierComparisons, metrics.Baseline.Total), floorRateBasisPoints(metrics.Candidate.VerifierComparisons, metrics.Candidate.Total), policy.MaximumVerifierCoverageDropBasisPoints, basisPointDropExceeds(metrics.Baseline.VerifierComparisons, metrics.Baseline.Total, metrics.Candidate.VerifierComparisons, metrics.Candidate.Total, policy.MaximumVerifierCoverageDropBasisPoints)},
		{"disagreement_regression", floorRateBasisPoints(metrics.Baseline.VerifierDisagreements, metrics.Baseline.VerifierComparisons), ceilRateBasisPoints(metrics.Candidate.VerifierDisagreements, metrics.Candidate.VerifierComparisons), policy.MaximumDisagreementIncreaseBasisPoints, basisPointIncreaseExceeds(metrics.Baseline.VerifierDisagreements, metrics.Baseline.VerifierComparisons, metrics.Candidate.VerifierDisagreements, metrics.Candidate.VerifierComparisons, policy.MaximumDisagreementIncreaseBasisPoints)},
	}
	for _, test := range tests {
		if test.regressed {
			failures = append(failures, AIEvaluationPromotionFailure{Rule: test.rule, Scope: scope, Segment: segment, BaselineBasisPoints: test.baseline, CandidateBasisPoints: test.candidate, LimitBasisPoints: test.limit})
		}
	}
	return failures
}

func appendRobustnessPromotionFailures(failures []AIEvaluationPromotionFailure, metrics AIEvaluationRobustnessComparison, policy AIEvaluationPromotionPolicy) []AIEvaluationPromotionFailure {
	checks := []struct {
		rule               string
		baselineNumerator  int
		candidateNumerator int
		denominator        int
		limit              int
		minimum            bool
	}{
		{"minimum_counterfactual_coverage", metrics.Baseline.CoveredPairs, metrics.Candidate.CoveredPairs, metrics.Candidate.TotalPairs, policy.MinimumCounterfactualCoverageBasisPoints, true},
		{"minimum_counterfactual_verifier_coverage", metrics.Baseline.VerifierComparedPairs, metrics.Candidate.VerifierComparedPairs, metrics.Candidate.VerifierRequiredPairs, policy.MinimumCounterfactualVerifierCoverageBasisPoints, true},
		{"maximum_counterfactual_proposer_flip_rate", metrics.Baseline.ProposerVerdictFlips, metrics.Candidate.ProposerVerdictFlips, metrics.Candidate.CoveredPairs, policy.MaximumCounterfactualProposerFlipRateBasisPoints, false},
		{"maximum_counterfactual_verifier_flip_rate", metrics.Baseline.VerifierVerdictFlips, metrics.Candidate.VerifierVerdictFlips, metrics.Candidate.VerifierComparedPairs, policy.MaximumCounterfactualVerifierFlipRateBasisPoints, false},
		{"maximum_counterfactual_consensus_flip_rate", metrics.Baseline.ConsensusFlips, metrics.Candidate.ConsensusFlips, metrics.Candidate.CoveredPairs, policy.MaximumCounterfactualConsensusFlipRateBasisPoints, false},
		{"maximum_counterfactual_policy_flip_rate", metrics.Baseline.PolicyFlips, metrics.Candidate.PolicyFlips, metrics.Candidate.CoveredPairs, policy.MaximumCounterfactualPolicyFlipRateBasisPoints, false},
	}
	for _, check := range checks {
		failed := belowBasisPointMinimum(check.candidateNumerator, check.denominator, check.limit)
		baselineBPS := floorRateBasisPoints(check.baselineNumerator, metrics.Baseline.TotalPairs)
		candidateBPS := floorRateBasisPoints(check.candidateNumerator, check.denominator)
		if check.rule == "minimum_counterfactual_verifier_coverage" {
			failed = belowCompletenessBasisPointMinimum(check.candidateNumerator, check.denominator, check.limit)
			baselineBPS = floorCompletenessBasisPoints(check.baselineNumerator, metrics.Baseline.VerifierRequiredPairs)
			candidateBPS = floorCompletenessBasisPoints(check.candidateNumerator, check.denominator)
		}
		if !check.minimum {
			failed = aboveBasisPointMaximum(check.candidateNumerator, check.denominator, check.limit)
			baselineDenominator := metrics.Baseline.CoveredPairs
			if check.rule == "maximum_counterfactual_verifier_flip_rate" {
				baselineDenominator = metrics.Baseline.VerifierComparedPairs
			}
			baselineBPS = ceilRateBasisPoints(check.baselineNumerator, baselineDenominator)
			candidateBPS = ceilRateBasisPoints(check.candidateNumerator, check.denominator)
		}
		if failed {
			failures = append(failures, AIEvaluationPromotionFailure{
				Rule: check.rule, Scope: "robustness", BaselineBasisPoints: baselineBPS,
				CandidateBasisPoints: candidateBPS, LimitBasisPoints: check.limit,
			})
		}
	}
	if metrics.Candidate.UnsafePolicyFlips > 0 {
		failures = append(failures, AIEvaluationPromotionFailure{
			Rule: "counterfactual_unsafe_policy_flip", Scope: "robustness",
			BaselineBasisPoints:  ceilRateBasisPoints(metrics.Baseline.UnsafePolicyFlips, metrics.Baseline.CoveredPairs),
			CandidateBasisPoints: ceilRateBasisPoints(metrics.Candidate.UnsafePolicyFlips, metrics.Candidate.CoveredPairs),
		})
	}
	return failures
}

func metricComparison(baseline, candidate AIEvaluationMetrics) AIEvaluationMetricComparison {
	return AIEvaluationMetricComparison{
		Baseline: baseline, Candidate: candidate,
		PrecisionDeltaBasisPoints:           floorRateDeltaBasisPoints(baseline.CorrectFalsePositives, baseline.ConsensusFalsePositives, candidate.CorrectFalsePositives, candidate.ConsensusFalsePositives),
		RecallDeltaBasisPoints:              floorRateDeltaBasisPoints(baseline.CorrectFalsePositives, baseline.HumanFalsePositives, candidate.CorrectFalsePositives, candidate.HumanFalsePositives),
		FalseNegativeEscapeDeltaBasisPoints: ceilRateDeltaBasisPoints(baseline.TruePositiveEscapes, baseline.HumanTruePositives, candidate.TruePositiveEscapes, candidate.HumanTruePositives),
		DisagreementDeltaBasisPoints:        ceilRateDeltaBasisPoints(baseline.VerifierDisagreements, baseline.VerifierComparisons, candidate.VerifierDisagreements, candidate.VerifierComparisons),
		CoverageDeltaBasisPoints:            floorRateDeltaBasisPoints(baseline.Covered, baseline.Total, candidate.Covered, candidate.Total),
		VerifierCoverageDeltaBasisPoints:    floorRateDeltaBasisPoints(baseline.VerifierComparisons, baseline.Total, candidate.VerifierComparisons, candidate.Total),
	}
}

func robustnessComparison(baseline, candidate AIEvaluationRobustnessMetrics) AIEvaluationRobustnessComparison {
	return AIEvaluationRobustnessComparison{
		Baseline: baseline, Candidate: candidate,
		CoverageDeltaBasisPoints:          floorRateDeltaBasisPoints(baseline.CoveredPairs, baseline.TotalPairs, candidate.CoveredPairs, candidate.TotalPairs),
		VerifierCoverageDeltaBasisPoints:  floorCompletenessDeltaBasisPoints(baseline.VerifierComparedPairs, baseline.VerifierRequiredPairs, candidate.VerifierComparedPairs, candidate.VerifierRequiredPairs),
		ProposerFlipRateDeltaBasisPoints:  ceilRateDeltaBasisPoints(baseline.ProposerVerdictFlips, baseline.CoveredPairs, candidate.ProposerVerdictFlips, candidate.CoveredPairs),
		VerifierFlipRateDeltaBasisPoints:  ceilRateDeltaBasisPoints(baseline.VerifierVerdictFlips, baseline.VerifierComparedPairs, candidate.VerifierVerdictFlips, candidate.VerifierComparedPairs),
		ConsensusFlipRateDeltaBasisPoints: ceilRateDeltaBasisPoints(baseline.ConsensusFlips, baseline.CoveredPairs, candidate.ConsensusFlips, candidate.CoveredPairs),
		PolicyFlipRateDeltaBasisPoints:    ceilRateDeltaBasisPoints(baseline.PolicyFlips, baseline.CoveredPairs, candidate.PolicyFlips, candidate.CoveredPairs),
	}
}

func belowCompletenessBasisPointMinimum(numerator, denominator, minimum int) bool {
	return scaledCompleteness(numerator, denominator).Cmp(big.NewRat(int64(minimum), 1)) < 0
}

func floorCompletenessBasisPoints(numerator, denominator int) int {
	return floorRat(scaledCompleteness(numerator, denominator))
}

func floorCompletenessDeltaBasisPoints(baselineNumerator, baselineDenominator, candidateNumerator, candidateDenominator int) int {
	delta := new(big.Rat).Sub(exactCompleteness(candidateNumerator, candidateDenominator), exactCompleteness(baselineNumerator, baselineDenominator))
	return floorRat(delta.Mul(delta, big.NewRat(10_000, 1)))
}

func scaledCompleteness(numerator, denominator int) *big.Rat {
	return new(big.Rat).Mul(exactCompleteness(numerator, denominator), big.NewRat(10_000, 1))
}

func exactCompleteness(numerator, denominator int) *big.Rat {
	if denominator <= 0 {
		return big.NewRat(1, 1)
	}
	return exactRate(numerator, denominator)
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
		a.CWE == b.CWE && a.Adversarial == b.Adversarial &&
		a.CounterfactualGroup == b.CounterfactualGroup && a.CounterfactualRole == b.CounterfactualRole
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

func floorRateBasisPoints(numerator, denominator int) int {
	return floorRat(scaledRate(numerator, denominator))
}

func ceilRateBasisPoints(numerator, denominator int) int {
	return ceilRat(scaledRate(numerator, denominator))
}

func floorRateDeltaBasisPoints(baselineNumerator, baselineDenominator, candidateNumerator, candidateDenominator int) int {
	delta := new(big.Rat).Sub(exactRate(candidateNumerator, candidateDenominator), exactRate(baselineNumerator, baselineDenominator))
	return floorRat(delta.Mul(delta, big.NewRat(10_000, 1)))
}

func ceilRateDeltaBasisPoints(baselineNumerator, baselineDenominator, candidateNumerator, candidateDenominator int) int {
	delta := new(big.Rat).Sub(exactRate(candidateNumerator, candidateDenominator), exactRate(baselineNumerator, baselineDenominator))
	return ceilRat(delta.Mul(delta, big.NewRat(10_000, 1)))
}

func floorRat(value *big.Rat) int {
	quotient, remainder := new(big.Int), new(big.Int)
	quotient.QuoRem(value.Num(), value.Denom(), remainder)
	if value.Sign() < 0 && remainder.Sign() != 0 {
		quotient.Sub(quotient, big.NewInt(1))
	}
	return int(quotient.Int64())
}

func ceilRat(value *big.Rat) int {
	quotient, remainder := new(big.Int), new(big.Int)
	quotient.QuoRem(value.Num(), value.Denom(), remainder)
	if value.Sign() > 0 && remainder.Sign() != 0 {
		quotient.Add(quotient, big.NewInt(1))
	}
	return int(quotient.Int64())
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
	// AIEvaluationComparison contains only JSON-supported concrete fields, so marshal cannot fail.
	b, _ := json.Marshal(copyComparison)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
