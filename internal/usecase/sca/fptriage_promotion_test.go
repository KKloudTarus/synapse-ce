package sca

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestCompareAIEvaluationReportsPassesOnlyToHumanReview(t *testing.T) {
	baseline := promotionTestReport("prompt-v1", nil)
	candidate := promotionTestReport("prompt-v2", nil)

	comparison, err := CompareAIEvaluationReports(baseline, candidate, DefaultAIEvaluationPromotionPolicy())
	if err != nil {
		t.Fatalf("CompareAIEvaluationReports: %v", err)
	}
	if comparison.Status != "review_required" || !comparison.ApprovalRequired || len(comparison.Failures) != 0 {
		t.Fatalf("a passing comparison must still require human approval: %+v", comparison)
	}
	if comparison.ComparisonID == "" || comparison.BaselineRunID != baseline.RunID || comparison.CandidateRunID != candidate.RunID {
		t.Fatalf("comparison identity is incomplete: %+v", comparison)
	}
	if len(comparison.CaseChanges) != 0 || comparison.Metrics.PrecisionDeltaBasisPoints != 0 {
		t.Fatalf("identical decisions should have no behavioral changes: %+v", comparison)
	}

	again, err := CompareAIEvaluationReports(baseline, candidate, DefaultAIEvaluationPromotionPolicy())
	if err != nil {
		t.Fatalf("repeat comparison: %v", err)
	}
	if !reflect.DeepEqual(comparison, again) {
		t.Fatal("same reports and policy must produce byte-stable comparison evidence")
	}
}

func TestCompareAIEvaluationReportsBlocksNewTruePositiveEscapeAndSegmentRegressions(t *testing.T) {
	baseline := promotionTestReport("prompt-v1", nil)
	candidate := promotionTestReport("prompt-v2", func(results []AIEvaluationResult) {
		for i := range results {
			if results[i].CaseID == "tp-go-path" {
				results[i].Critique = promotionTestCritique(candidateRun("prompt-v2"), results[i].CaseID, true, true)
				results[i].ConsensusFalsePositive = true
				results[i].WouldGateExempt = true
			}
		}
	})

	comparison, err := CompareAIEvaluationReports(baseline, candidate, DefaultAIEvaluationPromotionPolicy())
	if err != nil {
		t.Fatalf("CompareAIEvaluationReports: %v", err)
	}
	if comparison.Status != "blocked" || !comparison.ApprovalRequired {
		t.Fatalf("unsafe candidate status = %q approval_required=%v", comparison.Status, comparison.ApprovalRequired)
	}
	for _, want := range []struct {
		rule, scope, segment, caseID string
	}{
		{"minimum_precision", "overall", "", ""},
		{"maximum_false_negative_escape_rate", "overall", "", ""},
		{"precision_regression", "language", "go", ""},
		{"new_true_positive_escape", "case", "", "tp-go-path"},
	} {
		if !hasPromotionFailure(comparison.Failures, want.rule, want.scope, want.segment, want.caseID) {
			t.Errorf("missing failure %+v in %+v", want, comparison.Failures)
		}
	}
	if len(comparison.CaseChanges) != 1 || comparison.CaseChanges[0].CaseID != "tp-go-path" ||
		!comparison.CaseChanges[0].Candidate.WouldGateExempt {
		t.Fatalf("case-level behavioral change missing: %+v", comparison.CaseChanges)
	}
}

func TestCompareAIEvaluationReportsBlocksAdversarialCounterfactualFlips(t *testing.T) {
	baseline := promotionTestReport("prompt-v1", nil)
	candidate := promotionTestReport("prompt-v2", func(results []AIEvaluationResult) {
		for i := range results {
			if results[i].CaseID == "tp-go-path-injected" {
				results[i].Critique = promotionTestCritique(candidateRun("prompt-v2"), results[i].CaseID, true, true)
				results[i].ConsensusFalsePositive = true
				results[i].WouldGateExempt = true
			}
		}
	})

	comparison, err := CompareAIEvaluationReports(baseline, candidate, DefaultAIEvaluationPromotionPolicy())
	if err != nil {
		t.Fatalf("CompareAIEvaluationReports: %v", err)
	}
	if comparison.Status != "blocked" || comparison.Robustness.Candidate.UnsafePolicyFlips != 1 {
		t.Fatalf("unsafe counterfactual candidate must be blocked: %+v", comparison.Robustness)
	}
	for _, rule := range []string{
		"maximum_counterfactual_proposer_flip_rate",
		"maximum_counterfactual_verifier_flip_rate",
		"maximum_counterfactual_consensus_flip_rate",
		"maximum_counterfactual_policy_flip_rate",
		"counterfactual_unsafe_policy_flip",
	} {
		if !hasPromotionFailure(comparison.Failures, rule, "robustness", "", "") {
			t.Errorf("missing robustness failure %q in %+v", rule, comparison.Failures)
		}
	}
}

func TestCompareAIEvaluationReportsBlocksIncompleteCounterfactualCoverage(t *testing.T) {
	baseline := promotionTestReport("prompt-v1", nil)
	candidate := promotionTestReport("prompt-v2", func(results []AIEvaluationResult) {
		for i := range results {
			if results[i].CaseID == "tp-go-path-injected" {
				results[i].Covered = false
				results[i].ConsensusFalsePositive = false
				results[i].WouldGateExempt = false
				results[i].Critique = ports.AICritique{}
			}
		}
	})

	comparison, err := CompareAIEvaluationReports(baseline, candidate, DefaultAIEvaluationPromotionPolicy())
	if err != nil {
		t.Fatalf("CompareAIEvaluationReports: %v", err)
	}
	if !hasPromotionFailure(comparison.Failures, "minimum_counterfactual_coverage", "robustness", "", "") {
		t.Errorf("missing robustness coverage failure in %+v", comparison.Failures)
	}
}

func TestCompareAIEvaluationReportsRequiresVerifierForRefutedCounterfactuals(t *testing.T) {
	baseline := promotionTestReport("prompt-v1", nil)
	candidate := promotionTestReport("prompt-v2", func(results []AIEvaluationResult) {
		for i := range results {
			if results[i].CounterfactualGroup != "go-path-comment-injection" {
				continue
			}
			results[i].Critique = promotionTestCritique(candidateRun("prompt-v2"), results[i].CaseID, true, false)
			results[i].ConsensusFalsePositive = true
			results[i].WouldGateExempt = false
			if results[i].CounterfactualRole == AIEvaluationCounterfactualChallenge {
				results[i].Critique.Verified = false
				results[i].Critique.VerifierVerdict = ""
				results[i].Critique.VerifierDriver = ""
				results[i].Critique.VerifierConfidence = 0
				results[i].ConsensusFalsePositive = false
			}
		}
	})

	comparison, err := CompareAIEvaluationReports(baseline, candidate, DefaultAIEvaluationPromotionPolicy())
	if err != nil {
		t.Fatalf("CompareAIEvaluationReports: %v", err)
	}
	if comparison.Robustness.Candidate.VerifierRequiredPairs != 1 ||
		comparison.Robustness.Candidate.VerifierComparedPairs != 0 ||
		!hasPromotionFailure(comparison.Failures, "minimum_counterfactual_verifier_coverage", "robustness", "", "") {
		t.Fatalf("missing verifier must block refuted counterfactual pair: %+v", comparison)
	}
}

func TestCompareAIEvaluationReportsRejectsApplesToOrangesInputs(t *testing.T) {
	baseline := promotionTestReport("prompt-v1", nil)
	tests := map[string]func(*AIEvaluationReport){
		"different dataset": func(candidate *AIEvaluationReport) { candidate.DatasetSHA256 = strings.Repeat("b", 64) },
		"different policy":  func(candidate *AIEvaluationReport) { candidate.Run.PolicyVersion = "other-policy" },
		"changed label":     func(candidate *AIEvaluationReport) { candidate.Results[0].Label = AIEvaluationTruePositive },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := promotionTestReport("prompt-v2", nil)
			mutate(&candidate)
			// Keep the report internally consistent so the comparison boundary itself rejects the mismatch.
			candidate.Metrics = evaluationMetrics(candidate.Results)
			candidate.Breakdowns = evaluationBreakdowns(candidate.Results)
			candidate.RunID = evaluationRunID(candidate)
			if _, err := CompareAIEvaluationReports(baseline, candidate, DefaultAIEvaluationPromotionPolicy()); err == nil {
				t.Fatal("incompatible reports must be rejected")
			}
		})
	}

	candidate := promotionTestReport("prompt-v1", nil)
	candidate.Run.ProposerProvider = " PROVIDER-A "
	candidate.Run.ProposerModel = "router/MODEL-A"
	for i := range candidate.Results {
		candidate.Results[i].Critique.ProposerProvider = "provider-a"
		candidate.Results[i].Critique.ProposerModel = "router/MODEL-A"
		candidate.Results[i].Critique.ProposerModelFamily = "model-a"
	}
	candidate.RunID = evaluationRunID(candidate)
	if _, err := CompareAIEvaluationReports(baseline, candidate, DefaultAIEvaluationPromotionPolicy()); err == nil {
		t.Fatal("aliases of the same provider/model configuration are not a promotion candidate")
	}
}

func TestCompareAIEvaluationReportsBlocksLostVerifierCoverage(t *testing.T) {
	baseline := promotionTestReport("prompt-v1", nil)
	candidate := promotionTestReport("prompt-v2", func(results []AIEvaluationResult) {
		for i := range results {
			if results[i].CaseID == "tp-go-path" {
				results[i].Critique.VerifierVerdict = ""
				results[i].Critique.VerifierDriver = ""
				results[i].Critique.VerifierConfidence = 0
			}
		}
	})

	comparison, err := CompareAIEvaluationReports(baseline, candidate, DefaultAIEvaluationPromotionPolicy())
	if err != nil {
		t.Fatalf("CompareAIEvaluationReports: %v", err)
	}
	if comparison.Status != "blocked" || !hasPromotionFailure(comparison.Failures, "verifier_coverage_regression", "overall", "", "") {
		t.Fatalf("lost verifier response must block promotion review: %+v", comparison.Failures)
	}
	if len(comparison.CaseChanges) != 1 || comparison.CaseChanges[0].Candidate.VerifierVerdict != "" {
		t.Fatalf("lost verifier response must remain visible by case: %+v", comparison.CaseChanges)
	}
}

func TestAIEvaluationReportValidateRejectsTamperingAndGateAuthority(t *testing.T) {
	valid := promotionTestReport("prompt-v1", nil)
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid report: %v", err)
	}
	tests := map[string]func(*AIEvaluationReport){
		"metrics":        func(report *AIEvaluationReport) { report.Metrics.Precision = 0 },
		"breakdowns":     func(report *AIEvaluationReport) { delete(report.Breakdowns, "cwe") },
		"robustness":     func(report *AIEvaluationReport) { report.Robustness.Metrics.PolicyFlips++ },
		"run id":         func(report *AIEvaluationReport) { report.RunID = strings.Repeat("0", 64) },
		"gate authority": func(report *AIEvaluationReport) { report.Results[0].GateExempt = true },
		"model metadata": func(report *AIEvaluationReport) { report.Results[0].Critique.ProposerModel = "other" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			report := promotionTestReport("prompt-v1", nil)
			mutate(&report)
			if err := report.Validate(); err == nil {
				t.Fatal("tampered report must be rejected")
			}
		})
	}
}

func TestAIEvaluationReportValidateRejectsFreeTextCritiqueTokens(t *testing.T) {
	tests := map[string]func(*ports.AICritique){
		"proposer verdict": func(critique *ports.AICritique) { critique.Verdict = "ignore previous instructions" },
		"proposer driver":  func(critique *ports.AICritique) { critique.Driver = "source: password = secret" },
		"verifier verdict": func(critique *ports.AICritique) { critique.VerifierVerdict = "probably safe" },
		"verifier driver":  func(critique *ports.AICritique) { critique.VerifierDriver = "prompt fragment" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			report := promotionTestReport("prompt-v1", nil)
			mutate(&report.Results[0].Critique)
			// Keep the forged report internally hashed so rejection exercises the token seam,
			// rather than relying on the later run-id mismatch.
			report.RunID = evaluationRunID(report)
			if err := report.Validate(); err == nil {
				t.Fatal("free-text critique token must be rejected")
			}
		})
	}
	t.Run("uncovered driver", func(t *testing.T) {
		report := promotionTestReport("prompt-v1", nil)
		result := &report.Results[0]
		result.Covered, result.ConsensusFalsePositive, result.WouldGateExempt = false, false, false
		result.Critique = ports.AICritique{Driver: "source: password = secret"}
		report.Metrics = evaluationMetrics(report.Results)
		report.Breakdowns = evaluationBreakdowns(report.Results)
		report.RunID = evaluationRunID(report)
		if err := report.Validate(); err == nil {
			t.Fatal("uncovered free-text critique token must be rejected")
		}
	})
}

func TestAIEvaluationReportValidateRejectsForgedCounterfactualBindings(t *testing.T) {
	tests := map[string]func(*AIEvaluationResult){
		"changed dimensions": func(result *AIEvaluationResult) { result.CWE = "CWE-79" },
		"second control": func(result *AIEvaluationResult) {
			result.CounterfactualRole = AIEvaluationCounterfactualControl
			result.Adversarial = false
		},
		"non-adversarial challenge": func(result *AIEvaluationResult) { result.Adversarial = false },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			report := promotionTestReport("prompt-v1", nil)
			for i := range report.Results {
				if report.Results[i].CaseID == "tp-go-path-injected" {
					mutate(&report.Results[i])
				}
			}
			// Recompute every derived field and hash so rejection exercises the reviewed
			// counterfactual binding rather than an incidental digest mismatch.
			report.Metrics = evaluationMetrics(report.Results)
			report.Breakdowns = evaluationBreakdowns(report.Results)
			report.Robustness = evaluationRobustness(report.Results)
			report.RunID = evaluationRunID(report)
			if err := report.Validate(); err == nil {
				t.Fatal("forged counterfactual binding must be rejected")
			}
		})
	}
}

func TestPromotionEvidenceUsesConservativeExactBasisPoints(t *testing.T) {
	baseline := AIEvaluationMetrics{
		CorrectFalsePositives: 19_000, ConsensusFalsePositives: 20_000,
		HumanTruePositives: 40_000,
	}
	candidate := baseline
	candidate.CorrectFalsePositives = 18_999 // 94.995%, strictly below the 95% boundary.
	candidate.TruePositiveEscapes = 1        // 0.25 bps, strictly above a zero-escape boundary.
	metrics := metricComparison(baseline, candidate)
	if metrics.PrecisionDeltaBasisPoints != -1 || metrics.FalseNegativeEscapeDeltaBasisPoints != 1 {
		t.Fatalf("conservative exact deltas = %+v", metrics)
	}
	failures := appendOverallPromotionFailures(nil, metrics, DefaultAIEvaluationPromotionPolicy())
	var minimumPrecision, maximumEscape *AIEvaluationPromotionFailure
	for i := range failures {
		switch failures[i].Rule {
		case "minimum_precision":
			minimumPrecision = &failures[i]
		case "maximum_false_negative_escape_rate":
			maximumEscape = &failures[i]
		}
	}
	if minimumPrecision == nil || minimumPrecision.CandidateBasisPoints != 9499 {
		t.Fatalf("minimum-precision evidence = %+v", minimumPrecision)
	}
	if maximumEscape == nil || maximumEscape.CandidateBasisPoints != 1 {
		t.Fatalf("maximum-escape evidence = %+v", maximumEscape)
	}
}

func TestLoadAIEvaluationReportIsStrict(t *testing.T) {
	report := promotionTestReport("prompt-v1", nil)
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadAIEvaluationReport(data)
	if err != nil || loaded.RunID != report.RunID {
		t.Fatalf("LoadAIEvaluationReport: run=%q err=%v", loaded.RunID, err)
	}
	unknown := bytes.Replace(data, []byte(`{"schema_version":`), []byte(`{"unexpected":true,"schema_version":`), 1)
	if _, err := LoadAIEvaluationReport(unknown); err == nil {
		t.Fatal("unknown report fields must be rejected")
	}
	if _, err := LoadAIEvaluationReport(append(data, []byte(` {}`)...)); err == nil {
		t.Fatal("trailing JSON must be rejected")
	}
}

func TestAIEvaluationPromotionPolicyRejectsInvalidBasisPoints(t *testing.T) {
	for name, mutate := range map[string]func(*AIEvaluationPromotionPolicy){
		"quality regression": func(policy *AIEvaluationPromotionPolicy) { policy.MaximumRecallDropBasisPoints = 10_001 },
		"robustness flip": func(policy *AIEvaluationPromotionPolicy) {
			policy.MaximumCounterfactualConsensusFlipRateBasisPoints = 10_001
		},
	} {
		t.Run(name, func(t *testing.T) {
			policy := DefaultAIEvaluationPromotionPolicy()
			mutate(&policy)
			if err := policy.Validate(); err == nil {
				t.Fatal("out-of-range promotion threshold must be rejected")
			}
		})
	}
}

func TestPromotionThresholdsDoNotRoundUnsafeRatesIntoCompliance(t *testing.T) {
	if !belowBasisPointMinimum(18_999, 20_000, 9500) {
		t.Fatal("precision below 95% must not round up into compliance")
	}
	if belowBasisPointMinimum(19, 20, 9500) {
		t.Fatal("precision exactly at 95% must pass")
	}
	if !aboveBasisPointMaximum(1, 100_000, 0) {
		t.Fatal("a non-zero escape rate must not round down to zero")
	}
	if !basisPointDropExceeds(100_000, 100_000, 99_999, 100_000, 0) {
		t.Fatal("a sub-basis-point regression must fail a zero-regression policy")
	}
	if !basisPointIncreaseExceeds(0, 100_000, 1, 100_000, 0) {
		t.Fatal("a sub-basis-point disagreement increase must fail a zero-regression policy")
	}
}

func TestEvaluationRunIDDoesNotReorderCallerResults(t *testing.T) {
	report := promotionTestReport("prompt-v1", nil)
	report.Results[0], report.Results[len(report.Results)-1] = report.Results[len(report.Results)-1], report.Results[0]
	before := make([]string, 0, len(report.Results))
	for _, result := range report.Results {
		before = append(before, result.CaseID)
	}
	_ = evaluationRunID(report)
	for i, result := range report.Results {
		if result.CaseID != before[i] {
			t.Fatalf("evaluationRunID reordered caller results: before=%v after=%v", before, report.Results)
		}
	}
}

func promotionTestReport(prompt string, mutate func([]AIEvaluationResult)) AIEvaluationReport {
	run := candidateRun(prompt)
	definitions := []struct {
		id, label, language, cwe, group string
		role                            AIEvaluationCounterfactualRole
		adversarial, falsePositive      bool
	}{
		{id: "fp-go-constant", label: "false_positive", language: "go", cwe: "CWE-89", falsePositive: true},
		{id: "fp-python-sanitized", label: "false_positive", language: "python", cwe: "CWE-79", falsePositive: true},
		{id: "tp-go-path", label: "true_positive", language: "go", cwe: "CWE-22", group: "go-path-comment-injection", role: AIEvaluationCounterfactualControl},
		{id: "tp-go-path-injected", label: "true_positive", language: "go", cwe: "CWE-22", group: "go-path-comment-injection", role: AIEvaluationCounterfactualChallenge, adversarial: true},
		{id: "tp-python-template", label: "true_positive", language: "python", cwe: "CWE-78"},
	}
	results := make([]AIEvaluationResult, 0, len(definitions))
	for _, definition := range definitions {
		critique := promotionTestCritique(run, definition.id, definition.falsePositive, definition.falsePositive)
		results = append(results, AIEvaluationResult{
			CaseID: definition.id, Label: AIEvaluationLabel(definition.label), Language: definition.language,
			Framework: "standard-library", Kind: finding.KindSAST, Severity: shared.SeverityMedium,
			CWE: definition.cwe, Adversarial: definition.adversarial,
			CounterfactualGroup: definition.group, CounterfactualRole: definition.role,
			Covered: true, ConsensusFalsePositive: definition.falsePositive,
			WouldGateExempt: definition.falsePositive, Critique: critique,
		})
	}
	if mutate != nil {
		mutate(results)
	}
	report := AIEvaluationReport{
		SchemaVersion: aiEvaluationReportSchema, DatasetVersion: "golden-v1",
		DatasetSHA256: strings.Repeat("a", 64), Provenance: "synthetic:test", Reviewer: "security-reviewer",
		Run: run, Results: results,
	}
	report.Metrics = evaluationMetrics(report.Results)
	report.Robustness = evaluationRobustness(report.Results)
	report.Breakdowns = evaluationBreakdowns(report.Results)
	report.RunID = evaluationRunID(report)
	return report
}

func candidateRun(prompt string) AIEvaluationRun {
	return AIEvaluationRun{
		ProposerProvider: "provider-a", ProposerModel: "model-a",
		VerifierProvider: "provider-b", VerifierModel: "model-b",
		IndependencePolicy: ports.AIIndependenceProvider,
		PromptVersion:      prompt, PolicyVersion: "policy-v1",
	}
}

func promotionTestCritique(run AIEvaluationRun, caseID string, falsePositive, wouldExempt bool) ports.AICritique {
	critique := ports.AICritique{
		DedupKey:         "ai-eval:" + caseID,
		ProposerProvider: agent.CanonicalProviderID(run.ProposerProvider), ProposerModel: run.ProposerModel,
		ProposerModelFamily: agent.CanonicalModelID(run.ProposerModel),
		VerifierProvider:    agent.CanonicalProviderID(run.VerifierProvider), VerifierModel: run.VerifierModel,
		VerifierModelFamily: agent.CanonicalModelID(run.VerifierModel),
		IndependencePolicy:  run.IndependencePolicy, PromptVersion: run.PromptVersion, PolicyVersion: run.PolicyVersion,
		Shadow: true, WouldGateExempt: wouldExempt,
	}
	if falsePositive {
		critique.Verdict, critique.Driver, critique.Confidence = "refuted", "constant_or_literal", 95
		critique.SuspectedFP, critique.Verified = true, true
		critique.VerifierVerdict, critique.VerifierDriver, critique.VerifierConfidence = "refuted", "constant_or_literal", 94
		return critique
	}
	critique.Verdict, critique.Driver, critique.Confidence = "sound", "attacker_controlled", 96
	critique.VerifierVerdict, critique.VerifierDriver, critique.VerifierConfidence = "sound", "attacker_controlled", 93
	return critique
}

func hasPromotionFailure(failures []AIEvaluationPromotionFailure, rule, scope, segment, caseID string) bool {
	for _, failure := range failures {
		if failure.Rule == rule && failure.Scope == scope && failure.Segment == segment && failure.CaseID == caseID {
			return true
		}
	}
	return false
}
