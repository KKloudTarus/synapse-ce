// Package rulepack evaluates deterministic release evidence for signed detection RulePacks.
package rulepack

import (
	"fmt"
	"math"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/purplecoverage"
	rulepackdomain "github.com/KKloudTarus/synapse-ce/internal/domain/rulepack"
)

// Stage is one ordered RulePack release gate.
type Stage string

const (
	StageCompatibility  Stage = "compatibility"
	StagePositiveReplay Stage = "positive_replay"
	StageNegativeReplay Stage = "negative_replay"
	StagePerformance    Stage = "performance"
	StageRetroHunt      Stage = "retro_hunt"
	StageEmulation      Stage = "emulation"
	StageFPBudget       Stage = "false_positive_budget"
	StageCanary         Stage = "canary_metrics"
	StageProduction     Stage = "production_metrics"
)

// GatePolicy is operator-owned release policy. Rates are integer basis points to keep CI decisions
// deterministic; detections/host-day is represented in milli-detections to avoid floating point.
type GatePolicy struct {
	MinimumPrecisionBPS                    int   `json:"minimum_precision_bps"`
	MaximumFalsePositiveRateBPS            int   `json:"maximum_false_positive_rate_bps"`
	MinimumAnalystDispositionRateBPS       int   `json:"minimum_analyst_disposition_rate_bps"`
	MinimumRequiredFieldAvailabilityBPS    int   `json:"minimum_required_field_availability_bps"`
	MinimumATTACKCoverageBPS               int   `json:"minimum_attack_coverage_bps"`
	MaximumCanaryDetectionsPerHostDayMilli int64 `json:"maximum_canary_detections_per_host_day_milli"`
	MaximumProdDetectionsPerHostDayMilli   int64 `json:"maximum_prod_detections_per_host_day_milli"`
	MinimumReviewedDetections              int64 `json:"minimum_reviewed_detections"`
	MinimumHostDays                        int64 `json:"minimum_host_days"`
}

// Validate rejects ambiguous release policy values.
func (p GatePolicy) Validate() error {
	bps := []struct {
		name  string
		value int
	}{
		{"minimum precision", p.MinimumPrecisionBPS},
		{"maximum false-positive rate", p.MaximumFalsePositiveRateBPS},
		{"minimum analyst disposition rate", p.MinimumAnalystDispositionRateBPS},
		{"minimum required-field availability", p.MinimumRequiredFieldAvailabilityBPS},
		{"minimum ATT&CK coverage", p.MinimumATTACKCoverageBPS},
	}
	for _, item := range bps {
		if item.value < 0 || item.value > 10_000 {
			return fmt.Errorf("rulepack gate policy %s must be between 0 and 10000 basis points", item.name)
		}
	}
	if p.MaximumCanaryDetectionsPerHostDayMilli < 0 || p.MaximumProdDetectionsPerHostDayMilli < 0 {
		return fmt.Errorf("rulepack gate policy detections/host-day limits must not be negative")
	}
	if p.MinimumReviewedDetections < 1 {
		return fmt.Errorf("rulepack gate policy minimum reviewed detections must be >= 1")
	}
	if p.MinimumHostDays < 1 {
		return fmt.Errorf("rulepack gate policy minimum host-days must be >= 1")
	}
	return nil
}

// RuleCostObservation is measured release evidence for one rule. It is compared to the signed
// RulePack's ExpectedCost budget; the gate does not benchmark wall-clock time itself.
type RuleCostObservation struct {
	RuleID              string `json:"rule_id"`
	LatencyMicros       int64  `json:"latency_micros"`
	CPUMicrosPerHostDay int64  `json:"cpu_micros_per_host_day"`
}

// RetroEvidence proves one candidate rule was evaluated against a telemetry window from the existing
// telemetry hunt seam. Complete, unsampled evidence is required for a release claim.
type RetroEvidence struct {
	RuleID        string `json:"rule_id"`
	ContextEvents int    `json:"context_events"`
	MatchedEvents int    `json:"matched_events"`
	Complete      bool   `json:"complete"`
	Sampled       bool   `json:"sampled"`
	SequenceGaps  int    `json:"sequence_gaps"`
	Losses        int    `json:"losses"`
}

// QualitySample is exact labelled/runtime evidence used to compute detection-quality metrics. Detections
// are emitted detections; SuppressedDetections are candidates suppressed before emission. True/false
// positives are analyst dispositions over emitted detections and therefore must not exceed Detections.
type QualitySample struct {
	Detections           int64             `json:"detections"`
	TruePositives        int64             `json:"true_positives"`
	FalsePositives       int64             `json:"false_positives"`
	SuppressedDetections int64             `json:"suppressed_detections"`
	HostDays             int64             `json:"host_days"`
	AvailableFields      []detection.Field `json:"available_fields"`
}

// QualityMetrics is the deterministic metric surface #630 emits for CI and release review.
type QualityMetrics struct {
	Detections                   int64 `json:"detections"`
	ReviewedDetections           int64 `json:"reviewed_detections"`
	TruePositives                int64 `json:"true_positives"`
	FalsePositives               int64 `json:"false_positives"`
	SuppressedDetections         int64 `json:"suppressed_detections"`
	HostDays                     int64 `json:"host_days"`
	PrecisionBPS                 int   `json:"precision_bps"`
	FalsePositiveRateBPS         int   `json:"false_positive_rate_bps"`
	SuppressionRateBPS           int   `json:"suppression_rate_bps"`
	AnalystDispositionRateBPS    int   `json:"analyst_disposition_rate_bps"`
	RequiredFieldAvailabilityBPS int   `json:"required_field_availability_bps"`
	DetectionsPerHostDayMilli    int64 `json:"detections_per_host_day_milli"`
}

// GateInput is all deterministic evidence needed for one RulePack release evaluation. Canary and
// Production may be omitted while a candidate is only seeking admission to the canary stage.
type GateInput struct {
	Deployment rulepackdomain.RulePackDeployment `json:"deployment"`
	Policy     GatePolicy                        `json:"policy"`
	Costs      []RuleCostObservation             `json:"costs"`
	Retro      []RetroEvidence                   `json:"retro"`
	Purple     []purplecoverage.Coverage         `json:"purple"`
	Evaluation QualitySample                     `json:"evaluation"`
	Canary     *QualitySample                    `json:"canary,omitempty"`
	Production *QualitySample                    `json:"production,omitempty"`
}

// Failure is a stable machine-readable reason one stage did not pass.
type Failure struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// StageResult records one gate's outcome in fixed release order.
type StageResult struct {
	Stage    Stage     `json:"stage"`
	Pass     bool      `json:"pass"`
	Failures []Failure `json:"failures,omitempty"`
}

// Report is deterministic CI evidence. PreCanaryPassed admits candidate->canary, while Passed requires
// both canary and production metrics and is required for canary->promoted.
type Report struct {
	PackID            string                `json:"pack_id"`
	PackVersion       int                   `json:"pack_version"`
	PackDigest        string                `json:"pack_digest"`
	PreCanaryPassed   bool                  `json:"pre_canary_passed"`
	CanaryPassed      bool                  `json:"canary_passed"`
	Passed            bool                  `json:"passed"`
	Stages            []StageResult         `json:"stages"`
	Costs             []RuleCostObservation `json:"costs"`
	EvaluationMetrics QualityMetrics        `json:"evaluation_metrics"`
	CanaryMetrics     *QualityMetrics       `json:"canary_metrics,omitempty"`
	ProductionMetrics *QualityMetrics       `json:"production_metrics,omitempty"`
	ATTACKCoverageBPS int                   `json:"attack_coverage_bps"`
}

// Evaluate runs every release stage deterministically. A malformed pack, policy, or evidence object is
// an error; valid evidence that misses a threshold produces a Report with Pass=false and explicit reasons.
func Evaluate(p rulepackdomain.RulePack, in GateInput) (Report, error) {
	if err := p.Validate(); err != nil {
		return Report{}, fmt.Errorf("validate rulepack: %w", err)
	}
	if err := in.Policy.Validate(); err != nil {
		return Report{}, err
	}
	if err := validateQualitySample(p, in.Evaluation); err != nil {
		return Report{}, fmt.Errorf("evaluation sample: %w", err)
	}
	if in.Canary != nil {
		if err := validateQualitySample(p, *in.Canary); err != nil {
			return Report{}, fmt.Errorf("canary sample: %w", err)
		}
	}
	if in.Production != nil {
		if err := validateQualitySample(p, *in.Production); err != nil {
			return Report{}, fmt.Errorf("production sample: %w", err)
		}
	}

	report := Report{PackID: p.ID, PackVersion: p.Version, PackDigest: p.Digest}
	appendStage := func(stage Stage, failures []Failure) {
		report.Stages = append(report.Stages, StageResult{Stage: stage, Pass: len(failures) == 0, Failures: failures})
	}

	appendStage(StageCompatibility, compatibilityFailures(p, in.Deployment))

	replay, err := rulepackdomain.Replay(p)
	if err != nil {
		return Report{}, fmt.Errorf("replay rulepack: %w", err)
	}
	positive, negative := replayFailures(replay)
	appendStage(StagePositiveReplay, positive)
	appendStage(StageNegativeReplay, negative)

	costs, failures, err := performanceFailures(p, in.Costs)
	if err != nil {
		return Report{}, err
	}
	report.Costs = costs
	appendStage(StagePerformance, failures)

	appendStage(StageRetroHunt, retroFailures(p, in.Retro))

	attackCoverage, purpleFailures, err := emulationFailures(p, in.Purple, in.Policy.MinimumATTACKCoverageBPS)
	if err != nil {
		return Report{}, err
	}
	report.ATTACKCoverageBPS = attackCoverage
	appendStage(StageEmulation, purpleFailures)

	evalMetrics, err := computeQualityMetrics(p, in.Evaluation)
	if err != nil {
		return Report{}, fmt.Errorf("evaluation metrics: %w", err)
	}
	report.EvaluationMetrics = evalMetrics
	appendStage(StageFPBudget, fpBudgetFailures(evalMetrics, in.Policy))

	report.PreCanaryPassed = stagesPassed(report.Stages)

	if in.Canary == nil {
		appendStage(StageCanary, []Failure{{Code: "canary_metrics_missing", Detail: "canary metrics were not provided"}})
	} else {
		metrics, err := computeQualityMetrics(p, *in.Canary)
		if err != nil {
			return Report{}, fmt.Errorf("canary metrics: %w", err)
		}
		report.CanaryMetrics = &metrics
		appendStage(StageCanary, runtimeMetricFailures("canary", metrics, in.Policy.MaximumCanaryDetectionsPerHostDayMilli, p.SuppressionPolicy.MaxSuppressionRateBPS, in.Policy))
	}
	report.CanaryPassed = report.PreCanaryPassed && report.Stages[len(report.Stages)-1].Pass

	if in.Production == nil {
		appendStage(StageProduction, []Failure{{Code: "production_metrics_missing", Detail: "production metrics were not provided"}})
	} else {
		metrics, err := computeQualityMetrics(p, *in.Production)
		if err != nil {
			return Report{}, fmt.Errorf("production metrics: %w", err)
		}
		report.ProductionMetrics = &metrics
		appendStage(StageProduction, runtimeMetricFailures("production", metrics, in.Policy.MaximumProdDetectionsPerHostDayMilli, p.SuppressionPolicy.MaxSuppressionRateBPS, in.Policy))
	}
	report.Passed = report.CanaryPassed && report.Stages[len(report.Stages)-1].Pass
	return report, nil
}

// Advance recomputes release evidence at the transition boundary instead of trusting a caller-supplied
// Report. Candidate->canary needs all pre-canary gates and canary->promoted needs the full release gate.
// The deployment embedded in GateInput is overwritten with d so evidence cannot be evaluated against a
// healthier deployment than the one actually being transitioned. Rollback deliberately bypasses gate
// recomputation: if signed rollback metadata is valid, safety must remain available even when evidence is
// malformed or the rollout is incompatible.
func Advance(p rulepackdomain.RulePack, d rulepackdomain.RulePackDeployment, in GateInput, next rulepackdomain.DeploymentState) (rulepackdomain.RulePackDeployment, error) {
	if next == rulepackdomain.DeploymentRolledBack {
		return rulepackdomain.Transition(p, d, next)
	}
	in.Deployment = d
	report, err := Evaluate(p, in)
	if err != nil {
		return rulepackdomain.RulePackDeployment{}, fmt.Errorf("recompute rulepack gate evidence: %w", err)
	}
	switch next {
	case rulepackdomain.DeploymentCanary:
		if !report.PreCanaryPassed {
			return rulepackdomain.RulePackDeployment{}, fmt.Errorf("rulepack cannot enter canary: pre-canary gates did not pass")
		}
	case rulepackdomain.DeploymentPromoted:
		if !report.Passed {
			return rulepackdomain.RulePackDeployment{}, fmt.Errorf("rulepack cannot be promoted: full release gate did not pass")
		}
	default:
		return rulepackdomain.RulePackDeployment{}, fmt.Errorf("unsupported rulepack gate transition to %q", next)
	}
	return rulepackdomain.Transition(p, d, next)
}

func compatibilityFailures(p rulepackdomain.RulePack, d rulepackdomain.RulePackDeployment) []Failure {
	if err := rulepackdomain.Compatible(p, d); err != nil {
		return []Failure{{Code: "incompatible_deployment", Detail: err.Error()}}
	}
	return nil
}

func replayFailures(results []rulepackdomain.ReplayResult) (positive, negative []Failure) {
	for _, result := range results {
		if result.Pass {
			continue
		}
		failure := Failure{Code: "fixture_mismatch", Detail: fmt.Sprintf("fixture %s expected %v, got %v", result.FixtureID, result.Expected, result.Actual)}
		if len(result.Expected) == 0 {
			negative = append(negative, failure)
		} else {
			positive = append(positive, failure)
		}
	}
	return positive, negative
}

func performanceFailures(p rulepackdomain.RulePack, observations []RuleCostObservation) ([]RuleCostObservation, []Failure, error) {
	budgets := make(map[string]rulepackdomain.RuleCostBudget, len(p.ExpectedCost))
	for _, budget := range p.ExpectedCost {
		budgets[budget.RuleID] = budget
	}
	seen := make(map[string]struct{}, len(observations))
	ordered := append([]RuleCostObservation(nil), observations...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].RuleID < ordered[j].RuleID })
	var failures []Failure
	for _, observed := range ordered {
		if observed.RuleID == "" || observed.LatencyMicros < 0 || observed.CPUMicrosPerHostDay < 0 {
			return nil, nil, fmt.Errorf("invalid cost observation for rule %q", observed.RuleID)
		}
		budget, ok := budgets[observed.RuleID]
		if !ok {
			return nil, nil, fmt.Errorf("cost observation names unknown rule %q", observed.RuleID)
		}
		if _, dup := seen[observed.RuleID]; dup {
			return nil, nil, fmt.Errorf("duplicate cost observation for rule %q", observed.RuleID)
		}
		seen[observed.RuleID] = struct{}{}
		if observed.LatencyMicros > budget.MaxLatencyMicros {
			failures = append(failures, Failure{Code: "latency_budget_exceeded", Detail: fmt.Sprintf("rule %s latency %d exceeds budget %d microseconds", observed.RuleID, observed.LatencyMicros, budget.MaxLatencyMicros)})
		}
		if observed.CPUMicrosPerHostDay > budget.MaxCPUMicrosPerHostDay {
			failures = append(failures, Failure{Code: "cpu_budget_exceeded", Detail: fmt.Sprintf("rule %s CPU %d exceeds budget %d microseconds/host-day", observed.RuleID, observed.CPUMicrosPerHostDay, budget.MaxCPUMicrosPerHostDay)})
		}
	}
	for ruleID := range budgets {
		if _, ok := seen[ruleID]; !ok {
			failures = append(failures, Failure{Code: "cost_observation_missing", Detail: fmt.Sprintf("rule %s has no measured cost", ruleID)})
		}
	}
	sortFailures(failures)
	return ordered, failures, nil
}

func retroFailures(p rulepackdomain.RulePack, evidence []RetroEvidence) []Failure {
	rules := make(map[string]struct{}, len(p.Rules))
	for _, rule := range p.Rules {
		rules[rule.ID] = struct{}{}
	}
	seen := make(map[string]struct{}, len(evidence))
	var failures []Failure
	for _, item := range evidence {
		if _, ok := rules[item.RuleID]; !ok {
			failures = append(failures, Failure{Code: "retro_unknown_rule", Detail: fmt.Sprintf("retro evidence names unknown rule %q", item.RuleID)})
			continue
		}
		if _, dup := seen[item.RuleID]; dup {
			failures = append(failures, Failure{Code: "retro_duplicate_rule", Detail: fmt.Sprintf("rule %s has duplicate retro evidence", item.RuleID)})
			continue
		}
		seen[item.RuleID] = struct{}{}
		switch {
		case item.ContextEvents < 1:
			failures = append(failures, Failure{Code: "retro_context_missing", Detail: fmt.Sprintf("rule %s retro hunt returned no surrounding telemetry", item.RuleID)})
		case item.MatchedEvents < 1:
			failures = append(failures, Failure{Code: "retro_rule_not_observed", Detail: fmt.Sprintf("rule %s did not match its retro-hunt window", item.RuleID)})
		}
		if !item.Complete || item.Sampled || item.SequenceGaps != 0 || item.Losses != 0 {
			failures = append(failures, Failure{Code: "retro_window_incomplete", Detail: fmt.Sprintf("rule %s retro window is incomplete (complete=%t sampled=%t gaps=%d losses=%d)", item.RuleID, item.Complete, item.Sampled, item.SequenceGaps, item.Losses)})
		}
	}
	for ruleID := range rules {
		if _, ok := seen[ruleID]; !ok {
			failures = append(failures, Failure{Code: "retro_evidence_missing", Detail: fmt.Sprintf("rule %s has no retro-hunt evidence", ruleID)})
		}
	}
	sortFailures(failures)
	return failures
}

func emulationFailures(p rulepackdomain.RulePack, coverage []purplecoverage.Coverage, minimumBPS int) (int, []Failure, error) {
	claimed := make(map[string]rulepackdomain.ATTACKMapping, len(p.ATTACKMappings))
	for _, mapping := range p.ATTACKMappings {
		claimed[mapping.RuleID+"\x1f"+mapping.TechniqueID] = mapping
	}
	if len(coverage) > rulepackdomain.MaxATTACKMappings {
		return 0, nil, fmt.Errorf("purple coverage evidence exceeds %d rows", rulepackdomain.MaxATTACKMappings)
	}
	verdicts := make(map[string]purplecoverage.Verdict, len(coverage))
	var scope purplecoverage.Coverage
	haveScope := false
	for _, item := range coverage {
		if err := item.Validate(); err != nil {
			return 0, nil, fmt.Errorf("invalid purple coverage evidence: %w", err)
		}
		if item.AssetID == "" || item.Expected == "" || item.ComputedAt.IsZero() {
			return 0, nil, fmt.Errorf("invalid purple coverage evidence: asset, expected detection, and computed-at are required")
		}
		if !haveScope {
			scope = item
			haveScope = true
		} else if item.TenantID != scope.TenantID || item.EngagementID != scope.EngagementID || item.RunID != scope.RunID || item.AssetID != scope.AssetID {
			return 0, nil, fmt.Errorf("purple coverage evidence mixes release scopes; every row must share tenant, engagement, run, and asset")
		}
		if item.Verdict == purplecoverage.VerdictCovered && !containsDetectionID(item.Actual, item.Expected) {
			return 0, nil, fmt.Errorf("purple coverage evidence claims %s covered without the expected detection %s in actual detections", item.TaxonomyRef, item.Expected)
		}
		if item.Verdict == purplecoverage.VerdictGap && containsDetectionID(item.Actual, item.Expected) {
			return 0, nil, fmt.Errorf("purple coverage evidence claims %s gap even though expected detection %s is present", item.TaxonomyRef, item.Expected)
		}
		key := item.Expected + "\x1f" + item.TaxonomyRef
		if _, ok := claimed[key]; !ok {
			return 0, nil, fmt.Errorf("purple coverage evidence names unclaimed detection/taxonomy pair %s / %s", item.Expected, item.TaxonomyRef)
		}
		if _, duplicate := verdicts[key]; duplicate {
			return 0, nil, fmt.Errorf("duplicate purple coverage evidence for detection %s / %s", item.Expected, item.TaxonomyRef)
		}
		verdicts[key] = item.Verdict
	}
	covered := int64(0)
	missing := make([]string, 0)
	for key, mapping := range claimed {
		verdict, ok := verdicts[key]
		if ok && verdict == purplecoverage.VerdictCovered {
			covered++
			continue
		}
		detail := fmt.Sprintf("%s/%s:missing", mapping.RuleID, mapping.TechniqueID)
		if ok {
			detail = fmt.Sprintf("%s/%s:%s", mapping.RuleID, mapping.TechniqueID, verdict)
		}
		missing = append(missing, detail)
	}
	sort.Strings(missing)
	coverageBPS, err := ratioBPS(covered, int64(len(claimed)))
	if err != nil {
		return 0, nil, err
	}
	var failures []Failure
	if coverageBPS < minimumBPS {
		detail := fmt.Sprintf("ATT&CK coverage %d bps is below required %d bps", coverageBPS, minimumBPS)
		if len(missing) != 0 {
			detail += fmt.Sprintf(" (uncovered: %v)", missing)
		}
		failures = append(failures, Failure{Code: "attack_coverage_below_minimum", Detail: detail})
	}
	return coverageBPS, failures, nil
}

func containsDetectionID(actual []string, expected string) bool {
	if expected == "" {
		return false
	}
	for _, id := range actual {
		if id == expected {
			return true
		}
	}
	return false
}

func fpBudgetFailures(metrics QualityMetrics, policy GatePolicy) []Failure {
	var failures []Failure
	if metrics.ReviewedDetections < policy.MinimumReviewedDetections {
		failures = append(failures, Failure{Code: "reviewed_detection_floor_not_met", Detail: fmt.Sprintf("reviewed detections %d is below required %d", metrics.ReviewedDetections, policy.MinimumReviewedDetections)})
	}
	if metrics.PrecisionBPS < policy.MinimumPrecisionBPS {
		failures = append(failures, Failure{Code: "precision_below_minimum", Detail: fmt.Sprintf("precision %d bps is below required %d bps", metrics.PrecisionBPS, policy.MinimumPrecisionBPS)})
	}
	if metrics.FalsePositiveRateBPS > policy.MaximumFalsePositiveRateBPS {
		failures = append(failures, Failure{Code: "false_positive_rate_above_maximum", Detail: fmt.Sprintf("false-positive rate %d bps exceeds allowed %d bps", metrics.FalsePositiveRateBPS, policy.MaximumFalsePositiveRateBPS)})
	}
	sortFailures(failures)
	return failures
}

func runtimeMetricFailures(scope string, metrics QualityMetrics, maxDensity int64, maxSuppressionBPS int, policy GatePolicy) []Failure {
	var failures []Failure
	if metrics.ReviewedDetections < policy.MinimumReviewedDetections {
		failures = append(failures, Failure{Code: scope + "_reviewed_detection_floor_not_met", Detail: fmt.Sprintf("%s reviewed detections %d is below required %d", scope, metrics.ReviewedDetections, policy.MinimumReviewedDetections)})
	}
	if metrics.PrecisionBPS < policy.MinimumPrecisionBPS {
		failures = append(failures, Failure{Code: scope + "_precision_below_minimum", Detail: fmt.Sprintf("%s precision %d bps is below required %d", scope, metrics.PrecisionBPS, policy.MinimumPrecisionBPS)})
	}
	if metrics.FalsePositiveRateBPS > policy.MaximumFalsePositiveRateBPS {
		failures = append(failures, Failure{Code: scope + "_false_positive_rate_above_maximum", Detail: fmt.Sprintf("%s false-positive rate %d bps exceeds allowed %d", scope, metrics.FalsePositiveRateBPS, policy.MaximumFalsePositiveRateBPS)})
	}
	if metrics.HostDays < policy.MinimumHostDays {
		failures = append(failures, Failure{Code: scope + "_host_day_floor_not_met", Detail: fmt.Sprintf("%s host-days %d is below required %d", scope, metrics.HostDays, policy.MinimumHostDays)})
	}
	if metrics.DetectionsPerHostDayMilli > maxDensity {
		failures = append(failures, Failure{Code: scope + "_detection_density_above_maximum", Detail: fmt.Sprintf("%s detection density %d milli/host-day exceeds allowed %d", scope, metrics.DetectionsPerHostDayMilli, maxDensity)})
	}
	if metrics.RequiredFieldAvailabilityBPS < policy.MinimumRequiredFieldAvailabilityBPS {
		failures = append(failures, Failure{Code: scope + "_required_field_availability_below_minimum", Detail: fmt.Sprintf("%s required-field availability %d bps is below required %d", scope, metrics.RequiredFieldAvailabilityBPS, policy.MinimumRequiredFieldAvailabilityBPS)})
	}
	if metrics.SuppressionRateBPS > maxSuppressionBPS {
		failures = append(failures, Failure{Code: scope + "_suppression_rate_above_maximum", Detail: fmt.Sprintf("%s suppression rate %d bps exceeds pack policy %d", scope, metrics.SuppressionRateBPS, maxSuppressionBPS)})
	}
	if metrics.AnalystDispositionRateBPS < policy.MinimumAnalystDispositionRateBPS {
		failures = append(failures, Failure{Code: scope + "_analyst_disposition_below_minimum", Detail: fmt.Sprintf("%s analyst disposition rate %d bps is below required %d", scope, metrics.AnalystDispositionRateBPS, policy.MinimumAnalystDispositionRateBPS)})
	}
	sortFailures(failures)
	return failures
}

func validateQualitySample(p rulepackdomain.RulePack, sample QualitySample) error {
	counts := []struct {
		name  string
		value int64
	}{
		{"detections", sample.Detections},
		{"true positives", sample.TruePositives},
		{"false positives", sample.FalsePositives},
		{"suppressed detections", sample.SuppressedDetections},
		{"host-days", sample.HostDays},
	}
	for _, item := range counts {
		if item.value < 0 {
			return fmt.Errorf("%s must not be negative", item.name)
		}
	}
	if sample.TruePositives > math.MaxInt64-sample.FalsePositives {
		return fmt.Errorf("reviewed detection count overflows int64")
	}
	reviewed := sample.TruePositives + sample.FalsePositives
	if reviewed > sample.Detections {
		return fmt.Errorf("reviewed detections %d exceed emitted detections %d", reviewed, sample.Detections)
	}
	if sample.Detections > math.MaxInt64-sample.SuppressedDetections {
		return fmt.Errorf("detection plus suppression count overflows int64")
	}
	seen := map[detection.Field]struct{}{}
	for _, field := range sample.AvailableFields {
		if !field.Valid() {
			return fmt.Errorf("quality sample contains unknown field %q", field)
		}
		if _, duplicate := seen[field]; duplicate {
			return fmt.Errorf("quality sample repeats available field %q", field)
		}
		seen[field] = struct{}{}
	}
	return nil
}

func computeQualityMetrics(p rulepackdomain.RulePack, sample QualitySample) (QualityMetrics, error) {
	reviewed := sample.TruePositives + sample.FalsePositives
	precision, err := ratioBPS(sample.TruePositives, reviewed)
	if err != nil {
		return QualityMetrics{}, err
	}
	fpRate, err := ratioBPS(sample.FalsePositives, reviewed)
	if err != nil {
		return QualityMetrics{}, err
	}
	totalCandidates := sample.Detections + sample.SuppressedDetections
	suppression, err := ratioBPS(sample.SuppressedDetections, totalCandidates)
	if err != nil {
		return QualityMetrics{}, err
	}
	disposition, err := ratioBPS(reviewed, sample.Detections)
	if err != nil {
		return QualityMetrics{}, err
	}
	available := make(map[detection.Field]struct{}, len(sample.AvailableFields))
	for _, field := range sample.AvailableFields {
		available[field] = struct{}{}
	}
	availableRequired := int64(0)
	for _, field := range p.RequiredFields {
		if _, ok := available[field]; ok {
			availableRequired++
		}
	}
	fieldAvailability, err := ratioBPS(availableRequired, int64(len(p.RequiredFields)))
	if err != nil {
		return QualityMetrics{}, err
	}
	density, err := perHostDayMilli(sample.Detections, sample.HostDays)
	if err != nil {
		return QualityMetrics{}, err
	}
	return QualityMetrics{
		Detections:                   sample.Detections,
		ReviewedDetections:           reviewed,
		TruePositives:                sample.TruePositives,
		FalsePositives:               sample.FalsePositives,
		SuppressedDetections:         sample.SuppressedDetections,
		HostDays:                     sample.HostDays,
		PrecisionBPS:                 precision,
		FalsePositiveRateBPS:         fpRate,
		SuppressionRateBPS:           suppression,
		AnalystDispositionRateBPS:    disposition,
		RequiredFieldAvailabilityBPS: fieldAvailability,
		DetectionsPerHostDayMilli:    density,
	}, nil
}

func ratioBPS(numerator, denominator int64) (int, error) {
	if numerator < 0 || denominator < 0 || numerator > denominator {
		return 0, fmt.Errorf("invalid ratio %d/%d", numerator, denominator)
	}
	if denominator == 0 {
		return 0, nil
	}
	whole := numerator / denominator
	rem := numerator % denominator
	if rem > math.MaxInt64/10_000 {
		return 0, fmt.Errorf("ratio basis-point remainder overflows int64")
	}
	return int(whole*10_000 + (rem*10_000)/denominator), nil
}

func perHostDayMilli(detections, hostDays int64) (int64, error) {
	if detections < 0 || hostDays < 0 {
		return 0, fmt.Errorf("invalid detections/host-days %d/%d", detections, hostDays)
	}
	if hostDays == 0 {
		return 0, nil
	}
	whole := detections / hostDays
	rem := detections % hostDays
	if whole > math.MaxInt64/1000 || rem > math.MaxInt64/1000 {
		return 0, fmt.Errorf("detections/host-day metric overflows int64")
	}
	return whole*1000 + (rem*1000)/hostDays, nil
}

func stagesPassed(stages []StageResult) bool {
	for _, stage := range stages {
		if !stage.Pass {
			return false
		}
	}
	return true
}

func sortFailures(failures []Failure) {
	sort.Slice(failures, func(i, j int) bool {
		if failures[i].Code != failures[j].Code {
			return failures[i].Code < failures[j].Code
		}
		return failures[i].Detail < failures[j].Detail
	})
}
