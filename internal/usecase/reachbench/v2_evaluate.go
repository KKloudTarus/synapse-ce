package reachbench

import (
	"fmt"
	"math/big"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
)

type evaluationUnit struct {
	caseDef     ContractCase
	oracle      OracleCase
	cohort      ProductionCohort
	binding     CompositionBinding
	observation *MeasuredObservation
	safety      suppressionSafety
}

type suppressionSafety struct {
	falseClaim        bool
	invalidClaim      bool
	captureIncomplete bool
	findings          []SafetyFinding
}

type logicalCase struct {
	caseDef ContractCase
	oracle  OracleCase
	cohort  ProductionCohort
	rule    SuppressionPolicyRule
	units   []evaluationUnit
}

// EvaluateMeasurement validates v2 reachability semantics before projecting explicit positive and suppression
// sets into benchmark.EvaluateAccuracy. Raw duplicates and contradictory output are rejected before that projection.
func EvaluateMeasurement(input MeasurementInput) (MeasurementReport, error) {
	if err := input.Validate(); err != nil {
		return MeasurementReport{}, err
	}
	logical, err := buildLogicalCases(input)
	if err != nil {
		return MeasurementReport{}, err
	}
	report, err := reduceMeasurement(input, logical)
	if err != nil {
		return MeasurementReport{}, err
	}
	if input.Purpose == CandidateAcceptance {
		report.Candidate = CandidateDisposition{Evaluated: true}
		report.Candidate.Reasons = CheckCandidateAcceptance(report, *input.Ratchet, input.Exceptions)
		report.Candidate.Accepted = len(report.Candidate.Reasons) == 0
	}
	id, err := DigestMeasurementReport(report)
	if err != nil {
		return MeasurementReport{}, err
	}
	report.ID = id
	return canonicalReport(report), nil
}

func buildLogicalCases(input MeasurementInput) ([]logicalCase, error) {
	oracleByCase := make(map[string]OracleCase, len(input.Oracle.Cases))
	for _, item := range input.Oracle.Cases {
		oracleByCase[item.CaseID] = item
	}
	observed := make(map[string]*MeasuredObservation, len(input.Observations))
	for i := range input.Observations {
		observation := &input.Observations[i]
		item := corpusCase(input.Corpus, observation.CaseID)
		key := executionKey(item.CohortID, item.ModeID, observation.BindingID, observation.CaseID)
		observed[key] = observation
	}
	logical := make([]logicalCase, 0, len(input.Corpus.Cases))
	for _, item := range input.Corpus.Cases {
		cohort, _ := input.Inventory.cohort(cohortKey(item.CohortID, item.ModeID))
		rule, _ := policyRule(input.Policy, item.CohortID, item.ModeID)
		entry := logicalCase{caseDef: item, oracle: oracleByCase[item.ID], cohort: cohort, rule: rule}
		if cohort.BenchmarkRequired {
			for _, binding := range cohort.Bindings {
				if binding.State != BindingEnabled {
					continue
				}
				key := executionKey(item.CohortID, item.ModeID, binding.ID, item.ID)
				unit := evaluationUnit{caseDef: item, oracle: entry.oracle, cohort: cohort, binding: binding, observation: observed[key]}
				if unit.observation != nil {
					unit.safety = validateSuppression(unit, input.Policy, input.ActiveSnapshot)
				}
				entry.units = append(entry.units, unit)
			}
		}
		logical = append(logical, entry)
	}
	return logical, nil
}

func corpusCase(corpus ContractCorpus, id string) ContractCase {
	for _, item := range corpus.Cases {
		if item.ID == id {
			return item
		}
	}
	return ContractCase{}
}

func validateSuppression(unit evaluationUnit, policy MeasurementPolicy, active SnapshotIdentity) suppressionSafety {
	observation := unit.observation
	if observation == nil {
		return suppressionSafety{}
	}
	result := suppressionSafety{}
	capture := observation.Suppression
	if capture.Claim == SuppressionNone {
		if capture.Status != CaptureComplete || observation.OutputCapture != CaptureComplete {
			result.captureIncomplete = true
			result.findings = append(result.findings, safetyFinding("suppression_capture_incomplete", unit, "no produced suppression can be inferred from incomplete output capture"))
		}
		return result
	}
	if capture.Status != CaptureComplete || observation.OutputCapture != CaptureComplete || len(capture.Effects) == 0 {
		result.invalidClaim = true
		result.findings = append(result.findings, safetyFinding("invalid_suppression", unit, "produced suppression lacks complete capture"))
	}
	rule, ok := policyRule(policy, unit.caseDef.CohortID, unit.caseDef.ModeID)
	if !ok || unit.oracle.Category != OracleTrulyUnreachable || unit.oracle.Expected != OutcomePresentUnreached || !unit.oracle.SuppressionApplicable || unit.oracle.CoverageExpectation != CoverageComplete || observation.Coverage.Status != CoverageComplete || rule.Disposition != SuppressionEligible {
		result.falseClaim = true
		result.findings = append(result.findings, safetyFinding("false_suppression", unit, "produced suppression is not authorized by oracle, coverage, and policy"))
	}
	judgmentEffect := false
	for _, effect := range capture.Effects {
		if effect.Kind == EffectSuppressingJudgment {
			judgmentEffect = true
		}
		if err := validateSuppressionProof(effect, unit, rule, active, *observation); err != nil {
			result.invalidClaim = true
			result.findings = append(result.findings, safetyFinding("invalid_suppression", unit, err.Error()))
		}
	}
	if !judgmentEffect {
		result.invalidClaim = true
		result.findings = append(result.findings, safetyFinding("invalid_suppression", unit, "capture has no suppressing judgment effect"))
	}
	return deduplicateSuppressionSafety(result)
}

func validateSuppressionProof(effect SuppressionEffect, unit evaluationUnit, rule SuppressionPolicyRule, active SnapshotIdentity, observation MeasuredObservation) error {
	if !effect.Kind.valid() {
		return fmt.Errorf("unknown suppression effect")
	}
	proof := effect.Proof
	for _, named := range []struct {
		name string
		ref  ArtifactReference
	}{
		{"judgment reference", proof.Judgment}, {"proof completeness contract", proof.CompletenessContract}, {"proof analyzer", proof.Analyzer}, {"proof configuration", proof.Configuration}, {"proof evidence", proof.Evidence},
	} {
		if err := named.ref.validate(named.name); err != nil {
			return err
		}
	}
	if !validSubjectID(proof.SubjectID) || !validID(proof.BoundaryID) || !validID(proof.Proposer) || !validID(proof.Verifier) || proof.Proposer == proof.Verifier {
		return fmt.Errorf("proof has missing or non-distinct actors and boundary identity")
	}
	if proof.SubjectID != unit.caseDef.SubjectID {
		return fmt.Errorf("proof subject does not match measured case subject")
	}
	if proof.BoundaryID != unit.binding.BoundaryID {
		return fmt.Errorf("proof boundary does not match measured binding boundary")
	}
	if len(proof.MissingProvenance) != 0 {
		return fmt.Errorf("proof declares missing provenance")
	}
	if err := proof.Snapshot.Validate(); err != nil {
		return err
	}
	if rule.CompletenessContract == nil || unit.oracle.CompletenessContract == nil || !sameRef(proof.CompletenessContract, *rule.CompletenessContract) || !sameRef(proof.CompletenessContract, *unit.oracle.CompletenessContract) {
		return fmt.Errorf("proof completeness contract does not match static oracle and current approval")
	}
	if proof.Proposer != rule.ApprovedProposer || proof.Verifier != rule.ApprovedVerifier {
		return fmt.Errorf("proof actor pair does not match current approval")
	}
	if !sameSnapshot(proof.Snapshot, active) {
		return fmt.Errorf("proof snapshot is stale or does not match active source, SBOM, and run")
	}
	if !sameRef(proof.Analyzer, observation.Analyzer) || !sameRef(proof.Configuration, observation.Configuration) {
		return fmt.Errorf("proof analyzer or configuration does not match measured output")
	}
	if observation.Positive != nil && !sameSnapshot(observation.Positive.Snapshot, active) {
		return fmt.Errorf("positive evidence snapshot is stale")
	}
	return nil
}

func deduplicateSuppressionSafety(result suppressionSafety) suppressionSafety {
	seen := map[string]struct{}{}
	out := result
	out.findings = out.findings[:0]
	for _, finding := range result.findings {
		key := safetyFindingKey(finding)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out.findings = append(out.findings, finding)
	}
	return out
}

func safetyFinding(kind string, unit evaluationUnit, reason string) SafetyFinding {
	return SafetyFinding{Kind: kind, CohortID: unit.caseDef.CohortID, ModeID: unit.caseDef.ModeID, BindingID: unit.binding.ID, CaseID: unit.caseDef.ID, Reason: reason}
}

func policyRule(policy MeasurementPolicy, cohortID, modeID string) (SuppressionPolicyRule, bool) {
	key := cohortKey(cohortID, modeID)
	for _, rule := range policy.Rules {
		if cohortKey(rule.CohortID, rule.ModeID) == key {
			return rule, true
		}
	}
	return SuppressionPolicyRule{}, false
}

func reduceMeasurement(input MeasurementInput, logical []logicalCase) (MeasurementReport, error) {
	policyDigest, err := DigestMeasurementPolicy(input.Policy)
	if err != nil {
		return MeasurementReport{}, err
	}
	inventoryDigest, err := DigestProductionInventory(input.Inventory)
	if err != nil {
		return MeasurementReport{}, err
	}
	corpusDigest, err := DigestContractCorpus(input.Corpus)
	if err != nil {
		return MeasurementReport{}, err
	}
	oracleDigest, err := DigestReachabilityOracle(input.Oracle)
	if err != nil {
		return MeasurementReport{}, err
	}
	exceptionDigest, err := DigestExceptionManifest(input.Exceptions)
	if err != nil {
		return MeasurementReport{}, err
	}

	report := MeasurementReport{
		SchemaVersion:     MeasurementReportSchemaVersion,
		Purpose:           input.Purpose,
		Policy:            artifactRef(input.Policy.ID, policyDigest),
		Inventory:         artifactRef(input.Inventory.ID, inventoryDigest),
		Corpus:            artifactRef(input.Corpus.ID, corpusDigest),
		Oracle:            artifactRef(input.Oracle.ID, oracleDigest),
		ExceptionManifest: artifactRef(input.Exceptions.ID, exceptionDigest),
		ActiveSnapshot:    input.ActiveSnapshot,
		Observations:      canonicalMeasuredObservations(input.Observations),
	}
	if input.Ratchet != nil {
		report.RatchetDigest = input.Ratchet.ID
	}
	reachability, suppressions, err := aggregateMetrics(logical)
	if err != nil {
		return MeasurementReport{}, err
	}
	report.Reachability = reachability
	report.Suppressions = suppressions
	report.RequiredExecutions, report.ObservedExecutions, report.UnobservedExecutions = executionCounts(logical)
	report.OutcomeConfusion = outcomeConfusion(logical)
	report.Coverage, report.CoverageRate = coverageSummary(logical)
	report.NoAnalysis, report.NoAnalysisRate = noAnalysisSummary(logical)
	report.ExecutionCoverage = executionCoverage(logical)
	report.Bindings = bindingSummaries(logical)
	report.Cohorts = cohortSummaries(input.Inventory, logical)
	report.Languages = languageSummaries(report.Cohorts, logical)
	report.EnabledCohorts, report.AssessedEnabledCohorts, report.ProductionPositiveCohorts = cohortCounts(report.Cohorts)
	report.C2 = calculateC2(report.Cohorts)
	report.Safety = safetyDisposition(logical)
	return canonicalReport(report), nil
}

func aggregateMetrics(cases []logicalCase) (ReachabilityMetrics, SuppressionMetrics, error) {
	positiveInput := benchmark.AccuracyInput{SchemaVersion: benchmark.AccuracyInputSchemaVersion}
	suppressionInput := benchmark.AccuracyInput{SchemaVersion: benchmark.AccuracyInputSchemaVersion}
	producedSuppressions, validSuppressions, falseSuppressions, invalidSuppressions := int64(0), int64(0), int64(0), int64(0)
	anyEligible, anyProduced, anyIncomplete := false, false, false
	for _, item := range cases {
		flags := scoreFlags(item)
		positive := benchmark.AccuracyObservation{Case: item.caseDef.ID}
		if positiveOutcome(item.oracle.Expected) {
			positive.Expected = []string{item.caseDef.ID}
		}
		if flags.positiveAll {
			positive.Produced = []string{item.caseDef.ID}
		}
		positiveInput.Observations = append(positiveInput.Observations, positive)

		suppression := benchmark.AccuracyObservation{Case: item.caseDef.ID}
		if flags.suppressionEligible {
			suppression.Expected = []string{item.caseDef.ID}
			anyEligible = true
		}
		if flags.suppressionValid {
			suppression.Produced = []string{item.caseDef.ID}
			validSuppressions++
		}
		if flags.suppressionProduced {
			producedSuppressions++
			anyProduced = true
		}
		if flags.falseSuppression {
			falseSuppressions++
		}
		if flags.invalidSuppression {
			invalidSuppressions++
		}
		anyIncomplete = anyIncomplete || flags.captureIncomplete
		suppressionInput.Observations = append(suppressionInput.Observations, suppression)
	}
	positiveReport, err := benchmark.EvaluateAccuracy(positiveInput)
	if err != nil {
		return ReachabilityMetrics{}, SuppressionMetrics{}, fmt.Errorf("evaluate positive accuracy: %w", err)
	}
	suppressionReport, err := benchmark.EvaluateAccuracy(suppressionInput)
	if err != nil {
		return ReachabilityMetrics{}, SuppressionMetrics{}, fmt.Errorf("evaluate suppression accuracy: %w", err)
	}
	reachability := metricsFromAccuracy(positiveReport.Overall)
	suppressions := SuppressionMetrics{
		Eligible: int64(suppressionReport.Overall.TruePositives + suppressionReport.Overall.FalseNegatives),
		Found:    int64(suppressionReport.Overall.TruePositives), Produced: producedSuppressions, Valid: validSuppressions,
		False: falseSuppressions, Invalid: invalidSuppressions,
		Precision: ratioFromCounts(int64(suppressionReport.Overall.TruePositives), int64(suppressionReport.Overall.TruePositives+suppressionReport.Overall.FalsePositives)),
		Recall:    ratioFromCounts(int64(suppressionReport.Overall.TruePositives), int64(suppressionReport.Overall.TruePositives+suppressionReport.Overall.FalseNegatives)),
	}
	switch {
	case anyIncomplete:
		suppressions.Status = RatioUnavailable
		suppressions.Precision = unavailableRatio()
		suppressions.Recall = unavailableRatio()
	case !anyEligible && !anyProduced:
		suppressions.Status = RatioNotApplicable
		suppressions.Precision = notApplicableRatio()
		suppressions.Recall = notApplicableRatio()
	default:
		suppressions.Status = RatioAvailable
	}
	return reachability, suppressions, nil
}

type caseFlags struct {
	assessed            bool
	positiveAll         bool
	positiveExact       bool
	suppressionEligible bool
	suppressionProduced bool
	suppressionValid    bool
	falseSuppression    bool
	invalidSuppression  bool
	captureIncomplete   bool
}

func scoreFlags(item logicalCase) caseFlags {
	flags := caseFlags{assessed: len(item.units) > 0, positiveAll: len(item.units) > 0, positiveExact: len(item.units) > 0}
	flags.suppressionEligible = item.oracle.Expected == OutcomePresentUnreached && item.oracle.SuppressionApplicable && item.oracle.CoverageExpectation == CoverageComplete && item.rule.Disposition == SuppressionEligible
	allProducedValid := true
	for _, unit := range item.units {
		if unit.observation == nil {
			flags.assessed, flags.positiveAll, flags.positiveExact = false, false, false
			continue
		}
		observation := unit.observation
		completeOutput := observation.Invoked && observation.OutputCapture == CaptureComplete
		if !completeOutput {
			flags.assessed, flags.positiveAll, flags.positiveExact = false, false, false
		}
		if completeOutput && !positiveOutcome(observation.Outcome) {
			flags.positiveAll = false
		}
		if completeOutput && observation.Outcome != item.oracle.Expected {
			flags.positiveExact = false
		}
		if observation.Suppression.Status != CaptureComplete || observation.OutputCapture != CaptureComplete {
			flags.captureIncomplete = true
		}
		if observation.Suppression.Claim == SuppressionProduced {
			flags.suppressionProduced = true
			if unit.safety.falseClaim || unit.safety.invalidClaim {
				allProducedValid = false
			}
		}
		if unit.safety.falseClaim {
			flags.falseSuppression = true
		}
		if unit.safety.invalidClaim {
			flags.invalidSuppression = true
		}
		if unit.safety.captureIncomplete {
			flags.captureIncomplete = true
		}
	}
	flags.suppressionValid = flags.suppressionProduced && allProducedValid
	return flags
}

func metricsFromAccuracy(metrics benchmark.Metrics) ReachabilityMetrics {
	return ReachabilityMetrics{
		Expected:  int64(metrics.TruePositives + metrics.FalseNegatives),
		Found:     int64(metrics.TruePositives),
		Produced:  int64(metrics.TruePositives + metrics.FalsePositives),
		Precision: ratioFromCounts(int64(metrics.TruePositives), int64(metrics.TruePositives+metrics.FalsePositives)),
		Recall:    ratioFromCounts(int64(metrics.TruePositives), int64(metrics.TruePositives+metrics.FalseNegatives)),
	}
}

func executionCounts(cases []logicalCase) (required, observed, unobserved int64) {
	for _, item := range cases {
		for _, unit := range item.units {
			required++
			if unit.observation == nil {
				unobserved++
			} else {
				observed++
			}
		}
	}
	return required, observed, unobserved
}

func outcomeConfusion(cases []logicalCase) []OutcomeConfusion {
	counts := map[string]*OutcomeConfusion{}
	for _, item := range cases {
		for _, unit := range item.units {
			if unit.observation == nil {
				continue
			}
			key := string(item.oracle.Expected) + "\x00" + string(unit.observation.Outcome)
			cell := counts[key]
			if cell == nil {
				cell = &OutcomeConfusion{Expected: item.oracle.Expected, Observed: unit.observation.Outcome}
				counts[key] = cell
			}
			cell.Count++
		}
	}
	out := make([]OutcomeConfusion, 0, len(counts))
	for _, cell := range counts {
		out = append(out, *cell)
	}
	return out
}

func coverageSummary(cases []logicalCase) ([]CoverageCount, Ratio) {
	counts := coverageCounts(cases)
	complete, required := int64(0), int64(0)
	for _, item := range cases {
		for _, unit := range item.units {
			required++
			if unit.observation != nil && unit.observation.Coverage.Status == CoverageComplete {
				complete++
			}
		}
	}
	return counts, ratioFromCounts(complete, required)
}

func coverageCounts(cases []logicalCase) []CoverageCount {
	counts := map[CoverageStatus]int64{CoverageComplete: 0, CoveragePartial: 0, CoverageUnavailable: 0, CoverageNotApplicable: 0}
	for _, item := range cases {
		for _, unit := range item.units {
			if unit.observation != nil {
				counts[unit.observation.Coverage.Status]++
			}
		}
	}
	out := make([]CoverageCount, 0, len(counts))
	for status, count := range counts {
		out = append(out, CoverageCount{Status: status, Count: count})
	}
	return canonicalCoverage(out)
}

func noAnalysisSummary(cases []logicalCase) (int64, Ratio) {
	count, required := int64(0), int64(0)
	for _, item := range cases {
		for _, unit := range item.units {
			required++
			if unit.observation != nil && unit.observation.Outcome == OutcomeNoAnalysis {
				count++
			}
		}
	}
	return count, ratioFromCounts(count, required)
}

func executionCoverage(cases []logicalCase) []ExecutionCoverage {
	out := make([]ExecutionCoverage, 0)
	for _, item := range cases {
		for _, unit := range item.units {
			coverage := ExecutionCoverage{CohortID: item.caseDef.CohortID, ModeID: item.caseDef.ModeID, BindingID: unit.binding.ID, CaseID: item.caseDef.ID}
			if unit.observation != nil {
				value := unit.observation.Coverage.Status
				coverage.Observed = true
				coverage.Assessed = unit.observation.Invoked && unit.observation.OutputCapture == CaptureComplete
				coverage.Coverage = &value
			}
			out = append(out, coverage)
		}
	}
	return out
}

func bindingSummaries(cases []logicalCase) []BindingSummary {
	groups := map[string][]logicalCase{}
	for _, item := range cases {
		for _, unit := range item.units {
			copy := item
			copy.units = []evaluationUnit{unit}
			key := cohortKey(item.caseDef.CohortID, item.caseDef.ModeID) + "/" + unit.binding.ID
			groups[key] = append(groups[key], copy)
		}
	}
	out := make([]BindingSummary, 0, len(groups))
	for _, group := range groups {
		reachability, suppressions, _ := aggregateMetrics(group)
		required, observed, _ := executionCounts(group)
		assessment := Assessed
		for _, item := range group {
			if !scoreFlags(item).assessed {
				assessment = NotAssessed
				break
			}
		}
		coverage, coverageRate := coverageSummary(group)
		noAnalysis, noAnalysisRate := noAnalysisSummary(group)
		unit := group[0].units[0]
		out = append(out, BindingSummary{CohortID: unit.caseDef.CohortID, ModeID: unit.caseDef.ModeID, BindingID: unit.binding.ID, RequiredExecutions: required, ObservedExecutions: observed, Assessment: assessment, Reachability: reachability, Suppressions: suppressions, Coverage: coverage, CoverageRate: coverageRate, NoAnalysis: noAnalysis, NoAnalysisRate: noAnalysisRate})
	}
	return out
}

func cohortSummaries(inventory ProductionInventory, cases []logicalCase) []CohortSummary {
	groups := map[string][]logicalCase{}
	for _, item := range cases {
		groups[cohortKey(item.caseDef.CohortID, item.caseDef.ModeID)] = append(groups[cohortKey(item.caseDef.CohortID, item.caseDef.ModeID)], item)
	}
	out := make([]CohortSummary, 0, len(inventory.Cohorts))
	for _, cohort := range inventory.Cohorts {
		group := groups[cohortKey(cohort.ID, cohort.Mode)]
		reachability, suppressions, _ := aggregateMetrics(group)
		required, observed, _ := executionCounts(group)
		assessment := Assessed
		if !cohort.BenchmarkRequired || len(group) == 0 {
			assessment = NotAssessed
		}
		correctPositive := int64(0)
		outcomes := map[Outcome]int64{OutcomeReachable: 0, OutcomeConditionallyReachable: 0, OutcomePresentUnreached: 0, OutcomeNoAnalysis: 0}
		categories := map[OracleCategory]int64{OracleReachable: 0, OracleTrulyUnreachable: 0, OracleOpaque: 0, OracleNoCoverage: 0}
		for _, item := range group {
			flags := scoreFlags(item)
			if !flags.assessed {
				assessment = NotAssessed
			}
			if positiveOutcome(item.oracle.Expected) && flags.assessed && flags.positiveExact {
				correctPositive++
			}
			outcomes[item.oracle.Expected]++
			categories[item.oracle.Category]++
		}
		outcomeCounts := make([]OutcomeCount, 0, len(outcomes))
		for outcome, count := range outcomes {
			outcomeCounts = append(outcomeCounts, OutcomeCount{Outcome: outcome, Count: count})
		}
		categoryCounts := make([]OracleCategoryCount, 0, len(categories))
		for category, count := range categories {
			categoryCounts = append(categoryCounts, OracleCategoryCount{Category: category, Count: count})
		}
		coverage, coverageRate := coverageSummary(group)
		noAnalysis, noAnalysisRate := noAnalysisSummary(group)
		out = append(out, CohortSummary{CohortID: cohort.ID, ModeID: cohort.Mode, Language: cohort.Language, BenchmarkRequired: cohort.BenchmarkRequired, Assessment: assessment, Cases: int64(len(group)), RequiredExecutions: required, ObservedExecutions: observed, OutcomeCounts: canonicalOutcomeCounts(outcomeCounts), CategoryCounts: canonicalCategoryCounts(categoryCounts), Reachability: reachability, Suppressions: suppressions, Coverage: coverage, CoverageRate: coverageRate, NoAnalysis: noAnalysis, NoAnalysisRate: noAnalysisRate, CorrectPositiveCases: correctPositive})
	}
	return out
}

func languageSummaries(cohorts []CohortSummary, cases []logicalCase) []LanguageSummary {
	groups := map[string][]logicalCase{}
	cohortCounts := map[string]int64{}
	for _, cohort := range cohorts {
		cohortCounts[cohort.Language]++
	}
	for _, item := range cases {
		groups[item.cohort.Language] = append(groups[item.cohort.Language], item)
	}
	out := make([]LanguageSummary, 0, len(cohortCounts))
	for language, count := range cohortCounts {
		group := groups[language]
		reachability, suppressions, _ := aggregateMetrics(group)
		coverage, coverageRate := coverageSummary(group)
		noAnalysis, noAnalysisRate := noAnalysisSummary(group)
		out = append(out, LanguageSummary{Language: language, Cohorts: count, Reachability: reachability, Suppressions: suppressions, Coverage: coverage, CoverageRate: coverageRate, NoAnalysis: noAnalysis, NoAnalysisRate: noAnalysisRate})
	}
	return out
}

func cohortCounts(cohorts []CohortSummary) (enabled, assessed, positive int64) {
	for _, cohort := range cohorts {
		if !cohort.BenchmarkRequired {
			continue
		}
		enabled++
		if cohort.Assessment == Assessed {
			assessed++
		}
		if cohort.Reachability.Expected > 0 {
			positive++
		}
	}
	return enabled, assessed, positive
}

func calculateC2(cohorts []CohortSummary) C2Vector {
	vector := C2Vector{MacroReachableRecall: notApplicableRatio()}
	sum := new(big.Rat)
	positiveCohorts := int64(0)
	for _, cohort := range cohorts {
		if !cohort.BenchmarkRequired {
			continue
		}
		if hasAllOracleCategories(cohort.CategoryCounts) && cohort.Assessment == Assessed && cohort.CorrectPositiveCases > 0 {
			vector.ProductionBreadth++
		}
		vector.CorrectPositiveCases += cohort.CorrectPositiveCases
		if cohort.Reachability.Expected > 0 && cohort.Reachability.Recall.Status == RatioAvailable {
			positiveCohorts++
			recall, _ := new(big.Rat).SetString(cohort.Reachability.Recall.Numerator + "/" + cohort.Reachability.Recall.Denominator)
			sum.Add(sum, recall)
		}
	}
	if positiveCohorts > 0 {
		sum.Quo(sum, new(big.Rat).SetInt64(positiveCohorts))
		vector.MacroReachableRecall = ratioFromBig(sum)
	}
	return vector
}

func hasAllOracleCategories(counts []OracleCategoryCount) bool {
	found := map[OracleCategory]int64{}
	for _, item := range counts {
		found[item.Category] = item.Count
	}
	return found[OracleReachable] > 0 && found[OracleTrulyUnreachable] > 0 && found[OracleOpaque] > 0 && found[OracleNoCoverage] > 0
}

func safetyDisposition(cases []logicalCase) SafetyDisposition {
	seen := map[string]struct{}{}
	findings := make([]SafetyFinding, 0)
	for _, item := range cases {
		for _, unit := range item.units {
			for _, finding := range unit.safety.findings {
				key := safetyFindingKey(finding)
				if _, exists := seen[key]; exists {
					continue
				}
				seen[key] = struct{}{}
				findings = append(findings, finding)
			}
		}
	}
	return SafetyDisposition{Pass: len(findings) == 0, Findings: findings}
}

func ratioFromCounts(numerator, denominator int64) Ratio {
	if denominator == 0 {
		return notApplicableRatio()
	}
	return ratioFromBig(new(big.Rat).SetFrac(big.NewInt(numerator), big.NewInt(denominator)))
}

func ratioFromBig(value *big.Rat) Ratio {
	return Ratio{Status: RatioAvailable, Numerator: value.Num().String(), Denominator: value.Denom().String()}
}

func unavailableRatio() Ratio   { return Ratio{Status: RatioUnavailable} }
func notApplicableRatio() Ratio { return Ratio{Status: RatioNotApplicable} }
