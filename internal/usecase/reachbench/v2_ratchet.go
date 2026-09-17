package reachbench

import (
	"fmt"
	"math/big"
	"sort"
)

// DeriveCandidateRatchet deterministically binds policy, the diagnostic baseline result, procedural checkpoint,
// and the frozen exception manifest. The baseline result itself never references this later ratchet.
func DeriveCandidateRatchet(policy MeasurementPolicy, baseline MeasurementReport, checkpoint ProceduralBaselineCheckpoint, exceptions ExceptionManifest) (CandidateRatchet, error) {
	if err := policy.Validate(); err != nil {
		return CandidateRatchet{}, err
	}
	if err := exceptions.Validate(); err != nil {
		return CandidateRatchet{}, err
	}
	if err := baseline.Validate(); err != nil {
		return CandidateRatchet{}, err
	}
	if baseline.Purpose != BaselineMeasurement || baseline.RatchetDigest != "" {
		return CandidateRatchet{}, fmt.Errorf("ratchet baseline is not an acyclic baseline measurement")
	}
	if err := checkpoint.Validate(policy, baseline); err != nil {
		return CandidateRatchet{}, err
	}
	policyDigest, err := DigestMeasurementPolicy(policy)
	if err != nil {
		return CandidateRatchet{}, err
	}
	exceptionDigest, err := DigestExceptionManifest(exceptions)
	if err != nil {
		return CandidateRatchet{}, err
	}
	if !sameRef(policy.ExceptionManifest, artifactRef(exceptions.ID, exceptionDigest)) {
		return CandidateRatchet{}, fmt.Errorf("ratchet exception manifest does not match measurement policy")
	}
	ratchetedBindings := make([]RatchetBinding, len(baseline.Bindings))
	for i, binding := range baseline.Bindings {
		ratchetedBindings[i] = RatchetBinding{CohortID: binding.CohortID, ModeID: binding.ModeID, BindingID: binding.BindingID, Recall: binding.Reachability.Recall}
	}
	ratchetedCohorts := make([]RatchetCohort, len(baseline.Cohorts))
	for i, cohort := range baseline.Cohorts {
		ratchetedCohorts[i] = RatchetCohort{CohortID: cohort.CohortID, ModeID: cohort.ModeID, Recall: cohort.Reachability.Recall, Suppressions: cohort.Suppressions}
	}
	ratchetedLanguages := make([]RatchetLanguage, len(baseline.Languages))
	for i, language := range baseline.Languages {
		ratchetedLanguages[i] = RatchetLanguage{Language: language.Language, Recall: language.Reachability.Recall}
	}
	ratcheted := CandidateRatchet{
		SchemaVersion: CandidateRatchetSchemaVersion,
		Policy:        artifactRef(policy.ID, policyDigest), BaselineResult: artifactRef(baseline.ID, baseline.ID),
		BaselineCheckpoint: artifactRef(checkpoint.ID, checkpoint.ID), ExceptionManifest: artifactRef(exceptions.ID, exceptionDigest),
		C2: baseline.C2, Reachability: baseline.Reachability, Bindings: ratchetedBindings, Cohorts: ratchetedCohorts, Languages: ratchetedLanguages,
		Coverage: append([]ExecutionCoverage(nil), baseline.ExecutionCoverage...),
	}
	id, err := DigestCandidateRatchet(ratcheted)
	if err != nil {
		return CandidateRatchet{}, err
	}
	ratcheted.ID = id
	if err := ratcheted.Validate(); err != nil {
		return CandidateRatchet{}, err
	}
	return canonicalRatchetV2(ratcheted), nil
}

// Validate checks every self-describing ratchet guard and its self digest before a candidate can consume it.
func (ratchet CandidateRatchet) Validate() error {
	if ratchet.SchemaVersion != CandidateRatchetSchemaVersion || !validDigest(ratchet.ID) {
		return fmt.Errorf("invalid candidate ratchet")
	}
	for _, named := range []struct {
		name string
		ref  ArtifactReference
	}{
		{"ratchet policy", ratchet.Policy}, {"ratchet baseline result", ratchet.BaselineResult}, {"ratchet baseline checkpoint", ratchet.BaselineCheckpoint}, {"ratchet exception manifest", ratchet.ExceptionManifest},
	} {
		if err := named.ref.validate(named.name); err != nil {
			return err
		}
	}
	if err := validateC2Vector(ratchet.C2); err != nil {
		return err
	}
	if err := validateReachabilityMetrics(ratchet.Reachability); err != nil {
		return err
	}
	bindings := map[string]struct{}{}
	for _, binding := range ratchet.Bindings {
		key := ratchetBindingKey(binding)
		if !validID(binding.CohortID) || !validID(binding.ModeID) || !validID(binding.BindingID) {
			return fmt.Errorf("invalid ratchet binding %q", key)
		}
		if _, exists := bindings[key]; exists {
			return fmt.Errorf("duplicate ratchet binding %q", key)
		}
		bindings[key] = struct{}{}
		if err := binding.Recall.Validate(); err != nil {
			return fmt.Errorf("ratchet binding %q: %w", key, err)
		}
	}
	cohorts := map[string]struct{}{}
	for _, cohort := range ratchet.Cohorts {
		key := cohortKey(cohort.CohortID, cohort.ModeID)
		if !validID(cohort.CohortID) || !validID(cohort.ModeID) {
			return fmt.Errorf("invalid ratchet cohort %q", key)
		}
		if _, exists := cohorts[key]; exists {
			return fmt.Errorf("duplicate ratchet cohort %q", key)
		}
		cohorts[key] = struct{}{}
		if err := cohort.Recall.Validate(); err != nil {
			return fmt.Errorf("ratchet cohort %q: %w", key, err)
		}
		if err := validateSuppressionMetrics(cohort.Suppressions); err != nil {
			return fmt.Errorf("ratchet cohort %q: %w", key, err)
		}
	}
	languages := map[string]struct{}{}
	for _, language := range ratchet.Languages {
		if !validID(language.Language) {
			return fmt.Errorf("invalid ratchet language")
		}
		if _, exists := languages[language.Language]; exists {
			return fmt.Errorf("duplicate ratchet language %q", language.Language)
		}
		languages[language.Language] = struct{}{}
		if err := language.Recall.Validate(); err != nil {
			return fmt.Errorf("ratchet language %q: %w", language.Language, err)
		}
	}
	observed := int64(0)
	for _, coverage := range ratchet.Coverage {
		if coverage.Observed {
			observed++
		}
	}
	if err := validateExecutionCoverage(ratchet.Coverage, int64(len(ratchet.Coverage)), observed); err != nil {
		return fmt.Errorf("ratchet coverage: %w", err)
	}
	digest, err := DigestCandidateRatchet(ratchet)
	if err != nil {
		return err
	}
	if ratchet.ID != digest {
		return fmt.Errorf("candidate ratchet digest does not bind its contents")
	}
	return nil
}

// CheckCandidateAcceptance enforces strict C2 improvement and every mandatory non-offsettable guard.
func CheckCandidateAcceptance(candidate MeasurementReport, ratchet CandidateRatchet, exceptions ExceptionManifest) []string {
	reasons := make([]string, 0)
	if err := ratchet.Validate(); err != nil {
		reasons = append(reasons, "candidate ratchet is structurally invalid")
	}
	if err := exceptions.Validate(); err != nil {
		reasons = append(reasons, "candidate exception manifest is structurally invalid")
	} else if digest, err := DigestExceptionManifest(exceptions); err != nil || !sameRef(ratchet.ExceptionManifest, artifactRef(exceptions.ID, digest)) {
		reasons = append(reasons, "candidate ratchet does not bind the supplied exception manifest")
	}
	if candidate.Purpose != CandidateAcceptance || candidate.RatchetDigest != ratchet.ID {
		reasons = append(reasons, "candidate report does not bind the supplied ratchet")
	}
	if !strictlyGreaterC2(candidate.C2, ratchet.C2) {
		reasons = append(reasons, "candidate C2 vector is not lexicographically strictly greater than baseline")
	}
	for _, cohort := range candidate.Cohorts {
		if cohort.BenchmarkRequired && cohort.Assessment != Assessed {
			reasons = append(reasons, fmt.Sprintf("enabled cohort %s is not assessed", cohortKey(cohort.CohortID, cohort.ModeID)))
		}
	}
	baselineBindings := map[string]RatchetBinding{}
	for _, binding := range ratchet.Bindings {
		baselineBindings[ratchetBindingKey(binding)] = binding
	}
	candidateBindings := map[string]BindingSummary{}
	for _, binding := range candidate.Bindings {
		key := bindingSummaryKey(binding)
		candidateBindings[key] = binding
		if base, ok := baselineBindings[key]; ok && ratioRegressed(binding.Reachability.Recall, base.Recall) {
			reasons = append(reasons, fmt.Sprintf("binding %s reachable recall regressed", key))
		}
	}
	for key := range baselineBindings {
		if _, ok := candidateBindings[key]; !ok {
			reasons = append(reasons, fmt.Sprintf("binding %s reachable recall regressed", key))
		}
	}
	baselineCohorts := map[string]RatchetCohort{}
	for _, cohort := range ratchet.Cohorts {
		baselineCohorts[cohortKey(cohort.CohortID, cohort.ModeID)] = cohort
	}
	for _, cohort := range candidate.Cohorts {
		base, ok := baselineCohorts[cohortKey(cohort.CohortID, cohort.ModeID)]
		if !ok {
			continue
		}
		if ratioRegressed(cohort.Reachability.Recall, base.Recall) {
			reasons = append(reasons, fmt.Sprintf("cohort %s reachable recall regressed", cohortKey(cohort.CohortID, cohort.ModeID)))
		}
		if base.Suppressions.Status == RatioAvailable && (ratioRegressed(cohort.Suppressions.Precision, base.Suppressions.Precision) || ratioRegressed(cohort.Suppressions.Recall, base.Suppressions.Recall)) {
			reasons = append(reasons, fmt.Sprintf("cohort %s suppressing metrics regressed", cohortKey(cohort.CohortID, cohort.ModeID)))
		}
	}
	baselineLanguages := map[string]RatchetLanguage{}
	for _, language := range ratchet.Languages {
		baselineLanguages[language.Language] = language
	}
	for _, language := range candidate.Languages {
		if base, ok := baselineLanguages[language.Language]; ok && ratioRegressed(language.Reachability.Recall, base.Recall) {
			reasons = append(reasons, fmt.Sprintf("language %s reachable recall regressed", language.Language))
		}
	}
	if ratioRegressed(candidate.Reachability.Precision, ratchet.Reachability.Precision) {
		reasons = append(reasons, "reachable precision regressed")
	}
	if candidate.Suppressions.False != 0 || candidate.Suppressions.Invalid != 0 {
		reasons = append(reasons, "candidate produced false or invalid suppressions")
	}
	if !candidate.Safety.Pass {
		reasons = append(reasons, "candidate has incomplete or unsafe suppression capture")
	}
	approved := map[string]struct{}{}
	for _, entry := range exceptions.Entries {
		approved[executionKey(entry.CohortID, entry.ModeID, entry.BindingID, entry.CaseID)] = struct{}{}
	}
	candidateCoverage := map[string]ExecutionCoverage{}
	for _, coverage := range candidate.ExecutionCoverage {
		candidateCoverage[executionCoverageKey(coverage)] = coverage
	}
	for _, baselineCoverage := range ratchet.Coverage {
		key := executionCoverageKey(baselineCoverage)
		current, ok := candidateCoverage[key]
		if !ok || coverageRegressed(current, baselineCoverage) {
			if _, allowed := approved[key]; !allowed {
				reasons = append(reasons, fmt.Sprintf("unlisted coverage regression at %s", key))
			}
		}
	}
	sort.Strings(reasons)
	return deduplicateStrings(reasons)
}

func strictlyGreaterC2(candidate, baseline C2Vector) bool {
	if candidate.ProductionBreadth != baseline.ProductionBreadth {
		return candidate.ProductionBreadth > baseline.ProductionBreadth
	}
	if candidate.CorrectPositiveCases != baseline.CorrectPositiveCases {
		return candidate.CorrectPositiveCases > baseline.CorrectPositiveCases
	}
	return compareRatios(candidate.MacroReachableRecall, baseline.MacroReachableRecall) > 0
}

func ratioRegressed(candidate, baseline Ratio) bool {
	if baseline.Status != RatioAvailable {
		return false
	}
	if candidate.Status != RatioAvailable {
		return true
	}
	return compareRatios(candidate, baseline) < 0
}

func compareRatios(left, right Ratio) int {
	if left.Status != right.Status {
		return ratioStatusRank(left.Status) - ratioStatusRank(right.Status)
	}
	if left.Status != RatioAvailable {
		return 0
	}
	leftN, leftOK := new(big.Int).SetString(left.Numerator, 10)
	leftD, leftDOK := new(big.Int).SetString(left.Denominator, 10)
	rightN, rightOK := new(big.Int).SetString(right.Numerator, 10)
	rightD, rightDOK := new(big.Int).SetString(right.Denominator, 10)
	if !leftOK || !leftDOK || !rightOK || !rightDOK || leftN.Sign() < 0 || rightN.Sign() < 0 || leftD.Sign() <= 0 || rightD.Sign() <= 0 {
		return 0
	}
	return new(big.Int).Mul(leftN, rightD).Cmp(new(big.Int).Mul(rightN, leftD))
}

func ratioStatusRank(status RatioStatus) int {
	switch status {
	case RatioAvailable:
		return 3
	case RatioNotApplicable:
		return 2
	case RatioUnavailable:
		return 1
	default:
		return 0
	}
}

func coverageRegressed(candidate, baseline ExecutionCoverage) bool {
	if !baseline.Assessed {
		return false
	}
	if !candidate.Assessed || candidate.Coverage == nil || baseline.Coverage == nil {
		return true
	}
	return coverageRank(*candidate.Coverage) < coverageRank(*baseline.Coverage)
}

func coverageRank(status CoverageStatus) int {
	switch status {
	case CoverageComplete:
		return 3
	case CoveragePartial:
		return 2
	case CoverageUnavailable:
		return 1
	default:
		return 0
	}
}

func deduplicateStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := values[:0]
	for _, value := range values {
		if len(out) == 0 || out[len(out)-1] != value {
			out = append(out, value)
		}
	}
	return out
}
