package reachbench

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
)

// DigestProductionInventory returns an order-independent artifact digest.
func DigestProductionInventory(inventory ProductionInventory) (string, error) {
	if err := inventory.Validate(); err != nil {
		return "", err
	}
	return digestCanonical(canonicalInventory(inventory))
}

// DigestContractCorpus returns an order-independent artifact digest.
func DigestContractCorpus(corpus ContractCorpus) (string, error) {
	if err := corpus.Validate(); err != nil {
		return "", err
	}
	return digestCanonical(canonicalCorpus(corpus))
}

// DigestReachabilityOracle returns an order-independent artifact digest.
func DigestReachabilityOracle(oracle ReachabilityOracle) (string, error) {
	if err := oracle.Validate(); err != nil {
		return "", err
	}
	return digestCanonical(canonicalOracleV2(oracle))
}

// DigestMeasurementPolicy returns the static policy digest without introducing a baseline/ratchet cycle.
func DigestMeasurementPolicy(policy MeasurementPolicy) (string, error) {
	if err := policy.Validate(); err != nil {
		return "", err
	}
	return digestCanonical(canonicalPolicy(policy))
}

// DigestExceptionManifest returns an order-independent exception manifest digest.
func DigestExceptionManifest(manifest ExceptionManifest) (string, error) {
	if err := manifest.Validate(); err != nil {
		return "", err
	}
	return digestCanonical(canonicalExceptions(manifest))
}

// DigestMeasurementReport excludes its self-referential ID field.
func DigestMeasurementReport(report MeasurementReport) (string, error) {
	canonical := canonicalReport(report)
	canonical.ID = ""
	return digestCanonical(canonical)
}

// DigestProceduralBaselineCheckpoint excludes its self-referential ID field.
func DigestProceduralBaselineCheckpoint(checkpoint ProceduralBaselineCheckpoint) (string, error) {
	canonical := checkpoint
	canonical.ID = ""
	return digestCanonical(canonical)
}

// DigestCandidateRatchet excludes its self-referential ID field.
func DigestCandidateRatchet(ratchet CandidateRatchet) (string, error) {
	canonical := canonicalRatchetV2(ratchet)
	canonical.ID = ""
	return digestCanonical(canonical)
}

func digestCanonical(value any) (string, error) {
	encoded, err := benchmark.CanonicalJSON(value)
	if err != nil {
		return "", err
	}
	return benchmark.SHA256Digest(encoded), nil
}

func canonicalInventory(inventory ProductionInventory) ProductionInventory {
	out := inventory
	out.Cohorts = append([]ProductionCohort(nil), inventory.Cohorts...)
	for i := range out.Cohorts {
		out.Cohorts[i].Bindings = append([]CompositionBinding(nil), out.Cohorts[i].Bindings...)
		sort.Slice(out.Cohorts[i].Bindings, func(left, right int) bool {
			return out.Cohorts[i].Bindings[left].ID < out.Cohorts[i].Bindings[right].ID
		})
	}
	sort.Slice(out.Cohorts, func(left, right int) bool {
		return cohortKey(out.Cohorts[left].ID, out.Cohorts[left].Mode) < cohortKey(out.Cohorts[right].ID, out.Cohorts[right].Mode)
	})
	return out
}

func canonicalCorpus(corpus ContractCorpus) ContractCorpus {
	out := corpus
	out.Cases = append([]ContractCase(nil), corpus.Cases...)
	sort.Slice(out.Cases, func(left, right int) bool { return out.Cases[left].ID < out.Cases[right].ID })
	return out
}

func canonicalOracleV2(oracle ReachabilityOracle) ReachabilityOracle {
	out := oracle
	out.Cases = append([]OracleCase(nil), oracle.Cases...)
	sort.Slice(out.Cases, func(left, right int) bool { return out.Cases[left].CaseID < out.Cases[right].CaseID })
	return out
}

func canonicalPolicy(policy MeasurementPolicy) MeasurementPolicy {
	out := policy
	out.Adapters = append([]ArtifactReference(nil), policy.Adapters...)
	sort.Slice(out.Adapters, func(left, right int) bool { return out.Adapters[left].ID < out.Adapters[right].ID })
	out.Rules = append([]SuppressionPolicyRule(nil), policy.Rules...)
	sort.Slice(out.Rules, func(left, right int) bool {
		return cohortKey(out.Rules[left].CohortID, out.Rules[left].ModeID) < cohortKey(out.Rules[right].CohortID, out.Rules[right].ModeID)
	})
	return out
}

func canonicalExceptions(manifest ExceptionManifest) ExceptionManifest {
	out := manifest
	out.Entries = append([]CoverageException(nil), manifest.Entries...)
	sort.Slice(out.Entries, func(left, right int) bool { return out.Entries[left].ID < out.Entries[right].ID })
	return out
}

func canonicalReport(report MeasurementReport) MeasurementReport {
	out := report
	out.OutcomeConfusion = append([]OutcomeConfusion(nil), report.OutcomeConfusion...)
	sort.Slice(out.OutcomeConfusion, func(left, right int) bool {
		return outcomePairKey(out.OutcomeConfusion[left]) < outcomePairKey(out.OutcomeConfusion[right])
	})
	out.Coverage = canonicalCoverage(out.Coverage)
	out.Bindings = append([]BindingSummary(nil), report.Bindings...)
	sort.Slice(out.Bindings, func(left, right int) bool {
		return bindingSummaryKey(out.Bindings[left]) < bindingSummaryKey(out.Bindings[right])
	})
	out.Cohorts = append([]CohortSummary(nil), report.Cohorts...)
	for i := range out.Cohorts {
		out.Cohorts[i].OutcomeCounts = canonicalOutcomeCounts(out.Cohorts[i].OutcomeCounts)
		out.Cohorts[i].CategoryCounts = canonicalCategoryCounts(out.Cohorts[i].CategoryCounts)
		out.Cohorts[i].Coverage = canonicalCoverage(out.Cohorts[i].Coverage)
	}
	sort.Slice(out.Cohorts, func(left, right int) bool {
		return cohortKey(out.Cohorts[left].CohortID, out.Cohorts[left].ModeID) < cohortKey(out.Cohorts[right].CohortID, out.Cohorts[right].ModeID)
	})
	out.Languages = append([]LanguageSummary(nil), report.Languages...)
	for i := range out.Languages {
		out.Languages[i].Coverage = canonicalCoverage(out.Languages[i].Coverage)
	}
	sort.Slice(out.Languages, func(left, right int) bool { return out.Languages[left].Language < out.Languages[right].Language })
	out.ExecutionCoverage = append([]ExecutionCoverage(nil), report.ExecutionCoverage...)
	sort.Slice(out.ExecutionCoverage, func(left, right int) bool {
		return executionCoverageKey(out.ExecutionCoverage[left]) < executionCoverageKey(out.ExecutionCoverage[right])
	})
	out.Observations = canonicalMeasuredObservations(report.Observations)
	out.Safety.Findings = append([]SafetyFinding(nil), report.Safety.Findings...)
	sort.Slice(out.Safety.Findings, func(left, right int) bool {
		return safetyFindingKey(out.Safety.Findings[left]) < safetyFindingKey(out.Safety.Findings[right])
	})
	out.Candidate.Reasons = append([]string(nil), report.Candidate.Reasons...)
	sort.Strings(out.Candidate.Reasons)
	return out
}

func canonicalRatchetV2(ratchet CandidateRatchet) CandidateRatchet {
	out := ratchet
	out.Bindings = append([]RatchetBinding(nil), ratchet.Bindings...)
	sort.Slice(out.Bindings, func(left, right int) bool {
		return ratchetBindingKey(out.Bindings[left]) < ratchetBindingKey(out.Bindings[right])
	})
	out.Cohorts = append([]RatchetCohort(nil), ratchet.Cohorts...)
	sort.Slice(out.Cohorts, func(left, right int) bool {
		return cohortKey(out.Cohorts[left].CohortID, out.Cohorts[left].ModeID) < cohortKey(out.Cohorts[right].CohortID, out.Cohorts[right].ModeID)
	})
	out.Languages = append([]RatchetLanguage(nil), ratchet.Languages...)
	sort.Slice(out.Languages, func(left, right int) bool { return out.Languages[left].Language < out.Languages[right].Language })
	out.Coverage = append([]ExecutionCoverage(nil), ratchet.Coverage...)
	sort.Slice(out.Coverage, func(left, right int) bool {
		return executionCoverageKey(out.Coverage[left]) < executionCoverageKey(out.Coverage[right])
	})
	return out
}

func canonicalCoverage(counts []CoverageCount) []CoverageCount {
	out := append([]CoverageCount(nil), counts...)
	sort.Slice(out, func(left, right int) bool { return out[left].Status < out[right].Status })
	return out
}

func canonicalOutcomeCounts(counts []OutcomeCount) []OutcomeCount {
	out := append([]OutcomeCount(nil), counts...)
	sort.Slice(out, func(left, right int) bool { return out[left].Outcome < out[right].Outcome })
	return out
}

func canonicalCategoryCounts(counts []OracleCategoryCount) []OracleCategoryCount {
	out := append([]OracleCategoryCount(nil), counts...)
	sort.Slice(out, func(left, right int) bool { return out[left].Category < out[right].Category })
	return out
}

func canonicalMeasuredObservations(observations []MeasuredObservation) []MeasuredObservation {
	out := append([]MeasuredObservation(nil), observations...)
	for i := range out {
		out[i].Coverage.Obligations = append([]CoverageObligation(nil), out[i].Coverage.Obligations...)
		sort.Slice(out[i].Coverage.Obligations, func(left, right int) bool {
			return out[i].Coverage.Obligations[left].ID < out[i].Coverage.Obligations[right].ID
		})
		out[i].Coverage.Reasons = append([]CoverageReason(nil), out[i].Coverage.Reasons...)
		sort.Slice(out[i].Coverage.Reasons, func(left, right int) bool {
			if out[i].Coverage.Reasons[left].Code != out[i].Coverage.Reasons[right].Code {
				return out[i].Coverage.Reasons[left].Code < out[i].Coverage.Reasons[right].Code
			}
			return out[i].Coverage.Reasons[left].Detail < out[i].Coverage.Reasons[right].Detail
		})
		out[i].Suppression.Effects = append([]SuppressionEffect(nil), out[i].Suppression.Effects...)
		for j := range out[i].Suppression.Effects {
			out[i].Suppression.Effects[j].Proof.MissingProvenance = append([]string(nil), out[i].Suppression.Effects[j].Proof.MissingProvenance...)
			sort.Strings(out[i].Suppression.Effects[j].Proof.MissingProvenance)
		}
		sort.Slice(out[i].Suppression.Effects, func(left, right int) bool {
			leftProof, rightProof := out[i].Suppression.Effects[left].Proof, out[i].Suppression.Effects[right].Proof
			return strings.Join([]string{string(out[i].Suppression.Effects[left].Kind), leftProof.Judgment.ID, leftProof.Judgment.Digest, leftProof.Evidence.ID, leftProof.Evidence.Digest}, "\x00") <
				strings.Join([]string{string(out[i].Suppression.Effects[right].Kind), rightProof.Judgment.ID, rightProof.Judgment.Digest, rightProof.Evidence.ID, rightProof.Evidence.Digest}, "\x00")
		})
	}
	sort.Slice(out, func(left, right int) bool {
		return out[left].CaseID+"\x00"+out[left].BindingID < out[right].CaseID+"\x00"+out[right].BindingID
	})
	return out
}

func sameMeasurementReport(left, right MeasurementReport) bool {
	leftJSON, leftErr := benchmark.CanonicalJSON(canonicalReport(left))
	rightJSON, rightErr := benchmark.CanonicalJSON(canonicalReport(right))
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func sameCandidateRatchet(left, right CandidateRatchet) bool {
	leftJSON, leftErr := benchmark.CanonicalJSON(canonicalRatchetV2(left))
	rightJSON, rightErr := benchmark.CanonicalJSON(canonicalRatchetV2(right))
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func artifactRef(id, digest string) ArtifactReference {
	return ArtifactReference{ID: id, Digest: digest}
}

func (ref ArtifactReference) validate(name string) error {
	if !validID(ref.ID) || !validDigest(ref.Digest) {
		return fmt.Errorf("%s requires immutable id and sha256 digest", name)
	}
	return nil
}

func sameRef(left, right ArtifactReference) bool {
	return left.ID == right.ID && left.Digest == right.Digest
}

func validID(value string) bool {
	if value == "" || value != strings.TrimSpace(value) {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune("._/-:", char) {
			continue
		}
		return false
	}
	return true
}

const maxSubjectIDBytes = 4096

// validSubjectID permits canonical package URLs and symbol identities while bounding untrusted input.
func validSubjectID(value string) bool {
	if value == "" || len(value) > maxSubjectIDBytes || value != strings.TrimSpace(value) || !utf8.ValidString(value) {
		return false
	}
	for _, char := range value {
		if unicode.IsControl(char) {
			return false
		}
	}
	return true
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, char := range value[len("sha256:"):] {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return false
		}
	}
	return true
}

func validLegacyDigest(value string) bool {
	if len(value) == 64 {
		for _, char := range value {
			if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
				return false
			}
		}
		return true
	}
	return validDigest(value)
}

func cohortKey(cohortID, modeID string) string { return cohortID + "/" + modeID }
func executionKey(cohortID, modeID, bindingID, caseID string) string {
	return cohortID + "/" + modeID + "/" + bindingID + "/" + caseID
}
func bindingSummaryKey(summary BindingSummary) string {
	return cohortKey(summary.CohortID, summary.ModeID) + "/" + summary.BindingID
}
func ratchetBindingKey(binding RatchetBinding) string {
	return cohortKey(binding.CohortID, binding.ModeID) + "/" + binding.BindingID
}
func executionCoverageKey(coverage ExecutionCoverage) string {
	return executionKey(coverage.CohortID, coverage.ModeID, coverage.BindingID, coverage.CaseID)
}
func safetyFindingKey(finding SafetyFinding) string {
	return strings.Join([]string{finding.Kind, finding.CohortID, finding.ModeID, finding.BindingID, finding.CaseID, finding.Reason}, "\x00")
}
func outcomePairKey(pair OutcomeConfusion) string {
	return string(pair.Expected) + "\x00" + string(pair.Observed)
}

func findBinding(cohort ProductionCohort, id string) (CompositionBinding, bool) {
	for _, binding := range cohort.Bindings {
		if binding.ID == id {
			return binding, true
		}
	}
	return CompositionBinding{}, false
}

func sameSnapshot(left, right SnapshotIdentity) bool {
	return sameRef(left.Source, right.Source) && sameRef(left.SBOM, right.SBOM) && sameRef(left.Run, right.Run)
}
