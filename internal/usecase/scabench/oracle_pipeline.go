package scabench

import (
	"fmt"
	"sort"
	"strings"
)

// BuildOracleCandidate deterministically derives proposed truth from the pinned
// public source disposition. It intentionally has no scanner input.
func BuildOracleCandidate(freeze SourceFreeze, source SourceCaseEvidenceSet) (OracleCandidate, error) {
	if err := freeze.Validate(); err != nil {
		return OracleCandidate{}, err
	}
	if err := source.Validate(); err != nil {
		return OracleCandidate{}, err
	}
	freezeDigest, err := DigestSourceFreeze(freeze)
	if err != nil {
		return OracleCandidate{}, err
	}
	if source.CycleID != freeze.CycleID || source.SourceFreezeDigest != freezeDigest {
		return OracleCandidate{}, fmt.Errorf("source case evidence does not bind the source freeze")
	}
	if len(source.Unsupported) != 0 {
		return OracleCandidate{}, fmt.Errorf("source case evidence retains unsupported vendor branches")
	}
	candidate := OracleCandidate{SchemaVersion: OracleCandidateSchemaVersion, CycleID: source.CycleID, SourceFreezeDigest: freezeDigest, Cases: make([]OracleCandidateCase, 0, len(source.Cases))}
	for _, item := range source.Cases {
		candidate.Cases = append(candidate.Cases, OracleCandidateCase{
			ID: item.ID, TargetID: item.TargetID, Component: item.Component, AdvisoryID: item.AdvisoryID,
			Truth: item.DerivedTruth, Rationale: item.Rationale,
			Citations: append([]ContentReference(nil), item.Citations...),
		})
	}
	if err := candidate.Validate(); err != nil {
		return OracleCandidate{}, err
	}
	return candidate, nil
}

// BuildAutomatedCrossCheck derives a separate source-only result from pinned
// version relations, then compares it with the candidate without accepting any
// observation, bundle, scanner, or score material.
// BuildAutomatedCrossCheck independently derives each case truth from the
// generated target-native comparison records. It never accepts an authored
// version relation.
func BuildAutomatedCrossCheck(source SourceCaseEvidenceSet, native NativeEvidenceSet, candidate OracleCandidate) (AutomatedCrossCheck, error) {
	if err := source.Validate(); err != nil {
		return AutomatedCrossCheck{}, err
	}
	if err := native.Validate(); err != nil {
		return AutomatedCrossCheck{}, err
	}
	if err := candidate.Validate(); err != nil {
		return AutomatedCrossCheck{}, err
	}
	if source.CycleID != candidate.CycleID || source.SourceFreezeDigest != candidate.SourceFreezeDigest || native.CycleID != source.CycleID || native.SourceFreezeDigest != source.SourceFreezeDigest {
		return AutomatedCrossCheck{}, fmt.Errorf("cross-check inputs belong to different freezes")
	}
	nativeDigest, err := DigestNativeEvidenceSet(native)
	if err != nil {
		return AutomatedCrossCheck{}, err
	}
	if source.NativeEvidenceDigest != nativeDigest {
		return AutomatedCrossCheck{}, fmt.Errorf("source case evidence does not bind native evidence")
	}
	sourceDigest, err := DigestSourceCaseEvidence(source)
	if err != nil {
		return AutomatedCrossCheck{}, err
	}
	candidateDigest, err := DigestOracleCandidate(candidate)
	if err != nil {
		return AutomatedCrossCheck{}, err
	}
	cases := make([]CrossCheckCase, 0, len(source.Cases))
	for _, item := range source.Cases {
		comparisons := make([]NativeComparisonRecord, 0, len(item.NativeComparisonIDs))
		for _, comparisonID := range item.NativeComparisonIDs {
			comparison, exists := native.Comparison(comparisonID)
			if !exists || comparison.TargetID != item.TargetID {
				return AutomatedCrossCheck{}, fmt.Errorf("source case evidence %q has an unbound native comparison", item.ID)
			}
			comparisons = append(comparisons, comparison)
		}
		truth, err := nativeComparisonTruth(comparisons)
		if err != nil {
			return AutomatedCrossCheck{}, fmt.Errorf("source case evidence %q: %w", item.ID, err)
		}
		if truth != item.DerivedTruth {
			return AutomatedCrossCheck{}, fmt.Errorf("source case evidence %q derived truth does not match target-native comparisons", item.ID)
		}
		cases = append(cases, CrossCheckCase{ID: item.ID, Truth: truth})
	}
	resultDigest, err := DigestCrossCheckCases(cases)
	if err != nil {
		return AutomatedCrossCheck{}, err
	}
	check := AutomatedCrossCheck{
		SchemaVersion: CrossCheckSchemaVersion, CycleID: source.CycleID, OracleCandidateDigest: candidateDigest,
		Method: "automated_scanner_blinded_cross_check", InputDigest: sourceDigest, ResultDigest: resultDigest,
		Status: crossCheckStatus(candidate, cases), Cases: cases,
	}
	if err := check.Validate(); err != nil {
		return AutomatedCrossCheck{}, err
	}
	return check, nil
}

// AdjudicateOracleCandidate records only whether the two source-only methods
// agree exactly. A disagreement remains unresolved; it cannot be waived by a
// scanner result or a reviewer label.
func AdjudicateOracleCandidate(candidate OracleCandidate, check AutomatedCrossCheck) (AdjudicationRecord, error) {
	if err := candidate.Validate(); err != nil {
		return AdjudicationRecord{}, err
	}
	if err := check.Validate(); err != nil {
		return AdjudicationRecord{}, err
	}
	candidateDigest, err := DigestOracleCandidate(candidate)
	if err != nil {
		return AdjudicationRecord{}, err
	}
	checkDigest, err := DigestAutomatedCrossCheck(check)
	if err != nil {
		return AdjudicationRecord{}, err
	}
	if check.CycleID != candidate.CycleID || check.OracleCandidateDigest != candidateDigest {
		return AdjudicationRecord{}, fmt.Errorf("adjudication inputs do not bind the oracle candidate")
	}
	resolution, err := DigestAdjudicationResolution(candidate, check.Cases)
	if err != nil {
		return AdjudicationRecord{}, err
	}
	status := "unresolved"
	if check.Status == "passed" && candidateMatchesCrossCheck(candidate, check.Cases) {
		status = "resolved"
	}
	record := AdjudicationRecord{SchemaVersion: AdjudicationSchemaVersion, CycleID: candidate.CycleID, OracleCandidateDigest: candidateDigest, CrossCheckDigest: checkDigest, ResolutionDigest: resolution, Status: status}
	if err := record.Validate(); err != nil {
		return AdjudicationRecord{}, err
	}
	return record, nil
}

// FreezeFinalOracle makes the review gate explicit. The caller supplies the
// accountable review record; this function never manufactures a reviewer identity.
func FreezeFinalOracle(freeze SourceFreeze, candidate OracleCandidate, check AutomatedCrossCheck, adjudication AdjudicationRecord, review AccountableReview, oracle Oracle) (FinalOracleFreeze, error) {
	if err := freeze.Validate(); err != nil {
		return FinalOracleFreeze{}, err
	}
	if err := candidate.Validate(); err != nil {
		return FinalOracleFreeze{}, err
	}
	if err := check.Validate(); err != nil {
		return FinalOracleFreeze{}, err
	}
	if err := adjudication.Validate(); err != nil {
		return FinalOracleFreeze{}, err
	}
	if err := review.Validate(); err != nil {
		return FinalOracleFreeze{}, err
	}
	if err := oracle.Validate(); err != nil {
		return FinalOracleFreeze{}, err
	}
	if check.Status != "passed" || adjudication.Status != "resolved" || review.Decision != "approved" {
		return FinalOracleFreeze{}, fmt.Errorf("final oracle freeze requires passed cross-check, resolved adjudication, and accountable approval")
	}
	freezeDigest, err := DigestSourceFreeze(freeze)
	if err != nil {
		return FinalOracleFreeze{}, err
	}
	candidateDigest, err := DigestOracleCandidate(candidate)
	if err != nil {
		return FinalOracleFreeze{}, err
	}
	checkDigest, err := DigestAutomatedCrossCheck(check)
	if err != nil {
		return FinalOracleFreeze{}, err
	}
	adjudicationDigest, err := DigestAdjudicationRecord(adjudication)
	if err != nil {
		return FinalOracleFreeze{}, err
	}
	reviewDigest, err := DigestAccountableReview(review)
	if err != nil {
		return FinalOracleFreeze{}, err
	}
	if candidate.CycleID != freeze.CycleID || check.CycleID != freeze.CycleID || adjudication.CycleID != freeze.CycleID || review.CycleID != freeze.CycleID || candidate.SourceFreezeDigest != freezeDigest || check.OracleCandidateDigest != candidateDigest || adjudication.OracleCandidateDigest != candidateDigest || adjudication.CrossCheckDigest != checkDigest || review.AdjudicationDigest != adjudicationDigest {
		return FinalOracleFreeze{}, fmt.Errorf("final oracle freeze inputs do not form a bound scanner-free chain")
	}
	if !candidateMatchesOracle(candidate, oracle) {
		return FinalOracleFreeze{}, fmt.Errorf("final oracle does not exactly retain every truth-bearing candidate field")
	}
	if !oracleReviewedBy(oracle, review.ReviewerIdentity) {
		return FinalOracleFreeze{}, fmt.Errorf("every final oracle case must identify the submitted accountable reviewer")
	}
	oracleDigest, err := DigestOracle(oracle)
	if err != nil {
		return FinalOracleFreeze{}, err
	}
	if review.FinalOracleDigest != oracleDigest {
		return FinalOracleFreeze{}, fmt.Errorf("accountable review does not bind the exact final oracle digest")
	}
	result := FinalOracleFreeze{SchemaVersion: FinalOracleFreezeSchemaVersion, CycleID: freeze.CycleID, SourceFreezeDigest: freezeDigest, OracleCandidateDigest: candidateDigest, CrossCheckDigest: checkDigest, AdjudicationDigest: adjudicationDigest, AccountableReviewDigest: reviewDigest, OracleDigest: oracleDigest}
	if err := result.Validate(); err != nil {
		return FinalOracleFreeze{}, err
	}
	return result, nil
}

func DigestCrossCheckCases(cases []CrossCheckCase) (string, error) {
	copyCases := append([]CrossCheckCase(nil), cases...)
	sort.Slice(copyCases, func(left, right int) bool { return copyCases[left].ID < copyCases[right].ID })
	for _, item := range copyCases {
		if strings.TrimSpace(item.ID) == "" || (item.Truth != TruthAffected && item.Truth != TruthFixed && item.Truth != TruthNotAffected && item.Truth != TruthWithdrawn) {
			return "", fmt.Errorf("cross-check case is invalid")
		}
	}
	body, err := CanonicalJSON(copyCases)
	if err != nil {
		return "", fmt.Errorf("encode cross-check cases: %w", err)
	}
	return SHA256Digest(body), nil
}

func DigestAdjudicationResolution(candidate OracleCandidate, cases []CrossCheckCase) (string, error) {
	if err := candidate.Validate(); err != nil {
		return "", err
	}
	candidateDigest, err := DigestOracleCandidate(candidate)
	if err != nil {
		return "", err
	}
	checkDigest, err := DigestCrossCheckCases(cases)
	if err != nil {
		return "", err
	}
	return SHA256Digest([]byte(candidateDigest + "\n" + checkDigest)), nil
}

func crossCheckStatus(candidate OracleCandidate, cases []CrossCheckCase) string {
	if candidateMatchesCrossCheck(candidate, cases) {
		return "passed"
	}
	return "failed"
}

func candidateMatchesCrossCheck(candidate OracleCandidate, cases []CrossCheckCase) bool {
	if len(candidate.Cases) != len(cases) {
		return false
	}
	truths := make(map[string]Truth, len(cases))
	for _, item := range cases {
		if _, exists := truths[item.ID]; exists {
			return false
		}
		truths[item.ID] = item.Truth
	}
	for _, item := range candidate.Cases {
		if truth, exists := truths[item.ID]; !exists || truth != item.Truth {
			return false
		}
	}
	return true
}

func candidateMatchesOracle(candidate OracleCandidate, oracle Oracle) bool {
	if len(candidate.Cases) != len(oracle.Cases) {
		return false
	}
	byID := make(map[string]OracleCase, len(oracle.Cases))
	for _, item := range oracle.Cases {
		byID[item.ID] = item
	}
	for _, item := range candidate.Cases {
		oracleCase, exists := byID[item.ID]
		if !exists || oracleCase.TargetID != item.TargetID || oracleCase.Component != item.Component || oracleCase.AdvisoryID != item.AdvisoryID || oracleCase.Truth != item.Truth || oracleCase.Rationale != item.Rationale || !candidateCitationsMatchOracle(item.Citations, oracleCase.Citations) {
			return false
		}
	}
	return true
}

func candidateCitationsMatchOracle(candidate []ContentReference, oracle []Citation) bool {
	if len(candidate) != len(oracle) {
		return false
	}
	byReference := make(map[string]string, len(oracle))
	for _, citation := range oracle {
		if _, exists := byReference[citation.Reference]; exists {
			return false
		}
		byReference[citation.Reference] = citation.Digest
	}
	for _, citation := range candidate {
		if digest, exists := byReference[citation.Locator]; !exists || digest != citation.Digest {
			return false
		}
	}
	return true
}

func oracleReviewedBy(oracle Oracle, reviewerIdentity string) bool {
	for _, item := range oracle.Cases {
		approved := false
		for _, reviewer := range item.ReviewerIDs {
			if reviewer == reviewerIdentity {
				approved = true
				break
			}
		}
		if !approved {
			return false
		}
	}
	return true
}
