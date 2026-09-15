package scabench

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestSourceOnlyOraclePipelineBuildsAndAdjudicatesDebianAndRPMCases(t *testing.T) {
	assets := []ContentReference{
		{Locator: "sources/debian-advisory.json", Digest: cycleTestDigest('a'), Size: 1},
		{Locator: "sources/rpm-advisory.json", Digest: cycleTestDigest('b'), Size: 1},
		{Locator: "citations/debian.json", Digest: cycleTestDigest('c'), Size: 1},
		{Locator: "citations/rpm.json", Digest: cycleTestDigest('d'), Size: 1},
	}
	contentDigest, err := DigestContentReferences(assets)
	if err != nil {
		t.Fatal(err)
	}
	freeze := SourceFreeze{SchemaVersion: SourceFreezeSchemaVersion, CycleID: "source-only-cycle", Assets: assets, ContentDigest: contentDigest}
	freezeDigest, err := DigestSourceFreeze(freeze)
	if err != nil {
		t.Fatal(err)
	}
	native := NativeEvidenceSet{SchemaVersion: NativeEvidenceSetSchemaVersion, CycleID: freeze.CycleID, SourceFreezeDigest: freezeDigest, Targets: []NativeTargetEvidence{
		{TargetID: "debian-target", TargetDigest: cycleTestDigest('e'), PackageFamily: "deb", Comparisons: []NativeComparisonRecord{{SchemaVersion: NativeComparisonSchemaVersion, ID: "debian-compare", TargetID: "debian-target", TargetDigest: cycleTestDigest('e'), PackageFamily: "deb", PackageIdentity: "binary:openssl", CandidateEVR: "1.0.0", FixedEVR: "2.0.0", Relation: "before", Method: "target-native-dpkg", ExecutionDigest: cycleTestDigest('f')}}},
		{TargetID: "rpm-target", TargetDigest: cycleTestDigest('g'), PackageFamily: "rpm", Comparisons: []NativeComparisonRecord{{SchemaVersion: NativeComparisonSchemaVersion, ID: "rpm-compare", TargetID: "rpm-target", TargetDigest: cycleTestDigest('g'), PackageFamily: "rpm", PackageIdentity: "binary:openssl", CandidateEVR: "2.0.0", FixedEVR: "2.0.0", Relation: "equal", Method: "target-native-rpm", ExecutionDigest: cycleTestDigest('h')}}},
	}}
	nativeDigest, err := DigestNativeEvidenceSet(native)
	if err != nil {
		t.Fatal(err)
	}
	source := SourceCaseEvidenceSet{SchemaVersion: SourceCaseEvidenceSchemaVersion, CycleID: freeze.CycleID, SourceFreezeDigest: freezeDigest, NativeEvidenceDigest: nativeDigest, Cases: []SourceCaseEvidence{
		{ID: "debian-case", TargetID: "debian-target", Component: Component{PURL: "pkg:deb/debian/openssl@1.0.0", Version: "1.0.0"}, AdvisoryID: "CVE-2026-0001", DerivedTruth: TruthAffected, NativeComparisonIDs: []string{"debian-compare"}, Rationale: "generated vendor source evaluation", Citations: []ContentReference{{Locator: "citations/debian.json", Digest: cycleTestDigest('c'), Size: 1}}},
		{ID: "rpm-case", TargetID: "rpm-target", Component: Component{PURL: "pkg:rpm/suse/openssl@2.0.0", Version: "2.0.0"}, AdvisoryID: "CVE-2026-0002", DerivedTruth: TruthFixed, NativeComparisonIDs: []string{"rpm-compare"}, Rationale: "generated vendor source evaluation", Citations: []ContentReference{{Locator: "citations/rpm.json", Digest: cycleTestDigest('d'), Size: 1}}},
	}}
	candidate, err := BuildOracleCandidate(freeze, source)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Cases[0].Truth != TruthAffected || candidate.Cases[1].Truth != TruthFixed {
		t.Fatalf("candidate truths = %+v", candidate.Cases)
	}
	check, err := BuildAutomatedCrossCheck(source, native, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if check.Status != "passed" || len(check.Cases) != 2 || check.Cases[0].Truth != TruthAffected || check.Cases[1].Truth != TruthFixed {
		t.Fatalf("cross-check = %+v", check)
	}
	adjudication, err := AdjudicateOracleCandidate(candidate, check)
	if err != nil {
		t.Fatal(err)
	}
	if adjudication.Status != "resolved" {
		t.Fatalf("adjudication = %+v", adjudication)
	}
}

func TestAutomatedCrossCheckCarriesNativeNotAffectedTruth(t *testing.T) {
	freeze := testSourceFreeze(t)
	freezeDigest, err := DigestSourceFreeze(freeze)
	if err != nil {
		t.Fatal(err)
	}
	native := NativeEvidenceSet{SchemaVersion: NativeEvidenceSetSchemaVersion, CycleID: freeze.CycleID, SourceFreezeDigest: freezeDigest, Targets: []NativeTargetEvidence{{
		TargetID: "rpm-target", TargetDigest: cycleTestDigest('a'), PackageFamily: "rpm", Comparisons: []NativeComparisonRecord{{
			SchemaVersion: NativeComparisonSchemaVersion, ID: "zero-compare", TargetID: "rpm-target", TargetDigest: cycleTestDigest('a'), PackageFamily: "rpm", PackageIdentity: "binary:pkg", CandidateEVR: "1", FixedEVR: "0", PredicateKind: NativePredicateVersionEqualsZero, Relation: "after", Method: "target-native-rpm", ExecutionDigest: cycleTestDigest('b'),
		}},
	}}}
	nativeDigest, err := DigestNativeEvidenceSet(native)
	if err != nil {
		t.Fatal(err)
	}
	source := SourceCaseEvidenceSet{SchemaVersion: SourceCaseEvidenceSchemaVersion, CycleID: freeze.CycleID, SourceFreezeDigest: freezeDigest, NativeEvidenceDigest: nativeDigest, Cases: []SourceCaseEvidence{{
		ID: "not-affected-case", TargetID: "rpm-target", Component: Component{PURL: "pkg:rpm/suse/pkg@1", Version: "1"}, AdvisoryID: "CVE-2026-0001", DerivedTruth: TruthNotAffected, NativeComparisonIDs: []string{"zero-compare"}, Rationale: "explicit vendor not-affected sentinel", Citations: []ContentReference{{Locator: "benchmark/citation.json", Digest: cycleTestDigest('c'), Size: 1}},
	}}}
	candidate, err := BuildOracleCandidate(freeze, source)
	if err != nil {
		t.Fatal(err)
	}
	check, err := BuildAutomatedCrossCheck(source, native, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if check.Status != "passed" || len(check.Cases) != 1 || check.Cases[0].Truth != TruthNotAffected {
		t.Fatalf("not-affected cross-check = %+v", check)
	}
}

func TestNativeComparisonTruthRejectsZeroSentinelCollision(t *testing.T) {
	comparison := NativeComparisonRecord{
		SchemaVersion:   NativeComparisonSchemaVersion,
		ID:              "zero-compare",
		TargetID:        "rpm-target",
		TargetDigest:    cycleTestDigest('a'),
		PackageFamily:   "rpm",
		PackageIdentity: "binary:pkg",
		CandidateEVR:    "0",
		FixedEVR:        "0",
		PredicateKind:   NativePredicateVersionEqualsZero,
		Relation:        "equal",
		Method:          "target-native-rpm",
		ExecutionDigest: cycleTestDigest('b'),
	}
	truth, err := nativeComparisonTruth([]NativeComparisonRecord{comparison})
	if err == nil {
		t.Fatal("native zero-version collision established truth")
	}
	if truth == TruthNotAffected {
		t.Fatalf("native zero-version collision derived not-affected truth: %q", truth)
	}
}

func TestNativeComparisonRecordDecodesLegacyEVRPredicate(t *testing.T) {
	legacy := NativeComparisonRecord{
		SchemaVersion: NativeComparisonSchemaVersion, ID: "legacy-compare", TargetID: "target-a", TargetDigest: cycleTestDigest('a'), PackageFamily: "deb", PackageIdentity: "binary:pkg", CandidateEVR: "1", FixedEVR: "2", Relation: "before", Method: "target-native-dpkg", ExecutionDigest: cycleTestDigest('b'),
	}
	body, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeNativeComparisonRecord(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.PredicateKind != "" {
		t.Fatalf("legacy predicate kind was rewritten to %q", decoded.PredicateKind)
	}
	truth, err := nativeComparisonTruth([]NativeComparisonRecord{decoded})
	if err != nil {
		t.Fatal(err)
	}
	if truth != TruthAffected {
		t.Fatalf("legacy native truth = %q, want affected", truth)
	}
}

func TestSourceOnlyOraclePipelineFailsClosedForDisagreementAndScannerMaterial(t *testing.T) {
	freeze := testSourceFreeze(t)
	freezeDigest, err := DigestSourceFreeze(freeze)
	if err != nil {
		t.Fatal(err)
	}
	native := NativeEvidenceSet{SchemaVersion: NativeEvidenceSetSchemaVersion, CycleID: freeze.CycleID, SourceFreezeDigest: freezeDigest, Targets: []NativeTargetEvidence{{TargetID: "target-a", TargetDigest: cycleTestDigest('a'), PackageFamily: "deb", Comparisons: []NativeComparisonRecord{{SchemaVersion: NativeComparisonSchemaVersion, ID: "case-a-compare", TargetID: "target-a", TargetDigest: cycleTestDigest('a'), PackageFamily: "deb", PackageIdentity: "binary:a", CandidateEVR: "1", FixedEVR: "2", Relation: "before", Method: "target-native-dpkg", ExecutionDigest: cycleTestDigest('b')}}}}}
	nativeDigest, err := DigestNativeEvidenceSet(native)
	if err != nil {
		t.Fatal(err)
	}
	source := SourceCaseEvidenceSet{SchemaVersion: SourceCaseEvidenceSchemaVersion, CycleID: freeze.CycleID, SourceFreezeDigest: freezeDigest, NativeEvidenceDigest: nativeDigest, Cases: []SourceCaseEvidence{{ID: "case-a", TargetID: "target-a", Component: Component{PURL: "pkg:deb/debian/a@1", Version: "1"}, AdvisoryID: "CVE-2026-0001", DerivedTruth: TruthAffected, NativeComparisonIDs: []string{"case-a-compare"}, Rationale: "generated vendor source evaluation", Citations: []ContentReference{{Locator: "benchmark/citation.json", Digest: cycleTestDigest('b'), Size: 1}}}}}
	candidate, err := BuildOracleCandidate(freeze, source)
	if err != nil {
		t.Fatal(err)
	}
	check, err := BuildAutomatedCrossCheck(source, native, candidate)
	if err != nil {
		t.Fatal(err)
	}
	check.Cases[0].Truth = TruthFixed
	check.Status = "failed"
	adjudication, err := AdjudicateOracleCandidate(candidate, check)
	if err != nil {
		t.Fatal(err)
	}
	if adjudication.Status != "unresolved" {
		t.Fatalf("adjudication = %+v, want unresolved", adjudication)
	}
	body, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	body = append(bytes.TrimSuffix(body, []byte("}")), []byte(`,"scanner_observation":"forbidden"}`)...)
	if _, err := DecodeSourceCaseEvidence(bytes.NewReader(body)); err == nil {
		t.Fatal("source-only evidence decoder accepted scanner material")
	}
}

func TestFreezeFinalOracleRequiresExactReviewedCandidateAndCapturedDecision(t *testing.T) {
	freeze := testSourceFreeze(t)
	freezeDigest, err := DigestSourceFreeze(freeze)
	if err != nil {
		t.Fatal(err)
	}
	candidate := testOracleCandidate(freeze)
	candidate.SourceFreezeDigest = freezeDigest
	candidateDigest, err := DigestOracleCandidate(candidate)
	if err != nil {
		t.Fatal(err)
	}
	crossCheck := AutomatedCrossCheck{
		SchemaVersion:         CrossCheckSchemaVersion,
		CycleID:               freeze.CycleID,
		OracleCandidateDigest: candidateDigest,
		Method:                "automated_scanner_blinded_cross_check",
		InputDigest:           cycleTestDigest('c'),
		ResultDigest:          cycleTestDigest('d'),
		Status:                "passed",
		Cases:                 []CrossCheckCase{{ID: candidate.Cases[0].ID, Truth: candidate.Cases[0].Truth}},
	}
	crossCheckDigest, err := DigestAutomatedCrossCheck(crossCheck)
	if err != nil {
		t.Fatal(err)
	}
	adjudication := AdjudicationRecord{
		SchemaVersion:         AdjudicationSchemaVersion,
		CycleID:               freeze.CycleID,
		OracleCandidateDigest: candidateDigest,
		CrossCheckDigest:      crossCheckDigest,
		ResolutionDigest:      cycleTestDigest('e'),
		Status:                "resolved",
	}
	adjudicationDigest, err := DigestAdjudicationRecord(adjudication)
	if err != nil {
		t.Fatal(err)
	}
	candidateCase := candidate.Cases[0]
	oracle := Oracle{
		SchemaVersion:   OracleSchemaVersion,
		CatalogRevision: "reviewed-source-cycle",
		Cases: []OracleCase{{
			ID: candidateCase.ID, Classification: CaseSynthetic, TargetID: candidateCase.TargetID,
			Component: candidateCase.Component, AdvisoryID: candidateCase.AdvisoryID, Truth: candidateCase.Truth,
			ExpectedCoverage: map[Engine]Coverage{EngineOwned: CoverageCovered, EngineGrype: CoverageCovered, EngineTrivy: CoverageCovered, EngineOSVScanner: CoverageCovered},
			Provenance:       ProvenanceIndependent, ReviewStatus: ReviewApproved,
			LabelerIDs: []string{"github:labeler"}, ReviewerIDs: []string{"github:reviewer"},
			Rationale: candidateCase.Rationale,
			Citations: []Citation{{Reference: candidateCase.Citations[0].Locator, Digest: candidateCase.Citations[0].Digest}},
		}},
	}
	oracleDigest, err := DigestOracle(oracle)
	if err != nil {
		t.Fatal(err)
	}
	review := testAccountableReview(freeze.CycleID, adjudicationDigest, oracleDigest)
	if _, err := FreezeFinalOracle(freeze, candidate, crossCheck, adjudication, review, oracle); err != nil {
		t.Fatalf("freeze valid review-backed oracle: %v", err)
	}

	wrongDigestReview := review
	wrongDigestReview.FinalOracleDigest = cycleTestDigest('f')
	if _, err := FreezeFinalOracle(freeze, candidate, crossCheck, adjudication, wrongDigestReview, oracle); err == nil {
		t.Fatal("freeze accepted a review bound to another final oracle")
	}
	unattributed := oracle
	unattributed.Cases = append([]OracleCase(nil), oracle.Cases...)
	unattributed.Cases[0].ReviewerIDs = []string{"github:other-reviewer"}
	if _, err := FreezeFinalOracle(freeze, candidate, crossCheck, adjudication, review, unattributed); err == nil {
		t.Fatal("freeze accepted a final oracle case without the submitted reviewer")
	}
	changedRationale := oracle
	changedRationale.Cases = append([]OracleCase(nil), oracle.Cases...)
	changedRationale.Cases[0].Rationale = "altered reviewed explanation"
	if _, err := FreezeFinalOracle(freeze, candidate, crossCheck, adjudication, review, changedRationale); err == nil {
		t.Fatal("freeze accepted a final oracle with altered candidate rationale")
	}
	changedCitation := oracle
	changedCitation.Cases = append([]OracleCase(nil), oracle.Cases...)
	changedCitation.Cases[0].Citations = []Citation{{Reference: candidateCase.Citations[0].Locator, Digest: cycleTestDigest('f')}}
	if _, err := FreezeFinalOracle(freeze, candidate, crossCheck, adjudication, review, changedCitation); err == nil {
		t.Fatal("freeze accepted a final oracle with altered candidate citations")
	}
}
