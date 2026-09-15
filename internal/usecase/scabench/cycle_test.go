package scabench

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestCycleLedgerRequiresEveryPlannedSlotAndRetainsRetries(t *testing.T) {
	plan := testCyclePlan(t)
	ledger := testCycleLedger(t, plan)
	if err := ledger.ValidateAgainstPlan(plan); err != nil {
		t.Fatalf("validate complete ledger: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*CycleLedger)
	}{
		{
			name: "missing slot",
			mutate: func(ledger *CycleLedger) {
				ledger.Slots = ledger.Slots[:len(ledger.Slots)-1]
			},
		},
		{
			name: "duplicate slot",
			mutate: func(ledger *CycleLedger) {
				ledger.Slots = append(ledger.Slots, ledger.Slots[0])
			},
		},
		{
			name: "unknown slot",
			mutate: func(ledger *CycleLedger) {
				ledger.Slots[0].TargetID = "unplanned-target"
			},
		},
		{
			name: "final incomplete",
			mutate: func(ledger *CycleLedger) {
				last := len(ledger.Slots[0].Attempts) - 1
				ledger.Slots[0].Attempts[last].Outcome = CycleAttemptRetry
				ledger.Slots[0].Attempts[last].ObservationState = ObservationIncomplete
				ledger.Slots[0].Attempts[last].EvidenceIdentity = nil
			},
		},
		{
			name: "other unsupported cell",
			mutate: func(ledger *CycleLedger) {
				for index := range ledger.Slots {
					if ledger.Slots[index].ExpectedState == ObservationComplete {
						ledger.Slots[index].ExpectedState = ObservationUnsupported
						ledger.Slots[index].ScannerDispatches = 0
						last := len(ledger.Slots[index].Attempts) - 1
						ledger.Slots[index].Attempts[last].ObservationState = ObservationUnsupported
						ledger.Slots[index].Attempts[last].ScannerDispatches = 0
						break
					}
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneCycleLedger(t, ledger)
			test.mutate(&candidate)
			if err := candidate.ValidateAgainstPlan(plan); err == nil {
				t.Fatal("ValidateAgainstPlan succeeded")
			}
		})
	}
}

func TestCycleAttemptAcceptedBindsProtectedBundleToEvidenceRoot(t *testing.T) {
	evidenceIdentity := cycleEvidenceIdentity("target-a", EngineOwned, 'a')
	accepted := CycleAttempt{
		AttemptID:         "accepted-root-binding",
		Sequence:          1,
		Outcome:           CycleAttemptAccepted,
		ObservationState:  ObservationComplete,
		ScannerDispatches: 1,
		ProtectedBundle: ProtectedBundleReference{
			Locator:   "protected://capture/root-binding",
			Digest:    evidenceIdentity.BundleRootDigest,
			Retention: "governed-retention",
		},
		EvidenceIdentity: evidenceIdentity,
	}
	if err := accepted.Validate(); err != nil {
		t.Fatalf("matching accepted attempt validation: %v", err)
	}

	mismatched := accepted
	mismatched.ProtectedBundle.Digest = cycleTestDigest('z')
	if err := mismatched.Validate(); err == nil {
		t.Fatal("accepted attempt allowed a protected bundle digest that differs from its evidence root")
	}

	for _, outcome := range []CycleAttemptOutcome{CycleAttemptFailed, CycleAttemptRetry} {
		t.Run(string(outcome), func(t *testing.T) {
			attempt := accepted
			attempt.Outcome = outcome
			attempt.EvidenceIdentity = nil
			attempt.ProtectedBundle.Digest = cycleTestDigest('z')
			if err := attempt.Validate(); err != nil {
				t.Fatalf("%s attempt validation: %v", outcome, err)
			}
		})
	}
}

func TestFreshCycleRecordsStrictlyRejectScannerFields(t *testing.T) {
	freeze := testSourceFreeze(t)
	candidate := testOracleCandidate(freeze)
	crossCheck := AutomatedCrossCheck{
		SchemaVersion:         CrossCheckSchemaVersion,
		CycleID:               freeze.CycleID,
		OracleCandidateDigest: cycleTestDigest('b'),
		Method:                "automated_scanner_blinded_cross_check",
		InputDigest:           cycleTestDigest('c'),
		ResultDigest:          cycleTestDigest('d'),
		Status:                "passed",
		Cases:                 []CrossCheckCase{{ID: "case-a", Truth: TruthAffected}},
	}
	adjudication := AdjudicationRecord{
		SchemaVersion:         AdjudicationSchemaVersion,
		CycleID:               freeze.CycleID,
		OracleCandidateDigest: cycleTestDigest('b'),
		CrossCheckDigest:      cycleTestDigest('c'),
		ResolutionDigest:      cycleTestDigest('d'),
		Status:                "resolved",
	}
	review := testAccountableReview(freeze.CycleID, cycleTestDigest('a'), cycleTestDigest('f'))

	tests := []struct {
		name   string
		value  any
		decode func(*bytes.Reader) error
	}{
		{name: "oracle candidate", value: candidate, decode: func(reader *bytes.Reader) error { _, err := DecodeOracleCandidate(reader); return err }},
		{name: "cross check", value: crossCheck, decode: func(reader *bytes.Reader) error { _, err := DecodeAutomatedCrossCheck(reader); return err }},
		{name: "adjudication", value: adjudication, decode: func(reader *bytes.Reader) error { _, err := DecodeAdjudicationRecord(reader); return err }},
		{name: "accountable review", value: review, decode: func(reader *bytes.Reader) error { _, err := DecodeAccountableReview(reader); return err }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body, err := json.Marshal(test.value)
			if err != nil {
				t.Fatal(err)
			}
			body = append(bytes.TrimSuffix(body, []byte("}")), []byte(`,"scanner_bundle":"forbidden"}`)...)
			if err := test.decode(bytes.NewReader(body)); err == nil {
				t.Fatal("strict decoder accepted scanner material")
			}
		})
	}
}

func TestTargetIDsRequirePortablePathSegments(t *testing.T) {
	for _, targetID := range []string{"", ".", "..", "target/path", "target\\path", "target path", "target:tag", "tärget"} {
		t.Run(targetID, func(t *testing.T) {
			catalog := validCatalog()
			catalog.Targets[0].ID = targetID
			if err := catalog.Validate(); err == nil {
				t.Fatal("catalog accepted a non-portable target id")
			}
			cell := CycleCell{TargetID: targetID, Engine: EngineOwned, ExpectedState: ObservationComplete, ScannerDispatches: 1}
			if err := cell.Validate(); err == nil {
				t.Fatal("cycle cell accepted a non-portable target id")
			}
		})
	}
	for _, targetID := range []string{"target", "target-1.2_amd64"} {
		t.Run("accept "+targetID, func(t *testing.T) {
			catalog := validCatalog()
			catalog.Targets[0].ID = targetID
			if err := catalog.Validate(); err != nil {
				t.Fatalf("catalog rejected portable target id: %v", err)
			}
		})
	}
}

func TestAccountableReviewRequiresImmutableSanitizedGitHubCapture(t *testing.T) {
	valid := testAccountableReview("review-cycle", cycleTestDigest('a'), cycleTestDigest('b'))
	if err := valid.Validate(); err != nil {
		t.Fatalf("validate complete accountable review: %v", err)
	}
	tests := []struct {
		name string
		edit func(*AccountableReview)
	}{
		{name: "non-github reviewer", edit: func(review *AccountableReview) { review.ReviewerIdentity = "reviewer@example.test" }},
		{name: "invalid submitted time", edit: func(review *AccountableReview) { review.SubmittedAt = "not-a-time" }},
		{name: "unbound commit", edit: func(review *AccountableReview) { review.ReviewedCommit = "not-a-commit" }},
		{name: "unsafe review url", edit: func(review *AccountableReview) {
			review.GitHubReviewURL = "https://github.com/example/repository/pull/1?token=forbidden#pullrequestreview-1"
		}},
		{name: "non-review capture path", edit: func(review *AccountableReview) { review.ReviewCapture.Locator = "sources/review.json" }},
		{name: "decision not capture bound", edit: func(review *AccountableReview) { review.DecisionDigest = cycleTestDigest('c') }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			review := valid
			test.edit(&review)
			if err := review.Validate(); err == nil {
				t.Fatal("accountable review accepted incomplete or mutable GitHub review provenance")
			}
		})
	}
}

func TestGitHubReviewCaptureStrictlySanitizesAndBindsDecisionProvenance(t *testing.T) {
	review := testAccountableReview("review-cycle", cycleTestDigest('a'), cycleTestDigest('b'))
	capture := GitHubReviewCapture{
		SchemaVersion: GitHubReviewCaptureSchemaVersion,
		ID:            review.GitHubReviewID,
		URL:           review.GitHubReviewURL,
		Login:         "reviewer",
		State:         "APPROVED",
		SubmittedAt:   review.SubmittedAt,
		CommitID:      review.ReviewedCommit,
		Body:          "decision: approved",
	}
	body, err := json.Marshal(capture)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeGitHubReviewCapture(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("decode sanitized github review capture: %v", err)
	}
	if err := decoded.ValidateAgainstAccountableReview(review); err != nil {
		t.Fatalf("bind sanitized github review capture: %v", err)
	}

	tests := []struct {
		name string
		body []byte
	}{
		{name: "forbidden header field", body: append(append([]byte(nil), body[:len(body)-1]...), []byte(`,"headers":"forbidden"}`)...)},
		{name: "forbidden token field", body: append(append([]byte(nil), body[:len(body)-1]...), []byte(`,"token":"forbidden"}`)...)},
		{name: "forbidden user field", body: append(append([]byte(nil), body[:len(body)-1]...), []byte(`,"user":"forbidden"}`)...)},
		{name: "email login", body: mustJSON(t, GitHubReviewCapture{SchemaVersion: GitHubReviewCaptureSchemaVersion, ID: "1", URL: review.GitHubReviewURL, Login: "reviewer@example.test", State: "APPROVED", SubmittedAt: review.SubmittedAt, CommitID: review.ReviewedCommit, Body: "decision: approved"})},
		{name: "different decision", body: mustJSON(t, GitHubReviewCapture{SchemaVersion: GitHubReviewCaptureSchemaVersion, ID: "1", URL: review.GitHubReviewURL, Login: "reviewer", State: "CHANGES_REQUESTED", SubmittedAt: review.SubmittedAt, CommitID: review.ReviewedCommit, Body: "decision: rejected"})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate, err := DecodeGitHubReviewCapture(bytes.NewReader(test.body))
			if err == nil {
				err = candidate.ValidateAgainstAccountableReview(review)
			}
			if err == nil {
				t.Fatal("GitHub review capture accepted sensitive or mismatched provenance")
			}
		})
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestPublicationManifestBindsFullRawEvidenceAndApproval(t *testing.T) {
	plan := testCyclePlan(t)
	manifest := testPublicationManifest(t, plan)
	if err := manifest.ValidateAgainstPlan(plan); err != nil {
		t.Fatalf("validate publication manifest: %v", err)
	}
	before, err := DigestPublicationManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Repetitions[0].Bundles[0].RawOutputDigest = cycleTestDigest('e')
	after, err := DigestPublicationManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("publication identity did not change when raw evidence changed")
	}

	manifest = testPublicationManifest(t, plan)
	manifest.AccountableReview.Decision = "unresolved"
	if err := manifest.ValidateAgainstPlan(plan); err == nil {
		t.Fatal("publication accepted an unresolved accountable review")
	}
	manifest = testPublicationManifest(t, plan)
	manifest.Artifacts = append(manifest.Artifacts, PublicationArtifact{Kind: "raw_bundle", Reference: ContentReference{Locator: "evidence/raw.json", Digest: cycleTestDigest('f'), Size: 1}})
	if err := manifest.ValidateAgainstPlan(plan); err == nil {
		t.Fatal("publication accepted a raw bundle")
	}
	manifest = testPublicationManifest(t, plan)
	manifest.Artifacts = append(manifest.Artifacts, PublicationArtifact{Kind: "evidence_summary", Reference: ContentReference{Locator: "publication/candidate-evidence-summary.json", Digest: cycleTestDigest('g'), Size: 1}})
	if err := manifest.ValidateAgainstPlan(plan); err == nil {
		t.Fatal("publication accepted a self-referential candidate evidence summary")
	}
}

func TestCandidateEvidenceSummaryBindsEveryRetainedBundleIdentity(t *testing.T) {
	plan := testCyclePlan(t)
	manifest := testPublicationManifest(t, plan)
	planDigest, err := DigestCyclePlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	ledgerDigest := cycleTestDigest('a')
	publicationDigest, err := DigestPublicationManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	bundleDigest, err := DigestBundleEvidence(manifest.Repetitions)
	if err != nil {
		t.Fatal(err)
	}
	summary, err := NewCandidateEvidenceSummary(plan.CycleID, plan.FinalOracleDigest, planDigest, ledgerDigest, publicationDigest, bundleDigest, cycleTestDigest('b'), cycleTestDigest('c'), cycleTestDigest('d'), cycleTestDigest('e'))
	if err != nil {
		t.Fatal(err)
	}
	before, err := DigestCandidateEvidenceSummary(summary)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Repetitions[0].Bundles[0].ProcessEvidenceDigest = cycleTestDigest('f')
	changedBundleDigest, err := DigestBundleEvidence(manifest.Repetitions)
	if err != nil {
		t.Fatal(err)
	}
	changedPublicationDigest, err := DigestPublicationManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := NewCandidateEvidenceSummary(plan.CycleID, plan.FinalOracleDigest, planDigest, ledgerDigest, changedPublicationDigest, changedBundleDigest, cycleTestDigest('b'), cycleTestDigest('c'), cycleTestDigest('d'), cycleTestDigest('e'))
	if err != nil {
		t.Fatal(err)
	}
	after, err := DigestCandidateEvidenceSummary(changed)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("candidate evidence summary did not change when process/raw evidence identity changed")
	}
}

func TestBuildPublicationManifestBindsWrittenArtifactsWithoutSummarySelfReference(t *testing.T) {
	plan := testCyclePlan(t)
	review := testAccountableReview(plan.CycleID, cycleTestDigest('j'), plan.FinalOracleDigest)
	reviewDigest, err := DigestAccountableReview(review)
	if err != nil {
		t.Fatal(err)
	}
	plan.AccountableReviewDigest = reviewDigest
	ledger := testCycleLedger(t, plan)
	controlKinds := []string{"source_snapshot", "pin", "sbom", "normalized_observation", "native_comparison", "process_identity", "ratchet"}
	control := PublicationControl{SchemaVersion: PublicationControlSchemaVersion, ImplementationCommit: strings.Repeat("a", 40)}
	for index, kind := range controlKinds {
		control.Artifacts = append(control.Artifacts, PublicationArtifact{Kind: kind, Reference: ContentReference{Locator: "publication/" + kind + ".json", Digest: cycleTestDigest(byte('a' + index)), Size: 1}})
	}
	generatedKinds := []string{"source_evidence", "native_evidence", "oracle_candidate", "cross_check", "adjudication", "accountable_review", "oracle_freeze", "comparison", "falsifier_result", "result", "report", "ledger"}
	generated := make([]PublicationArtifact, 0, len(generatedKinds))
	for index, kind := range generatedKinds {
		generated = append(generated, PublicationArtifact{Kind: kind, Reference: ContentReference{Locator: "publication/" + kind + ".json", Digest: cycleTestDigest(byte('l' + index)), Size: 1}})
	}
	manifest, err := BuildPublicationManifest(plan, ledger, review, control, generated)
	if err != nil {
		t.Fatal(err)
	}
	if err := manifest.ValidateAgainstPlan(plan); err != nil {
		t.Fatal(err)
	}
	mismatchedPlan := plan
	mismatchedPlan.AccountableReviewDigest = cycleTestDigest('z')
	mismatchedLedger := testCycleLedger(t, mismatchedPlan)
	if _, err := BuildPublicationManifest(mismatchedPlan, mismatchedLedger, review, control, generated); err == nil {
		t.Fatal("publication accepted an accountable review not bound by the cycle plan")
	}
	body, err := CanonicalJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := DigestPublicationManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if SHA256Digest(body) != digest {
		t.Fatal("written canonical manifest does not match its publication identity")
	}
	for _, artifact := range manifest.Artifacts {
		if artifact.Kind == "evidence_summary" {
			t.Fatal("publication manifest must not include a self-referential candidate evidence summary")
		}
	}
	if _, err := BuildPublicationManifest(plan, ledger, review, control, generated[:len(generated)-1]); err == nil {
		t.Fatal("publication accepted a missing measured artifact")
	}
}

func TestFalsifierSpecUsesExpectedOutcomeInsteadOfStoredPass(t *testing.T) {
	spec := FalsifierSpec{
		SchemaVersion: FalsifierSpecSchemaVersion,
		Entries: []FalsifierEntry{{
			ID:              "owned_baseline_rejected",
			Capability:      "semantic-full-bundle-comparator",
			Engine:          EngineOwned,
			Baseline:        "synthetic-complete-bundle",
			Mutation:        "unexpected-profile-change",
			ExpectedOutcome: "rejected",
			Operation:       "semantic_bundle_comparator",
		}},
	}
	if err := spec.Validate(); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	body = append(bytes.TrimSuffix(body, []byte("}")), []byte(`,"passed":true}`)...)
	if _, err := DecodeFalsifierSpec(bytes.NewReader(body)); err == nil {
		t.Fatal("falsifier spec accepted a stored pass boolean")
	}
}

func testSourceFreeze(t *testing.T) SourceFreeze {
	t.Helper()
	assets := []ContentReference{{Locator: "benchmark/source.json", Digest: cycleTestDigest('a'), Size: 1}}
	digest, err := DigestContentReferences(assets)
	if err != nil {
		t.Fatal(err)
	}
	return SourceFreeze{SchemaVersion: SourceFreezeSchemaVersion, CycleID: "release-cycle", Assets: assets, ContentDigest: digest}
}

func testOracleCandidate(freeze SourceFreeze) OracleCandidate {
	return OracleCandidate{
		SchemaVersion:      OracleCandidateSchemaVersion,
		CycleID:            freeze.CycleID,
		SourceFreezeDigest: cycleTestDigest('a'),
		Cases: []OracleCandidateCase{{
			ID: "case-a", TargetID: "target-a", Component: Component{PURL: "pkg:deb/debian/a@1", Version: "1"}, AdvisoryID: "CVE-2026-0001", Truth: TruthAffected, Rationale: "independent source labels this affected", Citations: []ContentReference{{Locator: "benchmark/citations/case-a.json", Digest: cycleTestDigest('b'), Size: 1}},
		}},
	}
}

func testAccountableReview(cycleID, adjudicationDigest, finalOracleDigest string) AccountableReview {
	capture := ContentReference{Locator: "reviews/github/review-1.json", Digest: cycleTestDigest('b'), Size: 1}
	return AccountableReview{
		SchemaVersion:      AccountableReviewSchemaVersion,
		CycleID:            cycleID,
		AdjudicationDigest: adjudicationDigest,
		FinalOracleDigest:  finalOracleDigest,
		ReviewerIdentity:   "github:reviewer",
		SubmittedAt:        "2026-09-15T12:00:00Z",
		ReviewedCommit:     strings.Repeat("a", 40),
		GitHubReviewID:     "1",
		GitHubReviewURL:    "https://github.com/example/repository/pull/1#pullrequestreview-1",
		ReviewCapture:      capture,
		Decision:           "approved",
		DecisionDigest:     capture.Digest,
	}
}

func testCyclePlan(t *testing.T) CyclePlan {
	t.Helper()
	return CyclePlan{
		SchemaVersion:           CyclePlanSchemaVersion,
		CycleID:                 "release-cycle",
		SourceFreezeDigest:      cycleTestDigest('a'),
		OracleCandidateDigest:   cycleTestDigest('b'),
		CrossCheckDigest:        cycleTestDigest('c'),
		AdjudicationDigest:      cycleTestDigest('d'),
		AccountableReviewDigest: cycleTestDigest('e'),
		FinalOracleDigest:       cycleTestDigest('f'),
		Repetitions:             2,
		Cells: []CycleCell{
			{TargetID: "target-a", Engine: EngineOwned, ExpectedState: ObservationComplete, ScannerDispatches: 1},
			{TargetID: "target-b", Engine: EngineOSVScanner, ExpectedState: ObservationUnsupported, ScannerDispatches: 0},
		},
	}
}

func testCycleLedger(t *testing.T, plan CyclePlan) CycleLedger {
	t.Helper()
	planDigest, err := DigestCyclePlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	ledger := CycleLedger{SchemaVersion: CycleLedgerSchemaVersion, CycleID: plan.CycleID, CyclePlanDigest: planDigest}
	sequence := 0
	for repetition := 1; repetition <= plan.Repetitions; repetition++ {
		for _, cell := range plan.Cells {
			sequence++
			attempts := []CycleAttempt{}
			if repetition == 1 && cell.ExpectedState == ObservationComplete {
				attempts = append(attempts, CycleAttempt{AttemptID: "retry-before-success", Sequence: 1, Outcome: CycleAttemptRetry, ScannerDispatches: 1, ProtectedBundle: protectedCycleBundle('a')})
			}
			evidenceIdentity := cycleEvidenceIdentity(cell.TargetID, cell.Engine, byte('c'+sequence))
			protectedBundle := protectedCycleBundle(byte('b' + sequence))
			protectedBundle.Digest = evidenceIdentity.BundleRootDigest
			attempts = append(attempts, CycleAttempt{
				AttemptID:         "accepted-" + strings.Repeat(string(rune('a'+sequence)), 1),
				Sequence:          len(attempts) + 1,
				Outcome:           CycleAttemptAccepted,
				ObservationState:  cell.ExpectedState,
				ScannerDispatches: cell.ScannerDispatches,
				ProtectedBundle:   protectedBundle,
				EvidenceIdentity:  evidenceIdentity,
			})
			ledger.Slots = append(ledger.Slots, CycleSlot{Repetition: repetition, TargetID: cell.TargetID, Engine: cell.Engine, ExpectedState: cell.ExpectedState, ScannerDispatches: cell.ScannerDispatches, Attempts: attempts})
		}
	}
	return ledger
}

func testPublicationManifest(t *testing.T, plan CyclePlan) PublicationManifest {
	t.Helper()
	planDigest, err := DigestCyclePlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	kinds := []string{"source_snapshot", "pin", "sbom", "source_evidence", "native_evidence", "oracle_candidate", "cross_check", "adjudication", "accountable_review", "oracle_freeze", "normalized_observation", "native_comparison", "process_identity", "comparison", "falsifier_result", "result", "ratchet", "report", "ledger"}
	artifacts := make([]PublicationArtifact, 0, len(kinds))
	for index, kind := range kinds {
		artifacts = append(artifacts, PublicationArtifact{Kind: kind, Reference: ContentReference{Locator: "publication/" + kind + ".json", Digest: cycleTestDigest(byte('a' + index)), Size: 1}})
	}
	manifest := PublicationManifest{
		SchemaVersion:        PublicationManifestSchemaVersion,
		CycleID:              plan.CycleID,
		ImplementationCommit: strings.Repeat("a", 40),
		CyclePlanDigest:      planDigest,
		CycleLedgerDigest:    cycleTestDigest('f'),
		AccountableReview:    testAccountableReview(plan.CycleID, cycleTestDigest('a'), plan.FinalOracleDigest),
		Artifacts:            artifacts,
	}
	for repetition := 1; repetition <= plan.Repetitions; repetition++ {
		record := RepetitionEvidence{Repetition: repetition}
		for _, cell := range plan.Cells {
			record.Bundles = append(record.Bundles, *cycleEvidenceIdentity(cell.TargetID, cell.Engine, byte('c'+repetition)))
		}
		manifest.Repetitions = append(manifest.Repetitions, record)
	}
	return manifest
}

func protectedCycleBundle(marker byte) ProtectedBundleReference {
	return ProtectedBundleReference{Locator: "protected://capture/bundle-" + string(marker), Digest: cycleTestDigest(marker), Retention: "governed-retention"}
}

func cycleEvidenceIdentity(target string, engine Engine, marker byte) *BundleEvidenceIdentity {
	return &BundleEvidenceIdentity{TargetID: target, Engine: engine, BundleManifestDigest: cycleTestDigest(marker), BundleRootDigest: cycleTestDigest(marker + 1), RawOutputDigest: cycleTestDigest(marker + 2), NormalizedObservationDigest: cycleTestDigest(marker + 3), SBOMDigest: cycleTestDigest(marker + 4), NativeComparisonDigest: cycleTestDigest(marker + 5), ProcessEvidenceDigest: cycleTestDigest(marker + 6), EnvironmentDigest: cycleTestDigest(marker + 7)}
}

func cloneCycleLedger(t *testing.T, ledger CycleLedger) CycleLedger {
	t.Helper()
	body, err := json.Marshal(ledger)
	if err != nil {
		t.Fatal(err)
	}
	var copy CycleLedger
	if err := json.Unmarshal(body, &copy); err != nil {
		t.Fatal(err)
	}
	return copy
}

func cycleTestDigest(marker byte) string {
	return fmt.Sprintf("sha256:%064x", marker)
}
