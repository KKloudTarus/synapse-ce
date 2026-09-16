package scabench

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

func TestCaptureCycleCellComposesCapabilityPrepareCaptureWriteAndValidate(t *testing.T) {
	catalog, manifest := capabilityFixture(t)
	repositoryRoot := t.TempDir()
	writeCycleAsset(t, repositoryRoot, "sources/oracle.json", []byte("source"))
	writeCycleAsset(t, repositoryRoot, "citations/case-a.json", []byte("citation"))
	freeze, candidate := freshCycleAssets(t, repositoryRoot)
	gate := approvedCycleGate(t, freeze, candidate)
	plan := gate.plan
	plan.Repetitions = 1
	plan.Cells = []bench.CycleCell{{TargetID: manifest.TargetID, Engine: manifest.Engine, ExpectedState: bench.ObservationUnsupported, ScannerDispatches: 0}}
	output := filepath.Join(t.TempDir(), "bundle")
	capture, err := CaptureCycleCell(context.Background(), CycleCellInput{
		RepositoryRoot:    repositoryRoot,
		SourceFreeze:      freeze,
		OracleCandidate:   candidate,
		CrossCheck:        gate.crossCheck,
		Adjudication:      gate.adjudication,
		AccountableReview: gate.review,
		FinalOracleFreeze: gate.finalOracle,
		Plan:              plan,
		Repetition:        1,
		Catalog:           catalog,
		Manifest:          manifest,
		Output:            output,
		Retention:         bench.ProtectedBundleDestination{Locator: "protected://capture/capability", Retention: "governed-retention"},
		NativeEvidence:    nativeTargetEvidence(manifest.TargetID, digestByte('d'), digestByte('e')),
	})
	if err != nil {
		t.Fatal(err)
	}
	if capture.ObservationState != bench.ObservationUnsupported || capture.ScannerDispatches != 0 || capture.Identity.RootDigest == "" || capture.Bundle.Digest != capture.Identity.RootDigest {
		t.Fatalf("cycle capture = %+v", capture)
	}
	if err := ValidateBundle(output); err != nil {
		t.Fatalf("cycle bundle validation: %v", err)
	}
	ledger, err := BuildCycleLedger(plan, []CycleCellCapture{capture})
	if err != nil || ledger.ValidateAgainstPlan(plan) != nil {
		t.Fatalf("build retained cycle ledger: %+v, %v", ledger, err)
	}
}

func TestCaptureCycleCellRejectsBeforeScannerConstructionWithoutAccountableApproval(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineGrype)
	repositoryRoot := t.TempDir()
	writeCycleAsset(t, repositoryRoot, "sources/oracle.json", []byte("source"))
	writeCycleAsset(t, repositoryRoot, "citations/case-a.json", []byte("citation"))
	freeze, candidate := freshCycleAssets(t, repositoryRoot)
	gate := approvedCycleGate(t, freeze, candidate)
	gate.plan.Repetitions = 1
	gate.plan.Cells = []bench.CycleCell{{TargetID: manifest.TargetID, Engine: manifest.Engine, ExpectedState: bench.ObservationComplete, ScannerDispatches: 1}}
	gate.review.Decision = "rejected"
	runner := &preCaptureGateRunner{}
	_, err := CaptureCycleCell(context.Background(), CycleCellInput{RepositoryRoot: repositoryRoot, SourceFreeze: freeze, OracleCandidate: candidate, CrossCheck: gate.crossCheck, Adjudication: gate.adjudication, AccountableReview: gate.review, FinalOracleFreeze: gate.finalOracle, Plan: gate.plan, Repetition: 1, Catalog: catalog, Manifest: manifest, Output: filepath.Join(t.TempDir(), "bundle"), Retention: bench.ProtectedBundleDestination{Locator: "protected://capture/pre-gate", Retention: "governed-retention"}, Runner: runner})
	if err == nil {
		t.Fatal("capture accepted a missing accountable approval")
	}
	if runner.called {
		t.Fatal("scanner runner was dispatched before the accountable-review gate")
	}
}

func TestCaptureCycleCellRejectsMissingImmutableReviewCaptureBeforeDispatch(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineGrype)
	repositoryRoot := t.TempDir()
	writeCycleAsset(t, repositoryRoot, "sources/oracle.json", []byte("source"))
	writeCycleAsset(t, repositoryRoot, "citations/case-a.json", []byte("citation"))
	freeze, candidate := freshCycleAssets(t, repositoryRoot)
	gate := approvedCycleGate(t, freeze, candidate)
	gate.plan.Repetitions = 1
	gate.plan.Cells = []bench.CycleCell{{TargetID: manifest.TargetID, Engine: manifest.Engine, ExpectedState: bench.ObservationComplete, ScannerDispatches: 1}}
	if err := os.Remove(filepath.Join(repositoryRoot, "reviews", "github", "review-1.json")); err != nil {
		t.Fatal(err)
	}
	runner := &preCaptureGateRunner{}
	_, err := CaptureCycleCell(context.Background(), CycleCellInput{RepositoryRoot: repositoryRoot, SourceFreeze: freeze, OracleCandidate: candidate, CrossCheck: gate.crossCheck, Adjudication: gate.adjudication, AccountableReview: gate.review, FinalOracleFreeze: gate.finalOracle, Plan: gate.plan, Repetition: 1, Catalog: catalog, Manifest: manifest, Output: filepath.Join(t.TempDir(), "bundle"), Retention: bench.ProtectedBundleDestination{Locator: "protected://capture/review-capture", Retention: "governed-retention"}, NativeEvidence: nativeTargetEvidence(manifest.TargetID, digestByte('a'), digestByte('b')), Runner: runner})
	if err == nil {
		t.Fatal("capture accepted a missing immutable accountable review capture")
	}
	if runner.called {
		t.Fatal("scanner runner was dispatched before review-capture verification")
	}
}

func TestVerifyAccountableReviewCaptureRejectsProvenanceMismatches(t *testing.T) {
	root := t.TempDir()
	review := testAccountableReview("fresh-cycle", digestByte('a'), digestByte('b'))
	writeCycleAsset(t, root, review.DecisionCapture.Locator, testGitHubDispositionCapture("approved"))
	tests := []struct {
		name string
		edit func(string) string
	}{
		{name: "id", edit: func(body string) string {
			return strings.Replace(strings.Replace(body, `"id":"1"`, `"id":"2"`, 1), "pullrequestreview-1", "pullrequestreview-2", 1)
		}},
		{name: "url", edit: func(body string) string { return strings.Replace(body, "/pull/1#", "/pull/2#", 1) }},
		{name: "login", edit: func(body string) string {
			return strings.Replace(body, `"login":"reviewer"`, `"login":"another-reviewer"`, 1)
		}},
		{name: "submitted at", edit: func(body string) string {
			return strings.Replace(body, "2026-09-15T12:00:00Z", "2026-09-16T12:00:00Z", 1)
		}},
		{name: "commit", edit: func(body string) string {
			return strings.Replace(body, strings.Repeat("a", 40), strings.Repeat("b", 40), 1)
		}},
		{name: "state and body decision", edit: func(body string) string {
			return strings.Replace(strings.Replace(body, `"state":"APPROVED"`, `"state":"CHANGES_REQUESTED"`, 1), "decision: approved", "decision: rejected", 1)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := []byte(test.edit(string(testGitHubReviewCapture("approved"))))
			writeCycleAsset(t, root, "reviews/github/review-1.json", body)
			mismatched := review
			mismatched.ReviewCapture = bench.ContentReference{Locator: review.ReviewCapture.Locator, Digest: bench.SHA256Digest(body), Size: int64(len(body))}
			if err := VerifyAccountableReviewCapture(root, mismatched); err == nil {
				t.Fatal("immutable review capture accepted provenance fields that differ from the accountable review")
			}
		})
	}
}

func TestFinalizationValidatorsRejectMissingComparisonAndFalsifierCoverage(t *testing.T) {
	_, manifest := capabilityFixture(t)
	repositoryRoot := t.TempDir()
	writeCycleAsset(t, repositoryRoot, "sources/oracle.json", []byte("source"))
	writeCycleAsset(t, repositoryRoot, "citations/case-a.json", []byte("citation"))
	freeze, candidate := freshCycleAssets(t, repositoryRoot)
	gate := approvedCycleGate(t, freeze, candidate)
	plan := gate.plan
	plan.Repetitions = 1
	plan.Cells = []bench.CycleCell{{TargetID: manifest.TargetID, Engine: manifest.Engine, ExpectedState: bench.ObservationUnsupported, ScannerDispatches: 0}}
	if err := validateFinalizationComparisons(plan, nil); err == nil {
		t.Fatal("finalization accepted missing semantic comparisons")
	}
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve falsifier spec path")
	}
	body, err := os.ReadFile(filepath.Join(filepath.Dir(source), "..", "..", "usecase", "scabench", "testdata", "semantic-comparison-falsifiers.json"))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := bench.DecodeFalsifierSpec(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateFinalizationFalsifiers(spec, nil); err == nil {
		t.Fatal("finalization accepted missing falsifier results")
	}
}

func TestBuildCycleLedgerRejectsMissingDuplicateAndUnknownCapturedSlots(t *testing.T) {
	catalog, manifest := capabilityFixture(t)
	repositoryRoot := t.TempDir()
	writeCycleAsset(t, repositoryRoot, "sources/oracle.json", []byte("source"))
	writeCycleAsset(t, repositoryRoot, "citations/case-a.json", []byte("citation"))
	freeze, candidate := freshCycleAssets(t, repositoryRoot)
	gate := approvedCycleGate(t, freeze, candidate)
	plan := gate.plan
	plan.Repetitions = 1
	plan.Cells = []bench.CycleCell{{TargetID: manifest.TargetID, Engine: manifest.Engine, ExpectedState: bench.ObservationUnsupported, ScannerDispatches: 0}}
	captured, err := CaptureCycleCell(context.Background(), CycleCellInput{
		RepositoryRoot: repositoryRoot, SourceFreeze: freeze, OracleCandidate: candidate, CrossCheck: gate.crossCheck,
		Adjudication: gate.adjudication, AccountableReview: gate.review, FinalOracleFreeze: gate.finalOracle,
		Plan: plan, Repetition: 1, Catalog: catalog, Manifest: manifest, Output: filepath.Join(t.TempDir(), "bundle"),
		Retention:      bench.ProtectedBundleDestination{Locator: "protected://capture/ledger", Retention: "governed-retention"},
		NativeEvidence: nativeTargetEvidence(manifest.TargetID, digestByte('b'), digestByte('c')),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildCycleLedger(plan, []CycleCellCapture{captured}); err != nil {
		t.Fatalf("ledger rejected a protected bundle digest bound to the full bundle root: %v", err)
	}
	mismatched := captured
	mismatched.Bundle.Digest = mismatched.Bundle.Digest[:len(mismatched.Bundle.Digest)-1] + "0"
	if mismatched.Bundle.Digest == captured.Bundle.Digest {
		mismatched.Bundle.Digest = mismatched.Bundle.Digest[:len(mismatched.Bundle.Digest)-1] + "1"
	}
	if _, err := BuildCycleLedger(plan, []CycleCellCapture{mismatched}); err == nil {
		t.Fatal("ledger accepted a protected bundle digest that differs from the full bundle root")
	}
	if _, err := BuildCycleLedger(plan, nil); err == nil {
		t.Fatal("ledger accepted missing captured slots")
	}
	unknown := captured
	unknown.TargetID = "unplanned-target"
	unknown.EvidenceIdentity.TargetID = unknown.TargetID
	unknown.NativeEvidence.TargetID = unknown.TargetID
	if _, err := BuildCycleLedger(plan, []CycleCellCapture{unknown}); err == nil {
		t.Fatal("ledger accepted an unknown captured slot")
	}
	duplicatePlan := plan
	duplicatePlan.Cells = append(duplicatePlan.Cells, bench.CycleCell{TargetID: "other-target", Engine: bench.EngineOwned, ExpectedState: bench.ObservationComplete, ScannerDispatches: 1})
	if _, err := BuildCycleLedger(duplicatePlan, []CycleCellCapture{captured, captured}); err == nil {
		t.Fatal("ledger accepted duplicate captured slots")
	}
}

func TestBuildCycleLedgerRetainsIncompleteAttemptBeforeAcceptedRetry(t *testing.T) {
	catalog, manifest := capabilityFixture(t)
	repositoryRoot := t.TempDir()
	writeCycleAsset(t, repositoryRoot, "sources/oracle.json", []byte("source"))
	writeCycleAsset(t, repositoryRoot, "citations/case-a.json", []byte("citation"))
	freeze, candidate := freshCycleAssets(t, repositoryRoot)
	gate := approvedCycleGate(t, freeze, candidate)
	plan := gate.plan
	plan.Repetitions = 1
	plan.Cells = []bench.CycleCell{{TargetID: manifest.TargetID, Engine: manifest.Engine, ExpectedState: bench.ObservationUnsupported, ScannerDispatches: 0}}
	accepted, err := CaptureCycleCell(context.Background(), CycleCellInput{RepositoryRoot: repositoryRoot, SourceFreeze: freeze, OracleCandidate: candidate, CrossCheck: gate.crossCheck, Adjudication: gate.adjudication, AccountableReview: gate.review, FinalOracleFreeze: gate.finalOracle, Plan: plan, Repetition: 1, Catalog: catalog, Manifest: manifest, Output: filepath.Join(t.TempDir(), "accepted-bundle"), Retention: bench.ProtectedBundleDestination{Locator: "protected://capture/retry", Retention: "governed-retention"}, NativeEvidence: nativeTargetEvidence(manifest.TargetID, digestByte('b'), digestByte('c'))})
	if err != nil {
		t.Fatal(err)
	}
	failed := accepted
	failed.Outcome = bench.CycleAttemptFailed
	failed.ObservationState = bench.ObservationIncomplete
	failed.EvidenceIdentity = nil
	failed.Identity.RootDigest = digestByte('f')
	failed.Bundle.Digest = failed.Identity.RootDigest
	ledger, err := BuildCycleLedger(plan, []CycleCellCapture{failed, accepted})
	if err != nil {
		t.Fatal(err)
	}
	attempts := ledger.Slots[0].Attempts
	if len(attempts) != 2 || attempts[0].Outcome != bench.CycleAttemptFailed || attempts[0].EvidenceIdentity != nil || attempts[1].Outcome != bench.CycleAttemptAccepted {
		t.Fatalf("ledger attempts = %+v", attempts)
	}
}

func nativeTargetEvidence(targetID, targetDigest, executionDigest string) bench.NativeTargetEvidence {
	return bench.NativeTargetEvidence{TargetID: targetID, TargetDigest: targetDigest, PackageFamily: "deb", Comparisons: []bench.NativeComparisonRecord{{SchemaVersion: bench.NativeComparisonSchemaVersion, ID: "comparison", TargetID: targetID, TargetDigest: targetDigest, PackageFamily: "deb", PackageIdentity: "binary:fixture", CandidateEVR: "1", FixedEVR: "2", Relation: "before", Method: "target-native-dpkg", ExecutionDigest: executionDigest}}}
}

type preCaptureGateRunner struct{ called bool }

func (runner *preCaptureGateRunner) Run(_ context.Context, _ ports.ToolSpec) (ports.ToolResult, error) {
	runner.called = true
	return ports.ToolResult{}, nil
}

func TestWriteSourceFreezeRecordIsWriteOnce(t *testing.T) {
	assets := []bench.ContentReference{{Locator: "source/a.json", Digest: digestByte('a'), Size: 1}}
	contentDigest, err := bench.DigestContentReferences(assets)
	if err != nil {
		t.Fatal(err)
	}
	freeze := bench.SourceFreeze{SchemaVersion: bench.SourceFreezeSchemaVersion, CycleID: "freeze-cycle", Assets: assets, ContentDigest: contentDigest}
	path := filepath.Join(t.TempDir(), "freeze.json")
	if err := WriteSourceFreezeRecord(path, freeze); err != nil {
		t.Fatal(err)
	}
	if err := WriteSourceFreezeRecord(path, freeze); err == nil {
		t.Fatal("WriteSourceFreezeRecord overwrote an existing freeze")
	}
}

type approvedCaptureGate struct {
	plan         bench.CyclePlan
	crossCheck   bench.AutomatedCrossCheck
	adjudication bench.AdjudicationRecord
	review       bench.AccountableReview
	finalOracle  bench.FinalOracleFreeze
}

func approvedCycleGate(t *testing.T, freeze bench.SourceFreeze, candidate bench.OracleCandidate) approvedCaptureGate {
	t.Helper()
	freezeDigest, err := bench.DigestSourceFreeze(freeze)
	if err != nil {
		t.Fatal(err)
	}
	candidateDigest, err := bench.DigestOracleCandidate(candidate)
	if err != nil {
		t.Fatal(err)
	}
	crossCheck := bench.AutomatedCrossCheck{SchemaVersion: bench.CrossCheckSchemaVersion, CycleID: freeze.CycleID, OracleCandidateDigest: candidateDigest, Method: "automated_scanner_blinded_cross_check", InputDigest: digestByte('a'), ResultDigest: digestByte('b'), Status: "passed", Cases: []bench.CrossCheckCase{{ID: candidate.Cases[0].ID, Truth: candidate.Cases[0].Truth}}}
	crossCheckDigest, err := bench.DigestAutomatedCrossCheck(crossCheck)
	if err != nil {
		t.Fatal(err)
	}
	adjudication := bench.AdjudicationRecord{SchemaVersion: bench.AdjudicationSchemaVersion, CycleID: freeze.CycleID, OracleCandidateDigest: candidateDigest, CrossCheckDigest: crossCheckDigest, ResolutionDigest: digestByte('c'), Status: "resolved"}
	adjudicationDigest, err := bench.DigestAdjudicationRecord(adjudication)
	if err != nil {
		t.Fatal(err)
	}
	review := testAccountableReview(freeze.CycleID, adjudicationDigest, digestByte('e'))
	reviewDigest, err := bench.DigestAccountableReview(review)
	if err != nil {
		t.Fatal(err)
	}
	finalOracle := bench.FinalOracleFreeze{SchemaVersion: bench.FinalOracleFreezeSchemaVersion, CycleID: freeze.CycleID, SourceFreezeDigest: freezeDigest, OracleCandidateDigest: candidateDigest, CrossCheckDigest: crossCheckDigest, AdjudicationDigest: adjudicationDigest, AccountableReviewDigest: reviewDigest, OracleDigest: digestByte('e')}
	plan := bench.CyclePlan{SchemaVersion: bench.CyclePlanSchemaVersion, CycleID: freeze.CycleID, SourceFreezeDigest: freezeDigest, OracleCandidateDigest: candidateDigest, CrossCheckDigest: crossCheckDigest, AdjudicationDigest: adjudicationDigest, AccountableReviewDigest: reviewDigest, FinalOracleDigest: finalOracle.OracleDigest}
	return approvedCaptureGate{plan: plan, crossCheck: crossCheck, adjudication: adjudication, review: review, finalOracle: finalOracle}
}

func testAccountableReview(cycleID, adjudicationDigest, finalOracleDigest string) bench.AccountableReview {
	reviewCaptureBody := testGitHubReviewCapture("approved")
	reviewCapture := bench.ContentReference{Locator: "reviews/github/review-1.json", Digest: bench.SHA256Digest(reviewCaptureBody), Size: int64(len(reviewCaptureBody))}
	decisionCaptureBody := testGitHubDispositionCapture("approved")
	decisionCapture := bench.ContentReference{Locator: "reviews/dispositions/github/decision-1.json", Digest: bench.SHA256Digest(decisionCaptureBody), Size: int64(len(decisionCaptureBody))}
	return bench.AccountableReview{
		SchemaVersion:             bench.AccountableReviewSchemaVersion,
		CycleID:                   cycleID,
		AdjudicationDigest:        adjudicationDigest,
		FinalOracleDigest:         finalOracleDigest,
		ReviewerIdentity:          "github:reviewer",
		SubmittedAt:               "2026-09-15T12:00:00Z",
		ReviewedCommit:            strings.Repeat("a", 40),
		GitHubReviewID:            "1",
		GitHubReviewURL:           "https://github.com/example/repository/pull/1#pullrequestreview-1",
		ReviewCapture:             reviewCapture,
		DecisionAuthorityIdentity: "github:maintainer",
		DecisionSubmittedAt:       "2026-09-15T13:00:00Z",
		ImplementationCommit:      strings.Repeat("b", 40),
		GitHubDispositionID:       "2",
		GitHubDispositionURL:      "https://github.com/example/repository/pull/1#issuecomment-2",
		DecisionCapture:           decisionCapture,
		Decision:                  "approved",
		DecisionDigest:            decisionCapture.Digest,
	}
}
