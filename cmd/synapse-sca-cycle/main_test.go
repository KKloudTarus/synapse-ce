package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	capture "github.com/KKloudTarus/synapse-ce/internal/infrastructure/scabench"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

func TestPrepareModeFreezesResolvableScannerFreeInputs(t *testing.T) {
	root := t.TempDir()
	writeCycleFile(t, root, "sources/source.json", []byte("source"))
	writeCycleFile(t, root, "citations/case-a.json", []byte("citation"))
	writeCycleFile(t, root, "reviews/github/review-1.json", testGitHubReviewCapture("approved"))
	writeCycleFile(t, root, "reviews/dispositions/github/decision-1.json", testGitHubDispositionCapture("approved"))
	source := []byte("source")
	citation := []byte("citation")
	assets := []bench.ContentReference{{Locator: "sources/source.json", Digest: bench.SHA256Digest(source), Size: int64(len(source))}}
	contentDigest, err := bench.DigestContentReferences(assets)
	if err != nil {
		t.Fatal(err)
	}
	freeze := bench.SourceFreeze{SchemaVersion: bench.SourceFreezeSchemaVersion, CycleID: "cycle", Assets: assets, ContentDigest: contentDigest}
	freezeDigest, err := bench.DigestSourceFreeze(freeze)
	if err != nil {
		t.Fatal(err)
	}
	candidate := bench.OracleCandidate{SchemaVersion: bench.OracleCandidateSchemaVersion, CycleID: freeze.CycleID, SourceFreezeDigest: freezeDigest, Cases: []bench.OracleCandidateCase{{ID: "case-a", TargetID: "target-a", Component: bench.Component{PURL: "pkg:deb/debian/a@1", Version: "1"}, AdvisoryID: "CVE-2026-0001", Truth: bench.TruthAffected, Rationale: "independent source", Citations: []bench.ContentReference{{Locator: "citations/case-a.json", Digest: bench.SHA256Digest(citation), Size: int64(len(citation))}}}}}
	candidateDigest, err := bench.DigestOracleCandidate(candidate)
	if err != nil {
		t.Fatal(err)
	}
	crossCheck := bench.AutomatedCrossCheck{SchemaVersion: bench.CrossCheckSchemaVersion, CycleID: freeze.CycleID, OracleCandidateDigest: candidateDigest, Method: "automated_scanner_blinded_cross_check", InputDigest: bench.SHA256Digest([]byte("source-input")), ResultDigest: bench.SHA256Digest([]byte("cross-result")), Status: "passed", Cases: []bench.CrossCheckCase{{ID: "case-a", Truth: bench.TruthAffected}}}
	crossCheckDigest, err := bench.DigestAutomatedCrossCheck(crossCheck)
	if err != nil {
		t.Fatal(err)
	}
	adjudication := bench.AdjudicationRecord{SchemaVersion: bench.AdjudicationSchemaVersion, CycleID: freeze.CycleID, OracleCandidateDigest: candidateDigest, CrossCheckDigest: crossCheckDigest, ResolutionDigest: bench.SHA256Digest([]byte("resolution")), Status: "resolved"}
	adjudicationDigest, err := bench.DigestAdjudicationRecord(adjudication)
	if err != nil {
		t.Fatal(err)
	}
	finalOracleDigest := bench.SHA256Digest([]byte("final-oracle"))
	review := testAccountableReview(freeze.CycleID, adjudicationDigest, finalOracleDigest, "approved")
	reviewDigest, err := bench.DigestAccountableReview(review)
	if err != nil {
		t.Fatal(err)
	}
	finalOracle := bench.FinalOracleFreeze{SchemaVersion: bench.FinalOracleFreezeSchemaVersion, CycleID: freeze.CycleID, SourceFreezeDigest: freezeDigest, OracleCandidateDigest: candidateDigest, CrossCheckDigest: crossCheckDigest, AdjudicationDigest: adjudicationDigest, AccountableReviewDigest: reviewDigest, OracleDigest: finalOracleDigest}
	plan := bench.CyclePlan{SchemaVersion: bench.CyclePlanSchemaVersion, CycleID: freeze.CycleID, SourceFreezeDigest: freezeDigest, OracleCandidateDigest: candidateDigest, CrossCheckDigest: crossCheckDigest, AdjudicationDigest: adjudicationDigest, AccountableReviewDigest: reviewDigest, FinalOracleDigest: finalOracle.OracleDigest, Repetitions: 1, Cells: []bench.CycleCell{{TargetID: "target-a", Engine: bench.EngineOwned, ExpectedState: bench.ObservationComplete, ScannerDispatches: 1}}}
	planPath := writeCycleJSON(t, root, "plan.json", plan)
	freezePath := writeCycleJSON(t, root, "freeze.json", freeze)
	candidatePath := writeCycleJSON(t, root, "candidate.json", candidate)
	crossCheckPath := writeCycleJSON(t, root, "cross-check.json", crossCheck)
	adjudicationPath := writeCycleJSON(t, root, "adjudication.json", adjudication)
	reviewPath := writeCycleJSON(t, root, "review.json", review)
	finalOraclePath := writeCycleJSON(t, root, "final-oracle.json", finalOracle)
	var stdout, stderr bytes.Buffer
	if code := executeCLI([]string{"-mode", "prepare", "-repository-root", root, "-plan", planPath, "-source-freeze", freezePath, "-oracle-candidate", candidatePath, "-cross-check", crossCheckPath, "-adjudication", adjudicationPath, "-accountable-review", reviewPath, "-final-oracle-freeze", finalOraclePath}, &stdout, &stderr); code != 0 {
		t.Fatalf("prepare exit = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "cycle inputs prepared") {
		t.Fatalf("prepare stdout = %q", stdout.String())
	}
}

func TestOracleCandidateModeBuildsSourceOnlyCandidateFromResolvableAssets(t *testing.T) {
	root := t.TempDir()
	source := []byte("source")
	citation := []byte("citation")
	writeCycleFile(t, root, "sources/source.json", source)
	writeCycleFile(t, root, "citations/case-a.json", citation)
	assets := []bench.ContentReference{{Locator: "sources/source.json", Digest: bench.SHA256Digest(source), Size: int64(len(source))}}
	contentDigest, err := bench.DigestContentReferences(assets)
	if err != nil {
		t.Fatal(err)
	}
	freeze := bench.SourceFreeze{SchemaVersion: bench.SourceFreezeSchemaVersion, CycleID: "cycle", Assets: assets, ContentDigest: contentDigest}
	freezeDigest, err := bench.DigestSourceFreeze(freeze)
	if err != nil {
		t.Fatal(err)
	}
	native := bench.NativeEvidenceSet{SchemaVersion: bench.NativeEvidenceSetSchemaVersion, CycleID: freeze.CycleID, SourceFreezeDigest: freezeDigest, Targets: []bench.NativeTargetEvidence{{TargetID: "target-a", TargetDigest: bench.SHA256Digest([]byte("target")), PackageFamily: "deb", Comparisons: []bench.NativeComparisonRecord{{SchemaVersion: bench.NativeComparisonSchemaVersion, ID: "case-a-version", TargetID: "target-a", TargetDigest: bench.SHA256Digest([]byte("target")), PackageFamily: "deb", PackageIdentity: "binary:a", CandidateEVR: "1", FixedEVR: "2", Relation: "before", Method: "target-native-dpkg", ExecutionDigest: bench.SHA256Digest([]byte("native"))}}}}}
	nativeDigest, err := bench.DigestNativeEvidenceSet(native)
	if err != nil {
		t.Fatal(err)
	}
	evidence := bench.SourceCaseEvidenceSet{
		SchemaVersion: bench.SourceCaseEvidenceSchemaVersion, CycleID: freeze.CycleID, SourceFreezeDigest: freezeDigest, NativeEvidenceDigest: nativeDigest,
		Cases: []bench.SourceCaseEvidence{{
			ID: "case-a", TargetID: "target-a", Component: bench.Component{PURL: "pkg:deb/debian/a@1", Version: "1"}, AdvisoryID: "CVE-2026-0001", DerivedTruth: bench.TruthAffected, NativeComparisonIDs: []string{"case-a-version"}, Rationale: "generated vendor source evaluation",
			Citations: []bench.ContentReference{{Locator: "citations/case-a.json", Digest: bench.SHA256Digest(citation), Size: int64(len(citation))}},
		}},
	}
	freezePath := writeCycleJSON(t, root, "freeze.json", freeze)
	evidencePath := writeCycleJSON(t, root, "source-evidence.json", evidence)
	outputPath := filepath.Join(root, "candidate.json")
	var stdout, stderr bytes.Buffer
	if code := executeCLI([]string{"-mode", "oracle-candidate", "-repository-root", root, "-source-freeze", freezePath, "-source-case-evidence", evidencePath, "-oracle-output", outputPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("oracle candidate exit = %d, stderr = %q", code, stderr.String())
	}
	candidate, err := decodeOracleCandidate(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidate.Cases) != 1 || candidate.Cases[0].Truth != bench.TruthAffected || !strings.Contains(stdout.String(), "scanner-free oracle stage completed") {
		t.Fatalf("source-only candidate = %+v, stdout = %q", candidate, stdout.String())
	}
}

func TestCellModeRejectsReviewGateBeforeRunnerConstruction(t *testing.T) {
	root := t.TempDir()
	writeCycleFile(t, root, "sources/source.json", []byte("source"))
	writeCycleFile(t, root, "citations/case-a.json", []byte("citation"))
	source := []byte("source")
	citation := []byte("citation")
	assets := []bench.ContentReference{{Locator: "sources/source.json", Digest: bench.SHA256Digest(source), Size: int64(len(source))}}
	contentDigest, err := bench.DigestContentReferences(assets)
	if err != nil {
		t.Fatal(err)
	}
	freeze := bench.SourceFreeze{SchemaVersion: bench.SourceFreezeSchemaVersion, CycleID: "cell-gate", Assets: assets, ContentDigest: contentDigest}
	freezeDigest, err := bench.DigestSourceFreeze(freeze)
	if err != nil {
		t.Fatal(err)
	}
	candidate := bench.OracleCandidate{SchemaVersion: bench.OracleCandidateSchemaVersion, CycleID: freeze.CycleID, SourceFreezeDigest: freezeDigest, Cases: []bench.OracleCandidateCase{{ID: "case-a", TargetID: "target-a", Component: bench.Component{PURL: "pkg:deb/debian/a@1", Version: "1"}, AdvisoryID: "CVE-2026-0001", Truth: bench.TruthAffected, Rationale: "pinned source", Citations: []bench.ContentReference{{Locator: "citations/case-a.json", Digest: bench.SHA256Digest(citation), Size: int64(len(citation))}}}}}
	candidateDigest, err := bench.DigestOracleCandidate(candidate)
	if err != nil {
		t.Fatal(err)
	}
	check := bench.AutomatedCrossCheck{SchemaVersion: bench.CrossCheckSchemaVersion, CycleID: freeze.CycleID, OracleCandidateDigest: candidateDigest, Method: "automated_scanner_blinded_cross_check", InputDigest: bench.SHA256Digest([]byte("input")), ResultDigest: bench.SHA256Digest([]byte("result")), Status: "passed", Cases: []bench.CrossCheckCase{{ID: "case-a", Truth: bench.TruthAffected}}}
	checkDigest, err := bench.DigestAutomatedCrossCheck(check)
	if err != nil {
		t.Fatal(err)
	}
	adjudication := bench.AdjudicationRecord{SchemaVersion: bench.AdjudicationSchemaVersion, CycleID: freeze.CycleID, OracleCandidateDigest: candidateDigest, CrossCheckDigest: checkDigest, ResolutionDigest: bench.SHA256Digest([]byte("resolution")), Status: "resolved"}
	adjudicationDigest, err := bench.DigestAdjudicationRecord(adjudication)
	if err != nil {
		t.Fatal(err)
	}
	finalOracleDigest := bench.SHA256Digest([]byte("final"))
	review := testAccountableReview(freeze.CycleID, adjudicationDigest, finalOracleDigest, "rejected")
	reviewDigest, err := bench.DigestAccountableReview(review)
	if err != nil {
		t.Fatal(err)
	}
	finalOracle := bench.FinalOracleFreeze{SchemaVersion: bench.FinalOracleFreezeSchemaVersion, CycleID: freeze.CycleID, SourceFreezeDigest: freezeDigest, OracleCandidateDigest: candidateDigest, CrossCheckDigest: checkDigest, AdjudicationDigest: adjudicationDigest, AccountableReviewDigest: reviewDigest, OracleDigest: finalOracleDigest}
	plan := bench.CyclePlan{SchemaVersion: bench.CyclePlanSchemaVersion, CycleID: freeze.CycleID, SourceFreezeDigest: freezeDigest, OracleCandidateDigest: candidateDigest, CrossCheckDigest: checkDigest, AdjudicationDigest: adjudicationDigest, AccountableReviewDigest: reviewDigest, FinalOracleDigest: finalOracle.OracleDigest, Repetitions: 1, Cells: []bench.CycleCell{{TargetID: "target-a", Engine: bench.EngineGrype, ExpectedState: bench.ObservationComplete, ScannerDispatches: 1}}}
	planPath := writeCycleJSON(t, root, "plan.json", plan)
	freezePath := writeCycleJSON(t, root, "freeze.json", freeze)
	candidatePath := writeCycleJSON(t, root, "candidate.json", candidate)
	checkPath := writeCycleJSON(t, root, "check.json", check)
	adjudicationPath := writeCycleJSON(t, root, "adjudication.json", adjudication)
	reviewPath := writeCycleJSON(t, root, "review.json", review)
	finalOraclePath := writeCycleJSON(t, root, "final.json", finalOracle)
	constructed := false
	factory := func(capture.RuntimeLimits) (ports.ToolRunner, error) { constructed = true; return nil, nil }
	var stdout, stderr bytes.Buffer
	code := executeCLIWithDeps([]string{"-mode", "cell", "-repository-root", root, "-plan", planPath, "-source-freeze", freezePath, "-oracle-candidate", candidatePath, "-cross-check", checkPath, "-adjudication", adjudicationPath, "-accountable-review", reviewPath, "-final-oracle-freeze", finalOraclePath, "-catalog", "not-read.json", "-capture-manifest", "not-read.json", "-output", filepath.Join(root, "bundle"), "-repetition", "1", "-retention-locator", "protected://capture/cell", "-retention-policy", "governed"}, &stdout, &stderr, factory)
	if code != 1 || constructed {
		t.Fatalf("cell review gate code/runner construction = %d/%t, stderr=%q", code, constructed, stderr.String())
	}
}

func TestContentReferenceForFileHashesOnlyRegularArtifacts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "result.json")
	body := []byte(`{"result":"measured"}`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	reference, err := contentReferenceForFile("publication/result.json", path)
	if err != nil {
		t.Fatal(err)
	}
	want := bench.ContentReference{Locator: "publication/result.json", Digest: bench.SHA256Digest(body), Size: int64(len(body))}
	if reference != want {
		t.Fatalf("reference = %+v, want %+v", reference, want)
	}
	if _, err := contentReferenceForFile("publication/directory", filepath.Dir(path)); err == nil {
		t.Fatal("publication reference accepted a directory")
	}
}

func TestCycleCommandRejectsScannerArgumentsForScannerFreePrepareMode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := executeCLI([]string{"-mode", "prepare", "-observation", "forbidden"}, &stdout, &stderr); code == 0 {
		t.Fatal("prepare accepted scanner observation argument")
	}
}

func TestCycleCellExitCodesSeparateAcceptedRetainedAndPreDispatchOutcomes(t *testing.T) {
	tests := []struct {
		name    string
		outcome bench.CycleAttemptOutcome
		want    int
	}{
		{name: "accepted capture", outcome: bench.CycleAttemptAccepted, want: 0},
		{name: "retained failed attempt", outcome: bench.CycleAttemptFailed, want: 2},
		{name: "pre-dispatch invalid", outcome: "", want: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := cycleCellExitCode(test.outcome); got != test.want {
				t.Fatalf("cycle cell exit code = %d, want %d", got, test.want)
			}
		})
	}
}

func writeCycleFile(t *testing.T, root, relative string, body []byte) string {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeCycleJSON(t *testing.T, root, relative string, value any) string {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return writeCycleFile(t, root, relative, body)
}

func testAccountableReview(cycleID, adjudicationDigest, finalOracleDigest, decision string) bench.AccountableReview {
	reviewCaptureBody := testGitHubReviewCapture(decision)
	reviewCapture := bench.ContentReference{Locator: "reviews/github/review-1.json", Digest: bench.SHA256Digest(reviewCaptureBody), Size: int64(len(reviewCaptureBody))}
	decisionCaptureBody := testGitHubDispositionCapture(decision)
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
		Decision:                  decision,
		DecisionDigest:            decisionCapture.Digest,
	}
}

func testGitHubReviewCapture(decision string) []byte {
	state := "COMMENTED"
	switch decision {
	case "approved":
		state = "APPROVED"
	case "rejected":
		state = "CHANGES_REQUESTED"
	}
	body, err := json.Marshal(bench.GitHubReviewCapture{
		SchemaVersion: bench.GitHubReviewCaptureSchemaVersion,
		ID:            "1",
		URL:           "https://github.com/example/repository/pull/1#pullrequestreview-1",
		Login:         "reviewer",
		State:         state,
		SubmittedAt:   "2026-09-15T12:00:00Z",
		CommitID:      strings.Repeat("a", 40),
		Body:          "decision: " + decision,
	})
	if err != nil {
		panic(err)
	}
	return body
}

func testGitHubDispositionCapture(decision string) []byte {
	reviewedCommit := strings.Repeat("a", 40)
	implementationCommit := strings.Repeat("b", 40)
	body, err := json.Marshal(bench.GitHubReviewDispositionCapture{
		SchemaVersion:        bench.GitHubReviewDispositionCaptureSchemaVersion,
		ID:                   "2",
		URL:                  "https://github.com/example/repository/pull/1#issuecomment-2",
		Login:                "maintainer",
		CreatedAt:            "2026-09-15T13:00:00Z",
		UpdatedAt:            "2026-09-15T13:00:00Z",
		ReviewID:             "1",
		ReviewedCommit:       reviewedCommit,
		ImplementationCommit: implementationCommit,
		Decision:             decision,
		Body:                 bench.CanonicalReviewDispositionBody(decision, "1", reviewedCommit, implementationCommit),
	})
	if err != nil {
		panic(err)
	}
	return body
}
