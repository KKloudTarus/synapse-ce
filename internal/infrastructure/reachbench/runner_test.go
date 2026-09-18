package reachbench

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/benchcycle"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
	measurement "github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
)

type captureFunc func(context.Context, CaptureRequest) (CaptureResult, error)

func (capture captureFunc) Capture(ctx context.Context, request CaptureRequest) (CaptureResult, error) {
	return capture(ctx, request)
}

func TestRunnerRejectsCLIArguments(t *testing.T) {
	runner, err := NewRunner(testDependencies(t.TempDir(), t.TempDir(), map[string]string{}), captureFunc(validCapture(nil)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(context.Background(), []string{"--output", "outside"}); err == nil || !strings.Contains(err.Error(), "accepts no flags") {
		t.Fatalf("Run accepted caller-supplied arguments: %v", err)
	}
}

func TestRunDerivesHarnessCommitTreeAndCIKey(t *testing.T) {
	fixture := newFixture(t)
	calls := make([][]string, 0, 3)
	dependencies := fixture.dependencies(map[string]string{"GITHUB_RUN_ID": "42", "GITHUB_RUN_ATTEMPT": "3"})
	original := dependencies.Command
	dependencies.Command = func(ctx context.Context, binary string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{binary}, args...))
		return original(ctx, binary, args...)
	}
	runner, err := NewRunner(dependencies, captureFunc(validCapture(fixture.expected)))
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.RunKey != "github-42/attempt-3" {
		t.Fatalf("run key = %q", result.RunKey)
	}
	if result.Authoritative || result.Manifest.Route != RouteLocalDiagnostic || result.Manifest.FinalMode != FinalDiagnostic {
		t.Fatalf("run without a controller envelope was authoritative: %+v", result.Manifest)
	}
	want := [][]string{{"git", "rev-parse", "--show-toplevel"}, {"git", "rev-parse", "HEAD"}, {"git", "rev-parse", "HEAD^{tree}"}}
	if fmt.Sprint(calls) != fmt.Sprint(want) {
		t.Fatalf("git argv = %#v, want %#v", calls, want)
	}
	if result.Manifest.Harness != fixture.harness {
		t.Fatalf("manifest harness = %+v, want %+v", result.Manifest.Harness, fixture.harness)
	}
	if result.Manifest.Analyzer.Commit != fixture.harness.Commit || result.Manifest.Analyzer.Tree != fixture.harness.Tree {
		t.Fatalf("local analyzer did not derive from harness checkout: %+v", result.Manifest.Analyzer)
	}
	var report measurement.MeasurementReport
	if _, err := readCanonicalJSON(filepath.Join(result.Output, "repetition-1", "report.json"), &report); err != nil {
		t.Fatal(err)
	}
	if !report.Candidate.Evaluated || report.Candidate.Accepted {
		t.Fatalf("local diagnostic report must remain publishable when candidate acceptance fails: %+v", report.Candidate)
	}
}

func TestEnvelopeRoutesRejectDowngradesAndConflatedIdentities(t *testing.T) {
	fixture := newFixture(t)
	baseline := fixture.envelope(RouteProtectedBaseline, measurement.BaselineMeasurement, FinalBaseline, fixture.baselineAnalyzer, fixture.baseline.ActiveSnapshot)
	if err := baseline.Validate(); err != nil {
		t.Fatalf("baseline envelope rejected: %v", err)
	}
	baseline.Analyzer = RevisionIdentity{ID: AnalyzerSubjectID, Commit: fixture.harness.Commit, Tree: fixture.harness.Tree}
	if err := baseline.Validate(); err == nil {
		t.Fatal("protected baseline accepted a non-trusted analyzer revision")
	}
	candidate := fixture.envelope(RouteCandidate, measurement.CandidateAcceptance, FinalAcceptance, fixture.candidateAnalyzer, fixture.candidate.ActiveSnapshot)
	candidate.Purpose = measurement.BaselineMeasurement
	if err := candidate.Validate(); err == nil {
		t.Fatal("candidate route downgraded to baseline measurement")
	}
	candidate = fixture.envelope(RouteCandidate, measurement.CandidateAcceptance, FinalAcceptance, fixture.candidateAnalyzer, fixture.candidate.ActiveSnapshot)
	candidate.Authority.Class = "controller_reviewed"
	if err := candidate.Validate(); err == nil {
		t.Fatal("non-procedural authority class was accepted")
	}
	candidate = fixture.envelope(RouteCandidate, measurement.CandidateAcceptance, FinalAcceptance, fixture.candidateAnalyzer, fixture.candidate.ActiveSnapshot)
	candidate.Authority.GitHubOriginAuthenticated = true
	if err := candidate.Validate(); err == nil {
		t.Fatal("GitHub origin authentication was accepted as lifecycle authority")
	}
	candidate = fixture.envelope(RouteCandidate, measurement.CandidateAcceptance, FinalAcceptance, fixture.candidateAnalyzer, fixture.candidate.ActiveSnapshot)
	candidate.Authority.ReviewEvidence = measurement.ArtifactReference{}
	if err := candidate.Validate(); err == nil {
		t.Fatal("unbound review evidence was accepted")
	}
	runner, err := NewRunner(fixture.dependencies(map[string]string{}), captureFunc(validCapture(fixture.expected)))
	if err != nil {
		t.Fatal(err)
	}
	candidate = fixture.envelope(RouteCandidate, measurement.CandidateAcceptance, FinalAcceptance, fixture.candidateAnalyzer, fixture.candidate.ActiveSnapshot)
	if err := runner.validateAuthoritativeEnvelope(context.Background(), candidate, fixture.facts("local/fixed"), fixture.controllerBundleRef); err != nil {
		t.Fatalf("candidate analyzer revision matching the runtime harness was rejected: %v", err)
	}
	candidate.Analyzer.Commit = strings.Repeat("3", 40)
	if err := runner.validateAuthoritativeEnvelope(context.Background(), candidate, fixture.facts("local/fixed"), fixture.controllerBundleRef); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("candidate analyzer with an unrelated commit was accepted: %v", err)
	}
	candidate = fixture.envelope(RouteCandidate, measurement.CandidateAcceptance, FinalAcceptance, fixture.candidateAnalyzer, fixture.candidate.ActiveSnapshot)
	candidate.Analyzer.Tree = strings.Repeat("4", 40)
	if err := runner.validateAuthoritativeEnvelope(context.Background(), candidate, fixture.facts("local/fixed"), fixture.controllerBundleRef); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("candidate analyzer with an unrelated tree was accepted: %v", err)
	}
	candidate = fixture.envelope(RouteCandidate, measurement.CandidateAcceptance, FinalAcceptance, fixture.candidateAnalyzer, fixture.candidate.ActiveSnapshot)
	candidate.Harness.ID = candidate.Analyzer.ID
	if err := runner.validateAuthoritativeEnvelope(context.Background(), candidate, fixture.facts("local/fixed"), fixture.controllerBundleRef); err == nil {
		t.Fatal("harness and analyzer identities were conflated")
	}
}

func TestControllerEnvelopeAndBundleSubstitutionFailClosed(t *testing.T) {
	fixture := newFixture(t)
	if err := os.MkdirAll(filepath.Join(fixture.tempRoot, filepath.FromSlash(controllerEnvelopeDirectory)), 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "candidate-envelope.json")
	writeCanonicalTestFile(t, outside, fixture.envelope(RouteCandidate, measurement.CandidateAcceptance, FinalAcceptance, fixture.candidateAnalyzer, fixture.candidate.ActiveSnapshot))
	dependencies := fixture.dependencies(map[string]string{ControllerEnvelopeEnvironment: outside})
	runner, err := NewRunner(dependencies, captureFunc(validCapture(fixture.expected)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "trusted regular file") {
		t.Fatalf("candidate-controlled envelope path was accepted: %v", err)
	}

	fixture = newFixture(t)
	envelopePath := fixture.writeEnvelope(t, fixture.envelope(RouteCandidate, measurement.CandidateAcceptance, FinalAcceptance, fixture.candidateAnalyzer, fixture.candidate.ActiveSnapshot))
	candidatePath := filepath.Join(fixture.controllerBundleRoot, "candidate-input.json")
	body, err := os.ReadFile(candidatePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(candidatePath, append(body, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	dependencies = fixture.dependencies(map[string]string{ControllerEnvelopeEnvironment: envelopePath})
	runner, err = NewRunner(dependencies, captureFunc(validCapture(fixture.expected)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "not canonical") {
		t.Fatalf("mutated controller bundle input was accepted: %v", err)
	}
}

func TestAuthoritativeRunIgnoresCheckoutBundleMutation(t *testing.T) {
	fixture := newFixture(t)
	envelopePath := fixture.writeEnvelope(t, fixture.envelope(RouteCandidate, measurement.CandidateAcceptance, FinalAcceptance, fixture.candidateAnalyzer, fixture.candidate.ActiveSnapshot))
	checkoutCandidate := filepath.Join(fixture.checkoutBundleRoot, "candidate-input.json")
	if err := os.WriteFile(checkoutCandidate, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner, err := NewRunner(fixture.dependencies(map[string]string{ControllerEnvelopeEnvironment: envelopePath}), captureFunc(validCapture(fixture.expected)))
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(context.Background(), nil)
	if !errors.Is(err, errAuthoritativeCandidateRejected) {
		t.Fatalf("authoritative route consulted mutated checkout bundle: %v", err)
	}
	if !result.Authoritative || result.Manifest.Bundle != fixture.controllerBundleRef {
		t.Fatalf("authoritative bundle identity = %+v, want controller bundle %+v", result.Manifest.Bundle, fixture.controllerBundleRef)
	}
}

func TestEnumerateCellsRequiresEveryEnabledBenchmarkBinding(t *testing.T) {
	fixture := newFixture(t)
	cells, err := enumerateCells(fixture.candidate)
	if err != nil {
		t.Fatal(err)
	}
	if len(cells) != 95 {
		t.Fatalf("cells = %d, want 95", len(cells))
	}
	captures := make([]CaptureResult, len(cells))
	for index, cell := range cells {
		captures[index], err = validCapture(fixture.expected)(context.Background(), CaptureRequest{Cell: cell})
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := materializeInput(fixture.candidate, cells[:len(cells)-1], captures); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing capture did not fail: %v", err)
	}
	duplicateCells := append(append([]ExecutionCell(nil), cells...), cells[0])
	duplicateCaptures := append(append([]CaptureResult(nil), captures...), captures[0])
	if _, err := materializeInput(fixture.candidate, duplicateCells, duplicateCaptures); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate capture did not fail: %v", err)
	}
	outOfOrder := append([]CaptureResult(nil), captures...)
	for left, right := 0, len(outOfOrder)-1; left < right; left, right = left+1, right-1 {
		outOfOrder[left], outOfOrder[right] = outOfOrder[right], outOfOrder[left]
	}
	input, err := materializeInput(fixture.candidate, cells, outOfOrder)
	if err != nil {
		t.Fatalf("materialize keyed captures: %v", err)
	}
	for index, observation := range input.Observations {
		if observation.CaseID != cells[index].CaseID || observation.BindingID != cells[index].BindingID {
			t.Fatalf("observation %d = %s/%s, want plan cell %s/%s", index, observation.CaseID, observation.BindingID, cells[index].CaseID, cells[index].BindingID)
		}
	}
}

func TestRunRejectsTwoRunSemanticMismatch(t *testing.T) {
	fixture := newFixture(t)
	runner, err := NewRunner(fixture.dependencies(map[string]string{}), captureFunc(func(_ context.Context, request CaptureRequest) (CaptureResult, error) {
		result, err := validCapture(fixture.expected)(context.Background(), request)
		if request.Repetition == 2 && request.Cell.CaseID == fixture.candidate.Corpus.Cases[0].ID {
			if fixture.expected[request.Cell.CaseID] == measurement.OutcomeReachable {
				result.Observation.Outcome = measurement.OutcomeNoAnalysis
			} else {
				result.Observation.Outcome = measurement.OutcomeReachable
			}
		}
		return result, err
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "semantic repeat mismatch") {
		t.Fatalf("semantic mismatch did not block the lifecycle: %v", err)
	}
}

func TestCleanupFailureBlocksPublication(t *testing.T) {
	fixture := newFixture(t)
	dependencies := fixture.dependencies(map[string]string{})
	dependencies.RuntimeCleanup = func(context.Context) error { return errors.New("cleaner failed") }
	runner, err := NewRunner(dependencies, captureFunc(validCapture(fixture.expected)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "cleaner failed") {
		t.Fatalf("cleanup failure did not fail publication: %v", err)
	}
	output := filepath.Join(fixture.tempRoot, filepath.FromSlash(publishedRunDirectory), "local", "fixed")
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("cleanup failure published %q: %v", output, err)
	}
}

func TestRunCancellationCleansPrivateStateAndPublishesNothing(t *testing.T) {
	fixture := newFixture(t)
	dependencies := fixture.dependencies(map[string]string{})
	cleanupCalls := 0
	dependencies.RuntimeCleanup = func(ctx context.Context) error {
		cleanupCalls++
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("cleanup inherited capture cancellation: %w", err)
		}
		return nil
	}
	entered := make(chan struct{})
	runner, err := NewRunner(dependencies, captureFunc(func(ctx context.Context, _ CaptureRequest) (CaptureResult, error) {
		close(entered)
		<-ctx.Done()
		return CaptureResult{}, ctx.Err()
	}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := runner.Run(ctx, nil)
		done <- err
	}()
	<-entered
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context cancellation", err)
	}
	if cleanupCalls != 1 {
		t.Fatalf("runtime cleanup calls = %d, want 1", cleanupCalls)
	}
	privateRun := filepath.Join(fixture.tempRoot, filepath.FromSlash(privateRunDirectory), "local", "fixed")
	if _, err := os.Lstat(privateRun); !os.IsNotExist(err) {
		t.Fatalf("private run remains after cancellation: %v", err)
	}
	output := filepath.Join(fixture.tempRoot, filepath.FromSlash(publishedRunDirectory), "local", "fixed")
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("output exists after cancellation: %v", err)
	}
}

func TestReachabilityEvidenceLimitsBoundTwoPassWorkload(t *testing.T) {
	limits := reachabilityEvidenceLimits()
	if limits.MaxFiles != maxCells*fixedRepetitions {
		t.Fatalf("evidence file limit = %d, want %d", limits.MaxFiles, maxCells*fixedRepetitions)
	}
	unboundedWorkload := int64(maxCells*fixedRepetitions) * limits.MaxArtifactBytes
	if limits.MaxTotalBytes >= unboundedWorkload || limits.MaxTotalBytes >= 20<<30 {
		t.Fatalf("aggregate evidence limit = %d permits the prior unbounded two-pass retention", limits.MaxTotalBytes)
	}
	if limits.MaxTotalBytes < limits.MaxArtifactBytes {
		t.Fatalf("aggregate evidence limit = %d cannot hold one artifact", limits.MaxTotalBytes)
	}
}

func TestPublicationCollisionBlocksOverwrite(t *testing.T) {
	fixture := newFixture(t)
	output := filepath.Join(fixture.tempRoot, filepath.FromSlash(publishedRunDirectory), "local", "fixed")
	if err := os.MkdirAll(output, 0o700); err != nil {
		t.Fatal(err)
	}
	runner, err := NewRunner(fixture.dependencies(map[string]string{}), captureFunc(validCapture(fixture.expected)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("publication collision did not block overwrite: %v", err)
	}
}

func TestCleanupWorkspaceAfterBeginPublicationFailure(t *testing.T) {
	fixture := newFixture(t)
	facts := fixture.facts("local/fixed")
	facts.output = filepath.Join(facts.outputRoot, "local", "fixed")
	if err := os.MkdirAll(facts.rawRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	workspace, err := benchcycle.PrepareWorkspace(facts.rawRoot, facts.runKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(workspace.RawRunRoot(), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := benchcycle.NewEvidenceStore(workspace.RawRunRoot(), reachabilityEvidenceLimits()); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(facts.output, 0o700); err != nil {
		t.Fatal(err)
	}
	_, beginErr := benchcycle.BeginPublication(
		facts.output,
		reachabilityPublicationLimits(),
		func(context.Context) error { return nil },
		func(context.Context, string, []benchcycle.FileIdentity) error { return nil },
	)
	if beginErr == nil || !strings.Contains(beginErr.Error(), "already exists") {
		t.Fatalf("begin publication error = %v, want destination collision", beginErr)
	}

	cleanupFailure := errors.New("early cleaner failed")
	cleanupCalls := 0
	dependencies := fixture.dependencies(map[string]string{})
	dependencies.RuntimeCleanup = func(ctx context.Context) error {
		cleanupCalls++
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("early cleanup received canceled context: %w", err)
		}
		deadline, hasDeadline := ctx.Deadline()
		if !hasDeadline {
			return errors.New("early cleanup context has no deadline")
		}
		if remaining := time.Until(deadline); remaining <= 0 || remaining > reachabilityCleanupTimeout {
			return fmt.Errorf("early cleanup deadline remaining = %s, want live duration no greater than %s", remaining, reachabilityCleanupTimeout)
		}
		return cleanupFailure
	}
	runner, err := NewRunner(dependencies, captureFunc(validCapture(fixture.expected)))
	if err != nil {
		t.Fatal(err)
	}
	failure := fmt.Errorf("begin reachability publication: %w", beginErr)
	err = runner.cleanupWorkspaceAfterFailure(workspace, failure)
	if !errors.Is(err, beginErr) {
		t.Fatalf("begin publication failure was discarded: %v", err)
	}
	if !errors.Is(err, cleanupFailure) {
		t.Fatalf("early cleanup error was discarded: %v", err)
	}
	if cleanupCalls != 1 {
		t.Fatalf("runtime cleanup calls = %d, want 1", cleanupCalls)
	}
	for _, path := range []string{workspace.RawRunRoot(), workspace.WorkRoot()} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("private workspace path %q remains after publication setup failure: %v", path, err)
		}
	}
}

func TestRunPublishesOnlySanitizedDigestBoundArtifactsAndReplays(t *testing.T) {
	fixture := newFixture(t)
	privateRaw := []byte("controller-private-raw-evidence")
	runner, err := NewRunner(fixture.dependencies(map[string]string{}), captureFunc(func(ctx context.Context, request CaptureRequest) (CaptureResult, error) {
		result, err := validCapture(fixture.expected)(ctx, request)
		if err != nil {
			return CaptureResult{}, err
		}
		receipt, err := request.StoreRawEvidence(ctx, bytes.NewReader(privateRaw))
		if err != nil {
			return CaptureResult{}, err
		}
		result.EvidenceReceipts = []benchcycle.EvidenceReceipt{receipt}
		return result, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Authoritative || result.Manifest.Route != RouteLocalDiagnostic {
		t.Fatalf("local run manifest = %+v", result.Manifest)
	}
	privateRun := filepath.Join(fixture.tempRoot, filepath.FromSlash(privateRunDirectory), "local", "fixed")
	if _, err := os.Lstat(privateRun); !os.IsNotExist(err) {
		t.Fatalf("raw evidence remains after publication: %v", err)
	}
	files, err := regularRelativeFiles(context.Background(), result.Output)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"artifact-manifest.json", "lifecycle-manifest.json", "semantic-repeat.json",
		"repetition-1/corpus.json", "repetition-1/exceptions.json", "repetition-1/input.json", "repetition-1/inventory.json", "repetition-1/oracle.json", "repetition-1/policy.json", "repetition-1/report.json",
		"repetition-2/corpus.json", "repetition-2/exceptions.json", "repetition-2/input.json", "repetition-2/inventory.json", "repetition-2/oracle.json", "repetition-2/policy.json", "repetition-2/report.json",
	}
	sort.Strings(want)
	if fmt.Sprint(files) != fmt.Sprint(want) {
		t.Fatalf("sanitized files = %#v, want %#v", files, want)
	}
	for _, name := range files {
		body, err := os.ReadFile(filepath.Join(result.Output, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(body, privateRaw) || bytes.Contains(body, []byte(fixture.tempRoot)) || bytes.Contains(body, []byte(fixture.repositoryRoot)) {
			t.Fatalf("sanitized artifact %q leaked raw evidence or private path", name)
		}
	}
	facts := fixture.facts("local/fixed")
	if err := replaySanitizedBundle(context.Background(), result.Output, result.Manifest, SemanticRepeatResult{SchemaVersion: RepeatSchemaVersion, Repetitions: fixedRepetitions, SemanticallyEqual: true, ReportIDs: result.Manifest.ReportIDs, Cells: repeatCells(t, result.Output)}, facts); err != nil {
		t.Fatalf("replay published bundle: %v", err)
	}
	if err := os.WriteFile(filepath.Join(result.Output, "repetition-1", "report.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := replaySanitizedBundle(context.Background(), result.Output, result.Manifest, SemanticRepeatResult{}, facts); err == nil {
		t.Fatal("replay accepted a digest-tampered report")
	}
}

func TestAuthoritativeCandidateRejectionPublishesSanitizedEvidence(t *testing.T) {
	fixture := newFixture(t)
	envelope := fixture.envelope(RouteCandidate, measurement.CandidateAcceptance, FinalAcceptance, fixture.candidateAnalyzer, fixture.candidate.ActiveSnapshot)
	envelopePath := fixture.writeEnvelope(t, envelope)
	captures := 0
	runner, err := NewRunner(fixture.dependencies(map[string]string{ControllerEnvelopeEnvironment: envelopePath}), captureFunc(func(ctx context.Context, request CaptureRequest) (CaptureResult, error) {
		captures++
		if request.Analyzer != fixture.candidateAnalyzer || request.Analyzer.ID == fixture.harness.ID || request.Analyzer.Commit != fixture.harness.Commit || request.Analyzer.Tree != fixture.harness.Tree {
			return CaptureResult{}, fmt.Errorf("capture received incorrect candidate analyzer %+v", request.Analyzer)
		}
		return validCapture(fixture.expected)(ctx, request)
	}))
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(context.Background(), nil)
	if !errors.Is(err, errAuthoritativeCandidateRejected) {
		t.Fatalf("candidate rejection error = %v, want %v", err, errAuthoritativeCandidateRejected)
	}
	if !result.Authoritative || result.Manifest.Route != RouteCandidate || result.Manifest.FinalMode != FinalAcceptance {
		t.Fatalf("candidate controller run = %+v", result.Manifest)
	}
	if captures != fixedRepetitions*len(result.Manifest.Cells) {
		t.Fatalf("captures = %d", captures)
	}
	if result.Manifest.Analyzer.ID == result.Manifest.Harness.ID || result.Manifest.Analyzer.Commit != result.Manifest.Harness.Commit || result.Manifest.Analyzer.Tree != result.Manifest.Harness.Tree {
		t.Fatalf("candidate lifecycle identity did not preserve separate subjects at the checkout revision: %+v", result.Manifest)
	}
	if err := result.Manifest.Validate(); err != nil {
		t.Fatalf("candidate lifecycle manifest rejected matching analyzer revision: %v", err)
	}
	wrongCommit := result.Manifest
	wrongCommit.Analyzer.Commit = strings.Repeat("3", 40)
	if err := wrongCommit.Validate(); err == nil {
		t.Fatal("candidate lifecycle manifest accepted an unrelated analyzer commit")
	}
	wrongTree := result.Manifest
	wrongTree.Analyzer.Tree = strings.Repeat("4", 40)
	if err := wrongTree.Validate(); err == nil {
		t.Fatal("candidate lifecycle manifest accepted an unrelated analyzer tree")
	}
	if result.Manifest.Authority != envelope.Authority {
		t.Fatalf("published authority = %+v, want %+v", result.Manifest.Authority, envelope.Authority)
	}
	if err := replaySanitizedBundle(context.Background(), result.Output, result.Manifest, SemanticRepeatResult{SchemaVersion: RepeatSchemaVersion, Repetitions: fixedRepetitions, SemanticallyEqual: true, ReportIDs: result.Manifest.ReportIDs, Cells: repeatCells(t, result.Output)}, fixture.facts("local/fixed")); err != nil {
		t.Fatalf("replay rejected the published candidate evidence: %v", err)
	}
	published, err := os.ReadFile(filepath.Join(result.Output, "lifecycle-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(published, []byte("\"class\":\"procedural\"")) || !bytes.Contains(published, []byte("\"reviewed_harness\":true")) || !bytes.Contains(published, []byte("\"reviewed_harness_id\":\""+ReviewedHarnessID+"\"")) {
		t.Fatalf("publication omitted procedural authority: %s", published)
	}
	var report measurement.MeasurementReport
	if _, err := readCanonicalJSON(filepath.Join(result.Output, "repetition-1", "report.json"), &report); err != nil {
		t.Fatal(err)
	}
	if !report.Candidate.Evaluated || report.Candidate.Accepted || len(report.Candidate.Reasons) == 0 {
		t.Fatalf("published candidate rejection evidence = %+v", report.Candidate)
	}
	var persisted LifecycleManifest
	if _, err := readCanonicalJSON(filepath.Join(result.Output, "lifecycle-manifest.json"), &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Authority.ReviewEvidence != envelope.Authority.ReviewEvidence {
		t.Fatalf("published review evidence = %+v, want %+v", persisted.Authority.ReviewEvidence, envelope.Authority.ReviewEvidence)
	}
}

func TestProtectedBaselineAllowsReviewedAdditionsModificationsAndPackageLocalAdapter(t *testing.T) {
	fixture := newFixture(t)
	envelope := fixture.envelope(RouteProtectedBaseline, measurement.BaselineMeasurement, FinalBaseline, fixture.baselineAnalyzer, fixture.baseline.ActiveSnapshot)
	envelopePath := fixture.writeEnvelope(t, envelope)
	runner, err := NewRunner(fixture.dependencies(map[string]string{ControllerEnvelopeEnvironment: envelopePath}), captureFunc(func(ctx context.Context, request CaptureRequest) (CaptureResult, error) {
		if request.Analyzer != fixture.baselineAnalyzer || request.Analyzer.Commit != measurement.TrustedBaselineRevision || request.Analyzer.Commit == fixture.harness.Commit {
			return CaptureResult{}, fmt.Errorf("capture received incorrect baseline analyzer %+v", request.Analyzer)
		}
		return validCapture(fixture.expected)(ctx, request)
	}))
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Authoritative || result.Manifest.Route != RouteProtectedBaseline || result.Manifest.BaselineAllowlist == nil {
		t.Fatalf("protected baseline run = %+v", result.Manifest)
	}
	if result.Manifest.BaselineAllowlist.Harness != fixture.harness || result.Manifest.BaselineAllowlist.Analyzer != fixture.baselineAnalyzer {
		t.Fatalf("baseline allowlist identity = %+v", result.Manifest.BaselineAllowlist)
	}
	entries, err := benchmark.CanonicalJSON(fixture.baselineAllowlist.Entries)
	if err != nil {
		t.Fatal(err)
	}
	if result.Manifest.BaselineAllowlist.ChangedEntryCount != len(fixture.baselineAllowlist.Entries) || result.Manifest.BaselineAllowlist.ChangedEntryDigest != benchmark.SHA256Digest(entries) {
		t.Fatalf("baseline allowlist result did not bind canonical change entries: %+v", result.Manifest.BaselineAllowlist)
	}
	if _, err := os.Stat(filepath.Join(result.Output, baselineAllowlistResultPath())); err != nil {
		t.Fatalf("baseline allowlist result was not published: %v", err)
	}
	var report measurement.MeasurementReport
	if _, err := readCanonicalJSON(filepath.Join(result.Output, "repetition-1", "report.json"), &report); err != nil {
		t.Fatal(err)
	}
	if report.Candidate.Accepted {
		t.Fatalf("protected baseline must not require candidate acceptance: %+v", report.Candidate)
	}
}

func TestAuthoritativeRoutesRejectIgnoredCheckoutResidue(t *testing.T) {
	for _, test := range []struct {
		name     string
		route    Route
		purpose  measurement.RunPurpose
		final    FinalMode
		analyzer func(fixture) RevisionIdentity
		snapshot func(fixture) measurement.SnapshotIdentity
	}{
		{
			name: "protected baseline", route: RouteProtectedBaseline, purpose: measurement.BaselineMeasurement, final: FinalBaseline,
			analyzer: func(f fixture) RevisionIdentity { return f.baselineAnalyzer },
			snapshot: func(f fixture) measurement.SnapshotIdentity { return f.baseline.ActiveSnapshot },
		},
		{
			name: "candidate", route: RouteCandidate, purpose: measurement.CandidateAcceptance, final: FinalAcceptance,
			analyzer: func(f fixture) RevisionIdentity { return f.candidateAnalyzer },
			snapshot: func(f fixture) measurement.SnapshotIdentity { return f.candidate.ActiveSnapshot },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(t)
			envelope := fixture.envelope(test.route, test.purpose, test.final, test.analyzer(fixture), test.snapshot(fixture))
			dependencies := fixture.dependencies(map[string]string{ControllerEnvelopeEnvironment: fixture.writeEnvelope(t, envelope)})
			original := dependencies.Command
			dependencies.Command = func(ctx context.Context, binary string, args ...string) ([]byte, error) {
				if binary == "git" && strings.Join(args, " ") == "status --porcelain=v1 -z --untracked-files=all --ignored=matching" {
					return []byte("!! .cache/contaminated\x00"), nil
				}
				return original(ctx, binary, args...)
			}
			runner, err := NewRunner(dependencies, captureFunc(validCapture(fixture.expected)))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := runner.Run(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "pristine checkout") {
				t.Fatalf("ignored checkout residue was accepted: %v", err)
			}
		})
	}
}

func TestProtectedBaselineRejectsUnreviewedAnalyzerPath(t *testing.T) {
	fixture := newFixture(t)
	dependencies := fixture.dependencies(map[string]string{ControllerEnvelopeEnvironment: fixture.writeEnvelope(t, fixture.envelope(RouteProtectedBaseline, measurement.BaselineMeasurement, FinalBaseline, fixture.baselineAnalyzer, fixture.baseline.ActiveSnapshot))})
	original := dependencies.Command
	dependencies.Command = func(ctx context.Context, binary string, args ...string) ([]byte, error) {
		if binary == "git" && strings.HasPrefix(strings.Join(args, " "), "diff --name-status --no-renames -z ") {
			return encodeChangedEntries([]BaselineAllowlistEntry{{Status: "M", Path: "internal/usecase/reachbench/contract_types.go"}}), nil
		}
		return original(ctx, binary, args...)
	}
	runner, err := NewRunner(dependencies, captureFunc(validCapture(fixture.expected)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "status or path") {
		t.Fatalf("unreviewed analyzer-path baseline delta was accepted: %v", err)
	}
}

func TestProtectedBaselineRejectsStatusMismatch(t *testing.T) {
	fixture := newFixture(t)
	dependencies := fixture.dependencies(map[string]string{ControllerEnvelopeEnvironment: fixture.writeEnvelope(t, fixture.envelope(RouteProtectedBaseline, measurement.BaselineMeasurement, FinalBaseline, fixture.baselineAnalyzer, fixture.baseline.ActiveSnapshot))})
	original := dependencies.Command
	dependencies.Command = func(ctx context.Context, binary string, args ...string) ([]byte, error) {
		if binary == "git" && strings.HasPrefix(strings.Join(args, " "), "diff --name-status --no-renames -z ") {
			entries := append([]BaselineAllowlistEntry(nil), fixture.baselineAllowlist.Entries...)
			entries[1].Status = "A"
			return encodeChangedEntries(entries), nil
		}
		return original(ctx, binary, args...)
	}
	runner, err := NewRunner(dependencies, captureFunc(validCapture(fixture.expected)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "status or path") {
		t.Fatalf("baseline change-status mismatch was accepted: %v", err)
	}
}

func TestNormalizeChangedEntriesRejectsDeletionRenameCopyAndMalformedRecords(t *testing.T) {
	for name, raw := range map[string][]byte{
		"deletion":        []byte("D\x00internal/infrastructure/reachbench/runner.go\x00"),
		"rename":          []byte("R100\x00old.go\x00new.go\x00"),
		"copy":            []byte("C100\x00old.go\x00new.go\x00"),
		"invalid utf8":    []byte{'M', 0, 0xff, 0},
		"control in path": []byte("M\x00docs/guide/unsafe\x01.md\x00"),
		"unterminated":    []byte("M\x00Makefile"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := normalizeChangedEntries(raw); err == nil {
				t.Fatal("unsafe changed-entry record was accepted")
			}
		})
	}
}

func TestBaselineAllowlistPermitsReviewedFoundationContractAndWorkflowPaths(t *testing.T) {
	allowlist := BaselineAllowlist{
		SchemaVersion: BaselineAllowlistSchemaVersion,
		ID:            "reviewed-foundation",
		Entries: []BaselineAllowlistEntry{
			{Status: "M", Path: ".github/workflows/ci.yml"},
			{Status: "M", Path: "Makefile"},
			{Status: "M", Path: "docs/guide/reachability-benchmark-runbook.md"},
			{Status: "A", Path: "fixtures/reachability/new-case.go"},
			{Status: "M", Path: "internal/domain/engagement/identity.go"},
			{Status: "M", Path: "internal/infrastructure/reachbench/launch.go"},
			{Status: "M", Path: "internal/usecase/reachbench/contract_types.go"},
		},
	}
	if err := allowlist.Validate(); err != nil {
		t.Fatalf("reviewed shared foundation paths were rejected: %v", err)
	}
	for _, path := range []string{".git/config", ".claude/settings.json", ".serena/state", "CLAUDE.md", "AGENTS.md", ".mcp.json", ".gitignore"} {
		if safeHarnessPath(path) {
			t.Fatalf("control path %q was accepted", path)
		}
	}
}

func TestProtectedBaselineRejectsTamperedAllowlist(t *testing.T) {
	fixture := newFixture(t)
	tampered := fixture.baselineAllowlist
	tampered.ID = "tampered-allowlist"
	writeCanonicalTestFile(t, filepath.Join(fixture.controllerBundleRoot, "baseline-allowlist.json"), tampered)
	envelopePath := fixture.writeEnvelope(t, fixture.envelope(RouteProtectedBaseline, measurement.BaselineMeasurement, FinalBaseline, fixture.baselineAnalyzer, fixture.baseline.ActiveSnapshot))
	runner, err := NewRunner(fixture.dependencies(map[string]string{ControllerEnvelopeEnvironment: envelopePath}), captureFunc(validCapture(fixture.expected)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "digest does not match") {
		t.Fatalf("tampered allowlist was accepted: %v", err)
	}
}

func TestVerifyNoPrivateLeakRejectsJSONEscapedWindowsPath(t *testing.T) {
	stage := t.TempDir()
	const privateWindowsPath = `C:\\private\\reachbench`
	if err := os.WriteFile(filepath.Join(stage, "artifact.json"), []byte(`{"path":"C:\\\\private\\\\reachbench"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyNoPrivateLeak(context.Background(), stage, []PublishedArtifact{{Path: "artifact.json"}}, runtimeFacts{temporaryRoot: privateWindowsPath}); err == nil {
		t.Fatal("JSON-escaped Windows private path was accepted")
	}
}

func TestCandidateCannotFallBackWhenTrustedLifecycleArtifactsAreMissing(t *testing.T) {
	fixture := newFixture(t)
	candidate := fixture.candidate
	candidate.Checkpoint = nil
	envelope := fixture.envelope(RouteCandidate, measurement.CandidateAcceptance, FinalAcceptance, fixture.candidateAnalyzer, candidate.ActiveSnapshot)
	if err := validateEnvelopeMeasurement(envelope, candidate, fixture.controllerBundleRef); err == nil || !strings.Contains(err.Error(), "baseline report, checkpoint, and ratchet") {
		t.Fatalf("candidate input without checkpoint was allowed to fall back: %v", err)
	}
	candidate = fixture.candidate
	candidate.Ratchet = nil
	if err := validateEnvelopeMeasurement(envelope, candidate, fixture.controllerBundleRef); err == nil || !strings.Contains(err.Error(), "baseline report, checkpoint, and ratchet") {
		t.Fatalf("candidate input without ratchet was allowed to fall back: %v", err)
	}
}

type fixture struct {
	repositoryRoot            string
	tempRoot                  string
	checkoutBundleRoot        string
	controllerBundleRoot      string
	harness                   HarnessIdentity
	baselineAnalyzer          RevisionIdentity
	candidateAnalyzer         RevisionIdentity
	baselineAllowlist         BaselineAllowlist
	baseline                  measurement.MeasurementInput
	candidate                 measurement.MeasurementInput
	expected                  map[string]measurement.Outcome
	checkoutBundleRef         measurement.ArtifactReference
	controllerBundleRef       measurement.ArtifactReference
	baselineReview            baselineReviewEvidence
	baselineDisposition       baselineDispositionEvidence
	candidateReview           candidateReviewSubject
	candidateReviewRef        measurement.ArtifactReference
	candidateAuthorityObjects map[string][]byte
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	repositoryRoot := t.TempDir()
	temporaryRoot := t.TempDir()
	harness := HarnessIdentity{ID: ReviewedHarnessID, Commit: strings.Repeat("1", 40), Tree: strings.Repeat("2", 40)}
	baselineAnalyzer := RevisionIdentity{ID: AnalyzerSubjectID, Commit: measurement.TrustedBaselineRevision, Tree: strings.Repeat("5", 40)}
	candidateAnalyzer := RevisionIdentity{ID: AnalyzerSubjectID, Commit: harness.Commit, Tree: harness.Tree}
	baseline, candidate, expected := measurementTemplates(t)
	allowlist := BaselineAllowlist{
		SchemaVersion: BaselineAllowlistSchemaVersion,
		ID:            "reviewed-harness-delta",
		Entries: []BaselineAllowlistEntry{
			{Status: "A", Path: "cmd/synapse-reachability-cycle/main.go"},
			{Status: "M", Path: "internal/infrastructure/reachbench/launch.go"},
			{Status: "M", Path: "internal/infrastructure/reachbench/runner.go"},
		},
	}
	checkoutBundleRoot := filepath.Join(repositoryRoot, filepath.FromSlash(TrustedBundleRelativePath))
	controllerBundleRoot := filepath.Join(temporaryRoot, filepath.FromSlash(controllerBundleDirectory))
	checkoutRef := writeFixtureBundle(t, checkoutBundleRoot, baseline, candidate, allowlist)
	controllerRef := writeFixtureBundle(t, controllerBundleRoot, baseline, candidate, allowlist)
	baselineReview, baselineDisposition, candidateReview, candidateReviewRef, candidateAuthorityObjects := newFixtureReviewTrust(t, harness, baselineAnalyzer, candidate.ActiveSnapshot, controllerRef)
	return fixture{
		repositoryRoot: repositoryRoot, tempRoot: temporaryRoot,
		checkoutBundleRoot: checkoutBundleRoot, controllerBundleRoot: controllerBundleRoot,
		harness: harness, baselineAnalyzer: baselineAnalyzer, candidateAnalyzer: candidateAnalyzer,
		baselineAllowlist: allowlist, baseline: baseline, candidate: candidate, expected: expected,
		checkoutBundleRef: checkoutRef, controllerBundleRef: controllerRef,
		baselineReview: baselineReview, baselineDisposition: baselineDisposition, candidateReview: candidateReview,
		candidateReviewRef: candidateReviewRef, candidateAuthorityObjects: candidateAuthorityObjects,
	}
}

func writeFixtureBundle(t *testing.T, root string, baseline, candidate measurement.MeasurementInput, allowlist BaselineAllowlist) measurement.ArtifactReference {
	t.Helper()
	baselineEncoded := canonicalTestJSON(t, baseline)
	candidateEncoded := canonicalTestJSON(t, candidate)
	allowlistEncoded := canonicalTestJSON(t, allowlist)
	bundle := TrustedBundle{
		SchemaVersion:     BundleSchemaVersion,
		ID:                "reachability-trusted",
		BaselineInput:     BundleAsset{Path: "baseline-input.json", Digest: benchmark.SHA256Digest(baselineEncoded)},
		CandidateInput:    &BundleAsset{Path: "candidate-input.json", Digest: benchmark.SHA256Digest(candidateEncoded)},
		BaselineAllowlist: BundleAsset{Path: "baseline-allowlist.json", Digest: benchmark.SHA256Digest(allowlistEncoded)},
	}
	writeCanonicalTestFile(t, filepath.Join(root, "baseline-input.json"), baseline)
	writeCanonicalTestFile(t, filepath.Join(root, "candidate-input.json"), candidate)
	writeCanonicalTestFile(t, filepath.Join(root, "baseline-allowlist.json"), allowlist)
	writeCanonicalTestFile(t, filepath.Join(root, "trusted-bundle.json"), bundle)
	return measurement.ArtifactReference{ID: bundle.ID, Digest: benchmark.SHA256Digest(canonicalTestJSON(t, bundle))}
}

func (fixture fixture) dependencies(environment map[string]string) Dependencies {
	return Dependencies{
		Command: func(_ context.Context, binary string, args ...string) ([]byte, error) {
			if binary != "git" {
				return nil, fmt.Errorf("unexpected binary %q", binary)
			}
			switch strings.Join(args, " ") {
			case "rev-parse --show-toplevel":
				return []byte(fixture.repositoryRoot + "\n"), nil
			case "rev-parse HEAD":
				return []byte(fixture.harness.Commit + "\n"), nil
			case "rev-parse HEAD^{tree}":
				return []byte(fixture.harness.Tree + "\n"), nil
			case "rev-parse " + measurement.TrustedBaselineRevision:
				return []byte(fixture.baselineAnalyzer.Commit + "\n"), nil
			case "rev-parse " + measurement.TrustedBaselineRevision + "^{tree}":
				return []byte(fixture.baselineAnalyzer.Tree + "\n"), nil
			case "status --porcelain=v1 -z --untracked-files=all --ignored=matching":
				return nil, nil
			case "diff --name-status --no-renames -z " + measurement.TrustedBaselineRevision + "..." + fixture.harness.Commit:
				return encodeChangedEntries(fixture.baselineAllowlist.Entries), nil
			case "ls-tree -r -z --full-tree " + fixture.harness.Tree + " -- " + TrustedBundleRelativePath:
				return fixture.candidateAuthorityTree(), nil
			}
			if len(args) == 3 && args[0] == "cat-file" && args[1] == "blob" {
				if body, found := fixture.candidateAuthorityObjects[args[2]]; found {
					return append([]byte(nil), body...), nil
				}
			}
			return nil, fmt.Errorf("unexpected git argv %q", args)
		},
		Environment: func(name string) (string, bool) {
			value, ok := environment[name]
			return value, ok
		},
		TempRoot:      func() string { return fixture.tempRoot },
		RandomSegment: func() (string, error) { return "fixed", nil },
	}
}

func testDependencies(repositoryRoot, temporaryRoot string, environment map[string]string) Dependencies {
	fixture := fixture{
		repositoryRoot:    repositoryRoot,
		tempRoot:          temporaryRoot,
		harness:           HarnessIdentity{ID: ReviewedHarnessID, Commit: strings.Repeat("1", 40), Tree: strings.Repeat("2", 40)},
		baselineAnalyzer:  RevisionIdentity{ID: AnalyzerSubjectID, Commit: measurement.TrustedBaselineRevision, Tree: strings.Repeat("5", 40)},
		baselineAllowlist: BaselineAllowlist{Entries: []BaselineAllowlistEntry{{Status: "A", Path: "cmd/synapse-reachability-cycle/main.go"}}},
	}
	return fixture.dependencies(environment)
}

func (fixture fixture) envelope(route Route, purpose measurement.RunPurpose, final FinalMode, analyzer RevisionIdentity, snapshot measurement.SnapshotIdentity) RunEnvelope {
	envelope := RunEnvelope{
		SchemaVersion: EnvelopeSchemaVersion,
		Route:         route,
		Purpose:       purpose,
		FinalMode:     final,
		Harness:       fixture.harness,
		Analyzer:      analyzer,
		Snapshot:      snapshot,
		Bundle:        fixture.controllerBundleRef,
		Authority: ProceduralAuthority{
			Class: "procedural", Controller: "controller", ReviewEvidence: fixture.baselineReview.Reference,
			ReviewedHarness: true, ReviewedHarnessID: ReviewedHarnessID,
		},
	}
	if route == RouteCandidate {
		envelope.Authority.ReviewEvidence = fixture.candidateReviewRef
	}
	return envelope
}

func (fixture fixture) writeEnvelope(t *testing.T, envelope RunEnvelope) string {
	t.Helper()
	fixture.provisionExternalReviewTrust(t)
	root := filepath.Join(fixture.tempRoot, filepath.FromSlash(controllerEnvelopeDirectory))
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "envelope.json")
	writeCanonicalTestFile(t, path, envelope)
	return path
}

func (fixture fixture) facts(runKey string) runtimeFacts {
	return runtimeFacts{
		repositoryRoot:     fixture.repositoryRoot,
		checkoutBundleRoot: fixture.checkoutBundleRoot,
		temporaryRoot:      fixture.tempRoot,
		rawRoot:            filepath.Join(fixture.tempRoot, filepath.FromSlash(privateRunDirectory)),
		outputRoot:         filepath.Join(fixture.tempRoot, filepath.FromSlash(publishedRunDirectory)),
		controllerRoot:     filepath.Join(fixture.tempRoot, filepath.FromSlash(controllerRootDirectory)),
		runKey:             runKey,
		harness:            fixture.harness,
	}
}

func validCapture(expected map[string]measurement.Outcome) func(context.Context, CaptureRequest) (CaptureResult, error) {
	return func(_ context.Context, request CaptureRequest) (CaptureResult, error) {
		outcome, ok := expected[request.Cell.CaseID]
		if !ok {
			return CaptureResult{}, fmt.Errorf("unexpected case %q", request.Cell.CaseID)
		}
		return CaptureResult{Observation: measurement.MeasuredObservation{
			CaseID: request.Cell.CaseID, BindingID: request.Cell.BindingID, Invoked: true, Outcome: outcome,
			Coverage:      measurement.ObservedCoverage{Status: measurement.CoverageComplete, Obligations: []measurement.CoverageObligation{{ID: "entrypoints", Status: measurement.CoverageComplete}}},
			OutputCapture: measurement.CaptureComplete,
			Analyzer:      measurement.ArtifactReference{ID: request.Cell.AnalyzerID, Digest: benchmark.SHA256Digest([]byte(request.Cell.AnalyzerID))},
			Configuration: request.Cell.Configuration,
			Suppression:   measurement.SuppressionCapture{Claim: measurement.SuppressionNone, Status: measurement.CaptureComplete},
		}}, nil
	}
}

func encodeChangedEntries(entries []BaselineAllowlistEntry) []byte {
	encoded := make([]byte, 0, len(entries)*64)
	for _, entry := range entries {
		encoded = append(encoded, entry.Status...)
		encoded = append(encoded, 0)
		encoded = append(encoded, entry.Path...)
		encoded = append(encoded, 0)
	}
	return encoded
}

func measurementTemplates(t *testing.T) (measurement.MeasurementInput, measurement.MeasurementInput, map[string]measurement.Outcome) {
	t.Helper()
	baseline, err := measurement.DefaultBaselineMeasurementInput()
	if err != nil {
		t.Fatal(err)
	}
	cells, err := enumerateCells(baseline)
	if err != nil {
		t.Fatal(err)
	}
	expected := make(map[string]measurement.Outcome, len(baseline.Oracle.Cases))
	for _, item := range baseline.Oracle.Cases {
		expected[item.CaseID] = item.Expected
	}
	for _, cell := range cells {
		baseline.Observations = append(baseline.Observations, measurement.MeasuredObservation{
			CaseID: cell.CaseID, BindingID: cell.BindingID, Invoked: true, Outcome: expected[cell.CaseID],
			Coverage:      measurement.ObservedCoverage{Status: measurement.CoverageComplete, Obligations: []measurement.CoverageObligation{{ID: "entrypoints", Status: measurement.CoverageComplete}}},
			OutputCapture: measurement.CaptureComplete,
			Analyzer:      measurement.ArtifactReference{ID: cell.AnalyzerID, Digest: benchmark.SHA256Digest([]byte(cell.AnalyzerID))},
			Configuration: cell.Configuration,
			Suppression:   measurement.SuppressionCapture{Claim: measurement.SuppressionNone, Status: measurement.CaptureComplete},
		})
	}
	if err := baseline.Validate(); err != nil {
		t.Fatalf("baseline fixture invalid: %v", err)
	}
	report, err := measurement.EvaluateMeasurement(baseline)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := fixtureCheckpoint(t, baseline.Policy, report)
	candidate, err := measurement.BuildCandidateMeasurementInput(report, checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	baseline.Observations = nil
	if err := baseline.Validate(); err != nil {
		t.Fatalf("baseline template invalid: %v", err)
	}
	return baseline, candidate, expected
}

func fixtureCheckpoint(t *testing.T, policy measurement.MeasurementPolicy, baseline measurement.MeasurementReport) measurement.ProceduralBaselineCheckpoint {
	t.Helper()
	policyDigest, err := measurement.DigestMeasurementPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := measurement.ProceduralBaselineCheckpoint{
		SchemaVersion: measurement.BaselineCheckpointSchemaVersion, AuthorityClass: "procedural", StartingRevision: measurement.TrustedBaselineRevision,
		Policy: measurement.ArtifactReference{ID: policy.ID, Digest: policyDigest}, BaselineResult: measurement.ArtifactReference{ID: baseline.ID, Digest: baseline.ID},
		HarnessContract: reference("harness-contract"), AllowlistEvidence: reference("allowlist"), ReviewEvidence: reference("review"), DispositionEvidence: reference("disposition"),
		Producer: "producer", Reviewer: "reviewer", Maintainer: "maintainer",
	}
	id, err := measurement.DigestProceduralBaselineCheckpoint(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint.ID = id
	return checkpoint
}

func reference(id string) measurement.ArtifactReference {
	return measurement.ArtifactReference{ID: id, Digest: benchmark.SHA256Digest([]byte(id))}
}

func canonicalTestJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := benchmark.CanonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func writeCanonicalTestFile(t *testing.T, path string, value any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	encoded := canonicalTestJSON(t, value)
	encoded = append(encoded, '\n')
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}

func repeatCells(t *testing.T, root string) []CellRepeatDigest {
	t.Helper()
	var result SemanticRepeatResult
	if _, err := readCanonicalJSON(filepath.Join(root, "semantic-repeat.json"), &result); err != nil {
		t.Fatal(err)
	}
	sort.Slice(result.Cells, func(left, right int) bool {
		return result.Cells[left].CaseID+"\x00"+result.Cells[left].BindingID < result.Cells[right].CaseID+"\x00"+result.Cells[right].BindingID
	})
	return result.Cells
}
