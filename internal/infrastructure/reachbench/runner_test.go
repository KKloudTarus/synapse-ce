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
	candidate = fixture.envelope(RouteCandidate, measurement.CandidateAcceptance, FinalAcceptance, RevisionIdentity{ID: AnalyzerSubjectID, Commit: fixture.harness.Commit, Tree: fixture.harness.Tree}, fixture.candidate.ActiveSnapshot)
	if err := runner.validateAuthoritativeEnvelope(context.Background(), candidate, fixture.facts("local/fixed"), fixture.controllerBundleRef); err == nil || !strings.Contains(err.Error(), "distinct") {
		t.Fatalf("candidate analyzer matched the runtime harness: %v", err)
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
	if err != nil {
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
	if len(cells) != len(fixture.expected) {
		t.Fatalf("cells = %d, want %d", len(cells), len(fixture.expected))
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
		if request.Repetition == 2 && request.Cell.CaseID == "go-reachable" {
			result.Observation.Outcome = measurement.OutcomeNoAnalysis
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

func TestAuthoritativeCandidateEnvelopePassesDistinctAnalyzerAndPublishesAuthority(t *testing.T) {
	fixture := newFixture(t)
	envelope := fixture.envelope(RouteCandidate, measurement.CandidateAcceptance, FinalAcceptance, fixture.candidateAnalyzer, fixture.candidate.ActiveSnapshot)
	envelopePath := fixture.writeEnvelope(t, envelope)
	captures := 0
	runner, err := NewRunner(fixture.dependencies(map[string]string{ControllerEnvelopeEnvironment: envelopePath}), captureFunc(func(ctx context.Context, request CaptureRequest) (CaptureResult, error) {
		captures++
		if request.Analyzer != fixture.candidateAnalyzer || request.Analyzer.Commit == fixture.harness.Commit {
			return CaptureResult{}, fmt.Errorf("capture received incorrect candidate analyzer %+v", request.Analyzer)
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
	if !result.Authoritative || result.Manifest.Route != RouteCandidate || result.Manifest.FinalMode != FinalAcceptance {
		t.Fatalf("candidate controller run = %+v", result.Manifest)
	}
	if captures != fixedRepetitions*len(result.Manifest.Cells) {
		t.Fatalf("captures = %d", captures)
	}
	if result.Manifest.Authority != envelope.Authority {
		t.Fatalf("published authority = %+v, want %+v", result.Manifest.Authority, envelope.Authority)
	}
	published, err := os.ReadFile(filepath.Join(result.Output, "lifecycle-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(published, []byte("\"class\":\"procedural\"")) || !bytes.Contains(published, []byte("\"reviewed_harness\":true")) || !bytes.Contains(published, []byte("\"reviewed_harness_id\":\""+ReviewedHarnessID+"\"")) {
		t.Fatalf("publication omitted procedural authority: %s", published)
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
}

func TestProtectedBaselineRejectsDirtyHarness(t *testing.T) {
	fixture := newFixture(t)
	dependencies := fixture.dependencies(map[string]string{ControllerEnvelopeEnvironment: fixture.writeEnvelope(t, fixture.envelope(RouteProtectedBaseline, measurement.BaselineMeasurement, FinalBaseline, fixture.baselineAnalyzer, fixture.baseline.ActiveSnapshot))})
	original := dependencies.Command
	dependencies.Command = func(ctx context.Context, binary string, args ...string) ([]byte, error) {
		if binary == "git" && strings.Join(args, " ") == "status --porcelain" {
			return []byte(" M internal/infrastructure/reachbench/runner.go\n"), nil
		}
		return original(ctx, binary, args...)
	}
	runner, err := NewRunner(dependencies, captureFunc(validCapture(fixture.expected)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "clean harness") {
		t.Fatalf("dirty harness was accepted: %v", err)
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
	repositoryRoot       string
	tempRoot             string
	checkoutBundleRoot   string
	controllerBundleRoot string
	harness              HarnessIdentity
	baselineAnalyzer     RevisionIdentity
	candidateAnalyzer    RevisionIdentity
	baselineAllowlist    BaselineAllowlist
	baseline             measurement.MeasurementInput
	candidate            measurement.MeasurementInput
	expected             map[string]measurement.Outcome
	checkoutBundleRef    measurement.ArtifactReference
	controllerBundleRef  measurement.ArtifactReference
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	repositoryRoot := t.TempDir()
	temporaryRoot := t.TempDir()
	harness := HarnessIdentity{ID: ReviewedHarnessID, Commit: strings.Repeat("1", 40), Tree: strings.Repeat("2", 40)}
	baselineAnalyzer := RevisionIdentity{ID: AnalyzerSubjectID, Commit: measurement.TrustedBaselineRevision, Tree: strings.Repeat("5", 40)}
	candidateAnalyzer := RevisionIdentity{ID: AnalyzerSubjectID, Commit: strings.Repeat("3", 40), Tree: strings.Repeat("4", 40)}
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
	return fixture{
		repositoryRoot: repositoryRoot, tempRoot: temporaryRoot,
		checkoutBundleRoot: checkoutBundleRoot, controllerBundleRoot: controllerBundleRoot,
		harness: harness, baselineAnalyzer: baselineAnalyzer, candidateAnalyzer: candidateAnalyzer,
		baselineAllowlist: allowlist, baseline: baseline, candidate: candidate, expected: expected,
		checkoutBundleRef: checkoutRef, controllerBundleRef: controllerRef,
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
		CandidateInput:    BundleAsset{Path: "candidate-input.json", Digest: benchmark.SHA256Digest(candidateEncoded)},
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
			case "status --porcelain":
				return nil, nil
			case "diff --name-status --no-renames -z " + measurement.TrustedBaselineRevision + "..." + fixture.harness.Commit:
				return encodeChangedEntries(fixture.baselineAllowlist.Entries), nil
			default:
				return nil, fmt.Errorf("unexpected git argv %q", args)
			}
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
	return RunEnvelope{
		SchemaVersion: EnvelopeSchemaVersion,
		Route:         route,
		Purpose:       purpose,
		FinalMode:     final,
		Harness:       fixture.harness,
		Analyzer:      analyzer,
		Snapshot:      snapshot,
		Bundle:        fixture.controllerBundleRef,
		Authority: ProceduralAuthority{
			Class: "procedural", Controller: "controller", ReviewEvidence: reference("review-record"),
			ReviewedHarness: true, ReviewedHarnessID: ReviewedHarnessID,
		},
	}
}

func (fixture fixture) writeEnvelope(t *testing.T, envelope RunEnvelope) string {
	t.Helper()
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
	inventory := measurement.DefaultProductionInventory()
	corpus := measurement.ContractCorpus{SchemaVersion: measurement.ContractCorpusSchemaVersion, ID: "fixture-corpus", Cases: []measurement.ContractCase{
		{ID: "go-reachable", SubjectID: "pkg:reachbench/go/source_tier2#controlPositive", CohortID: "go", ModeID: "source_tier2", Fixture: pointer(measurement.ArtifactReference{ID: "go-source-tier2-input", Digest: "sha256:47f381492824aa8af1eb5694ba302d1a65b4f31f6e8fa3fdf87b9ad9e8469782"})},
		{ID: "go-conditional", SubjectID: "pkg:reachbench/go/source_tier2#controlOpaque", CohortID: "go", ModeID: "source_tier2", Fixture: pointer(measurement.ArtifactReference{ID: "go-source-tier2-input", Digest: "sha256:47f381492824aa8af1eb5694ba302d1a65b4f31f6e8fa3fdf87b9ad9e8469782"})},
		{ID: "go-unreached", SubjectID: "pkg:reachbench/go/source_tier2#controlUnreachable", CohortID: "go", ModeID: "source_tier2", Fixture: pointer(measurement.ArtifactReference{ID: "go-source-tier2-input", Digest: "sha256:47f381492824aa8af1eb5694ba302d1a65b4f31f6e8fa3fdf87b9ad9e8469782"})},
		{ID: "go-no-analysis", SubjectID: "pkg:reachbench/go/source_tier2#controlNoCoverage", CohortID: "go", ModeID: "source_tier2", Fixture: pointer(measurement.ArtifactReference{ID: "go-source-tier2-input", Digest: "sha256:47f381492824aa8af1eb5694ba302d1a65b4f31f6e8fa3fdf87b9ad9e8469782"})},
	}}
	completeness := reference("go-source-completeness")
	oracle := measurement.ReachabilityOracle{SchemaVersion: measurement.OracleSchemaVersion, ID: "fixture-oracle", Cases: []measurement.OracleCase{
		{CaseID: "go-reachable", Expected: measurement.OutcomeReachable, Category: measurement.OracleReachable, CoverageExpectation: measurement.CoverageComplete},
		{CaseID: "go-conditional", Expected: measurement.OutcomeConditionallyReachable, Category: measurement.OracleOpaque, CoverageExpectation: measurement.CoverageComplete},
		{CaseID: "go-unreached", Expected: measurement.OutcomePresentUnreached, Category: measurement.OracleTrulyUnreachable, CoverageExpectation: measurement.CoverageComplete, SuppressionApplicable: true, CompletenessContract: pointer(completeness)},
		{CaseID: "go-no-analysis", Expected: measurement.OutcomeNoAnalysis, Category: measurement.OracleNoCoverage, CoverageExpectation: measurement.CoverageComplete},
	}}
	exceptions := measurement.ExceptionManifest{SchemaVersion: measurement.ExceptionManifestSchemaVersion, ID: "no-exceptions"}
	policy := fixturePolicy(t, inventory, corpus, oracle, exceptions)
	baseline := measurement.MeasurementInput{
		SchemaVersion: measurement.MeasurementInputSchemaVersion, Purpose: measurement.BaselineMeasurement,
		Inventory: inventory, Corpus: corpus, Oracle: oracle, Policy: policy, Exceptions: exceptions,
		ActiveSnapshot: measurement.SnapshotIdentity{Source: reference("source"), SBOM: reference("sbom"), Run: reference("run")},
	}
	cohort, binding := goCohort(t, inventory)
	expected := map[string]measurement.Outcome{}
	for _, item := range oracle.Cases {
		expected[item.CaseID] = item.Expected
		baseline.Observations = append(baseline.Observations, measurement.MeasuredObservation{
			CaseID: item.CaseID, BindingID: binding.ID, Invoked: true, Outcome: item.Expected,
			Coverage:      measurement.ObservedCoverage{Status: measurement.CoverageComplete, Obligations: []measurement.CoverageObligation{{ID: "entrypoints", Status: measurement.CoverageComplete}}},
			OutputCapture: measurement.CaptureComplete, Analyzer: reference(cohort.AnalyzerID), Configuration: binding.Configuration,
			Suppression: measurement.SuppressionCapture{Claim: measurement.SuppressionNone, Status: measurement.CaptureComplete},
		})
	}
	if err := baseline.Validate(); err != nil {
		t.Fatalf("baseline fixture invalid: %v", err)
	}
	report, err := measurement.EvaluateMeasurement(baseline)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := fixtureCheckpoint(t, policy, report)
	ratchet, err := measurement.DeriveCandidateRatchet(policy, report, checkpoint, exceptions)
	if err != nil {
		t.Fatal(err)
	}
	candidate := baseline
	candidate.Purpose = measurement.CandidateAcceptance
	candidate.Observations = nil
	candidate.Baseline = &report
	candidate.Checkpoint = &checkpoint
	candidate.Ratchet = &ratchet
	if err := candidate.Validate(); err != nil {
		t.Fatalf("candidate fixture invalid: %v", err)
	}
	baseline.Observations = nil
	if err := baseline.Validate(); err != nil {
		t.Fatalf("baseline template invalid: %v", err)
	}
	return baseline, candidate, expected
}

func fixturePolicy(t *testing.T, inventory measurement.ProductionInventory, corpus measurement.ContractCorpus, oracle measurement.ReachabilityOracle, exceptions measurement.ExceptionManifest) measurement.MeasurementPolicy {
	t.Helper()
	inventoryDigest, err := measurement.DigestProductionInventory(inventory)
	if err != nil {
		t.Fatal(err)
	}
	corpusDigest, err := measurement.DigestContractCorpus(corpus)
	if err != nil {
		t.Fatal(err)
	}
	oracleDigest, err := measurement.DigestReachabilityOracle(oracle)
	if err != nil {
		t.Fatal(err)
	}
	exceptionDigest, err := measurement.DigestExceptionManifest(exceptions)
	if err != nil {
		t.Fatal(err)
	}
	completeness := reference("go-source-completeness")
	rules := make([]measurement.SuppressionPolicyRule, 0, len(inventory.Cohorts))
	for _, cohort := range inventory.Cohorts {
		rule := measurement.SuppressionPolicyRule{CohortID: cohort.ID, ModeID: cohort.Mode, Disposition: measurement.SuppressionRaiseOnly}
		if (cohort.ID == "rust" || cohort.ID == "ruby") && cohort.Mode == "import" {
			rule.Disposition = measurement.SuppressionProhibited
		}
		if cohort.ID == "go" && cohort.Mode == "source_tier2" {
			rule.Disposition = measurement.SuppressionEligible
			rule.CompletenessContract = pointer(completeness)
			rule.ApprovedProposer, rule.ApprovedVerifier = "proposer", "verifier"
		}
		rules = append(rules, rule)
	}
	return measurement.MeasurementPolicy{
		SchemaVersion: measurement.PolicySchemaVersion, ID: "fixture-policy",
		Inventory: measurement.ArtifactReference{ID: inventory.ID, Digest: inventoryDigest}, Corpus: measurement.ArtifactReference{ID: corpus.ID, Digest: corpusDigest},
		Oracle: measurement.ArtifactReference{ID: oracle.ID, Digest: oracleDigest}, ExceptionManifest: measurement.ArtifactReference{ID: exceptions.ID, Digest: exceptionDigest},
		SchemaDefinition: reference("contract-schema-definition"), RunPurposeRules: reference("contract-run-purpose-rules"), RatchetConstructionRule: reference("contract-ratchet-construction"),
		Evaluator: reference("contract-evaluator"), MetricDefinition: reference("contract-metrics"), Adapters: []measurement.ArtifactReference{reference("production-adapter")}, Rules: rules,
	}
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

func goCohort(t *testing.T, inventory measurement.ProductionInventory) (measurement.ProductionCohort, measurement.CompositionBinding) {
	t.Helper()
	for _, cohort := range inventory.Cohorts {
		if cohort.ID != "go" || cohort.Mode != "source_tier2" {
			continue
		}
		for _, binding := range cohort.Bindings {
			if binding.ID == "api" {
				return cohort, binding
			}
		}
	}
	t.Fatal("fixture inventory lacks go/source_tier2 api binding")
	return measurement.ProductionCohort{}, measurement.CompositionBinding{}
}

func reference(id string) measurement.ArtifactReference {
	return measurement.ArtifactReference{ID: id, Digest: benchmark.SHA256Digest([]byte(id))}
}
func pointer(value measurement.ArtifactReference) *measurement.ArtifactReference { return &value }

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
