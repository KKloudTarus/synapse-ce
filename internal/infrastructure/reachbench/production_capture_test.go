package reachbench

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/runtimereach"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/benchcycle"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachability"
	measurement "github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachproof"
)

type captureTestMaterializer struct{}

func (captureTestMaterializer) Materialize(_ context.Context, request FixtureMaterializationRequest) (MaterializedFixture, error) {
	return MaterializedFixture{Root: "/private/reachbench-fixture", Specification: request.Specification}, nil
}

type captureTestAnalyzer struct {
	result *reachability.Analysis
	err    error
	calls  int
}

func (analyzer *captureTestAnalyzer) Analyze(_ context.Context, _ string, _ []string) (*reachability.Analysis, error) {
	analyzer.calls++
	return analyzer.result, analyzer.err
}

func TestProductionCaptureRegistersFrozenModes(t *testing.T) {
	capture, err := NewProductionCapture(ProductionCaptureDependencies{Materializer: captureTestMaterializer{}})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(capture.modes); got != 19 {
		t.Fatalf("mode count = %d, want 19", got)
	}
	missing := make(map[string]productionMode, len(capture.modes)-1)
	for key, mode := range capture.modes {
		if key != "runtime\x00library_loads" {
			missing[key] = mode
		}
	}
	if err := validateProductionModes(missing); err == nil || !strings.Contains(err.Error(), "registry") {
		t.Fatalf("missing production mode error = %v, want closed-registry failure", err)
	}
	unexpected := make(map[string]productionMode, len(capture.modes)+1)
	for key, mode := range capture.modes {
		unexpected[key] = mode
	}
	unexpected["unexpected\x00mode"] = runGoSourceTier2
	if err := validateProductionModes(unexpected); err == nil || !strings.Contains(err.Error(), "registry") {
		t.Fatalf("unexpected production mode error = %v, want closed-registry failure", err)
	}
}

func TestImportSubjectsAcceptsScopedNPMPackageURL(t *testing.T) {
	const subjectID = "pkg:npm/@reachbench/unsupported@1.0.0"
	subjects, err := importSubjects(measurement.ResolvedFixtureSubject{
		Subject: measurement.FixtureSubject{ID: subjectID},
	}, "npm")
	if err != nil {
		t.Fatal(err)
	}
	if len(subjects) != 1 ||
		subjects[0].PackagePURL != subjectID ||
		len(subjects[0].Symbols) != 1 ||
		subjects[0].Symbols[0] != "@reachbench/unsupported" {
		t.Fatalf("scoped npm subjects = %#v", subjects)
	}
}

func TestImportSubjectsRejectsMalformedPackageURLs(t *testing.T) {
	for _, subjectID := range []string{
		"pkg:npm/@scope/name@1.0.0@2.0.0",
		"pkg:npm/@@1.0.0",
		"pkg:npm/@scope@1.0.0",
		"pkg:npm/@scope/@1.0.0",
		"pkg:npm/@scope/name@1.0.0?arch=x64",
		"pkg:npm/@scope/name @1.0.0",
		"pkg:npm/@scope/name@ 1.0.0",
		"pkg:npm/@scope/name@1.0.0 ",
		"pkg:npm/@scope/name" + string(rune(0x00a0)) + "@1.0.0",
		"pkg:pypi/@scope/name@1.0.0",
	} {
		t.Run(subjectID, func(t *testing.T) {
			wantType := "npm"
			if strings.HasPrefix(subjectID, "pkg:pypi/") {
				wantType = "pypi"
			}
			if _, err := importSubjects(measurement.ResolvedFixtureSubject{
				Subject: measurement.FixtureSubject{ID: subjectID},
			}, wantType); err == nil {
				t.Fatalf("importSubjects(%q) succeeded", subjectID)
			}
		})
	}
}

func TestProductionCaptureCapturesScopedNPMNoCoverageCell(t *testing.T) {
	fixtureReference := measurement.ArtifactReference{
		ID:     "javascript-import-input",
		Digest: "sha256:da56a31402f2aab42ba3655ed7020b28db5c86dfa6712949aa61917622658c9b",
	}
	cell := ExecutionCell{
		CaseID:        "javascript-import-control-no-coverage",
		CohortID:      "javascript",
		ModeID:        "import",
		BindingID:     "api",
		AnalyzerID:    "sca-javascript-import",
		Configuration: captureArtifact("configuration"),
		SubjectID:     "pkg:npm/@reachbench/unsupported@1.0.0",
		Fixture:       fixtureReference,
		BoundaryID:    "sca/reachability/javascript-import/api",
	}
	materializer := newFixtureMaterializer(t, &fixtureToolRunner{}, "linux/amd64")
	capture, err := NewProductionCapture(ProductionCaptureDependencies{Materializer: materializer})
	if err != nil {
		t.Fatal(err)
	}
	evidenceStore, err := benchcycle.NewEvidenceStore(t.TempDir(), reachabilityEvidenceLimits())
	if err != nil {
		t.Fatal(err)
	}
	result, err := capture.Capture(context.Background(), CaptureRequest{
		Cell:       cell,
		Repetition: 1,
		WorkRoot:   privateMaterializerRoot(t),
		Analyzer: RevisionIdentity{
			ID: AnalyzerSubjectID, Commit: measurement.TrustedBaselineRevision,
			Tree: strings.Repeat("b", 40),
		},
		Snapshot: captureSnapshot(),
		attempt:  benchcycle.AttemptAddress{CellKey: "javascript-import-scoped-capture", Repetition: 1},
		evidence: evidenceStore,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.EvidenceReceipts) != 1 {
		t.Fatalf("evidence receipts = %#v, want exactly one raw artifact", result.EvidenceReceipts)
	}
	if !result.Observation.Invoked || result.Observation.Outcome != measurement.OutcomeNoAnalysis {
		t.Fatalf("scoped npm observation = %#v, want invoked no-analysis", result.Observation)
	}
	if result.Observation.Suppression.Claim != measurement.SuppressionNone {
		t.Fatalf("scoped npm suppression = %#v, want no suppression", result.Observation.Suppression)
	}
}

func TestRecordingAnalyzerNormalizesOneProductionResult(t *testing.T) {
	delegate := &captureTestAnalyzer{result: &reachability.Analysis{
		Entrypoints: []string{"/private/materialization/main.go"},
		Results: []reachability.Result{{
			Symbol: "target", Reachable: true, Path: []string{"/private/materialization/main.go", "target"},
			Provenance: &reachability.SourceProvenance{ModulePath: "fixtures/go/main.go", Line: 7},
		}},
	}}
	analyzer := &recordingAnalyzer{delegate: delegate, materializedRoot: "/private/materialization"}
	result, err := analyzer.Analyze(context.Background(), "/private/materialization", []string{"target"})
	if err != nil {
		t.Fatal(err)
	}
	if delegate.calls != 1 || analyzer.calls != 1 {
		t.Fatalf("analyzer calls = delegate %d wrapper %d, want 1/1", delegate.calls, analyzer.calls)
	}
	if strings.Contains(strings.Join(result.Entrypoints, "\n")+strings.Join(result.Results[0].Path, "\n"), "/private/materialization") {
		t.Fatalf("normalized result retained materialization path: %#v", result)
	}
	if got := result.Results[0].Provenance; got == nil || got.ModulePath != "fixtures/go/main.go" || got.Line != 7 {
		t.Fatalf("normalized result lost safe declaration provenance: %#v", got)
	}
	if _, err := analyzer.Analyze(context.Background(), "/private/materialization", []string{"target"}); err == nil {
		t.Fatal("second analyzer invocation succeeded")
	}
}

func TestRecordingAnalyzerDropsUnsafeProvenance(t *testing.T) {
	delegate := &captureTestAnalyzer{result: &reachability.Analysis{Results: []reachability.Result{{
		Symbol: "target", Reachable: true,
		Provenance: &reachability.SourceProvenance{ModulePath: "/private/materialization/main.php", Line: 7},
	}}}}
	analyzer := &recordingAnalyzer{delegate: delegate, materializedRoot: "/private/materialization"}
	result, err := analyzer.Analyze(context.Background(), "/private/materialization", []string{"target"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Results[0].Provenance != nil {
		t.Fatalf("unsafe provenance leaked through production capture: %#v", result.Results[0].Provenance)
	}
}

func TestProductionCaptureDoesNotFabricateSuppressionWithoutAuthority(t *testing.T) {
	lifecycle, err := newCaptureLifecycle()
	if err != nil {
		t.Fatal(err)
	}
	resolved := measurement.ResolvedFixtureSubject{Subject: measurement.FixtureSubject{
		ID:              "pkg:reachbench/go/source_tier2#controlUnreachable",
		PackageIdentity: "example.invalid/reachbench/go-source-tier2",
		Locator:         measurement.FixtureLocator{Kind: measurement.FixtureLocatorSourceSymbol, ModulePath: "fixtures/golang/source_tier2/main.go", Symbol: "controlUnreachable", Line: 16},
	}}
	delegate := &captureTestAnalyzer{result: &reachability.Analysis{Results: []reachability.Result{{Symbol: "controlUnreachable"}}, Entrypoints: []string{"main.main"}}}
	executed, err := runStatic(context.Background(), MaterializedFixture{Root: "/private/fixture"}, resolved, lifecycle,
		[]ports.ReachabilitySubject{{FindingID: shared.ID(resolved.Subject.ID), Symbols: []string{"controlUnreachable"}}},
		func() (staticAnalyzer, error) { return delegate, nil },
		func(analyzer staticAnalyzer) (*reachproof.Coordinator, error) {
			return reachproof.NewCoordinator(analyzer, lifecycle.judgments, lifecycle.audit, lifecycle.clock)
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	cell := ExecutionCell{
		CaseID: "go-unreached", CohortID: "go", ModeID: "source_tier2", BindingID: "api", AnalyzerID: "sca-go-source-tier2",
		Configuration: captureArtifact("configuration"), SubjectID: resolved.Subject.ID, Fixture: captureArtifact("fixture"), BoundaryID: "sca/reachability/go-source-tier2/api",
	}
	observation, err := (&ProductionCapture{}).observation(context.Background(), CaptureRequest{
		Cell: cell, Analyzer: RevisionIdentity{ID: AnalyzerSubjectID, Commit: strings.Repeat("a", 40), Tree: strings.Repeat("b", 40)}, Snapshot: captureSnapshot(),
	}, lifecycle, executed)
	if err != nil {
		t.Fatal(err)
	}
	if observation.Outcome != measurement.OutcomePresentUnreached {
		t.Fatalf("outcome = %q, want present_unreached", observation.Outcome)
	}
	if observation.Suppression.Claim != measurement.SuppressionNone || len(observation.Suppression.Effects) != 0 {
		t.Fatalf("suppression = %#v, want fail-closed non-suppression", observation.Suppression)
	}
	judgments, err := lifecycle.judgments.List(context.Background(), productionCaptureEngagementID)
	if err != nil {
		t.Fatal(err)
	}
	disposition, ok := judgment.WinningReachabilityDispositions(judgments, nil)[cell.SubjectID]
	if !ok || disposition.State != judgment.NotReachable || disposition.Suppresses {
		t.Fatalf("persisted disposition = %#v, want present but unauthorized negative", disposition)
	}
}

func TestNilAnalyzerResultIsNoAnalysisNotSuppression(t *testing.T) {
	analyzer := &recordingAnalyzer{delegate: &captureTestAnalyzer{}}
	result, err := analyzer.Analyze(context.Background(), "/fixture", []string{"subject"})
	if result != nil || !errors.Is(err, errNilAnalyzerResult) {
		t.Fatalf("nil analyzer result = (%#v, %v), want nil and classified error", result, err)
	}
}

func TestProductionCaptureClassifiesAnalyzerFailureAsNoAnalysis(t *testing.T) {
	lifecycle, err := newCaptureLifecycle()
	if err != nil {
		t.Fatal(err)
	}
	resolved := measurement.ResolvedFixtureSubject{Subject: measurement.FixtureSubject{
		ID: "pkg:reachbench/go/source_tier2#controlNoCoverage", Locator: measurement.FixtureLocator{Symbol: "controlNoCoverage"},
	}}
	executed, err := runStatic(context.Background(), MaterializedFixture{Root: "/private/fixture"}, resolved, lifecycle,
		[]ports.ReachabilitySubject{{FindingID: shared.ID(resolved.Subject.ID), Symbols: []string{"controlNoCoverage"}}},
		func() (staticAnalyzer, error) {
			return &captureTestAnalyzer{err: errors.New("analyzer unavailable")}, nil
		},
		func(analyzer staticAnalyzer) (*reachproof.Coordinator, error) {
			return reachproof.NewCoordinator(analyzer, lifecycle.judgments, lifecycle.audit, lifecycle.clock)
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	cell := ExecutionCell{
		CaseID: "go-no-analysis", CohortID: "go", ModeID: "source_tier2", BindingID: "api", AnalyzerID: "sca-go-source-tier2",
		Configuration: captureArtifact("configuration"), SubjectID: resolved.Subject.ID, Fixture: captureArtifact("fixture"), BoundaryID: "sca/reachability/go-source-tier2/api",
	}
	observation, err := (&ProductionCapture{}).observation(context.Background(), CaptureRequest{
		Cell: cell, Analyzer: RevisionIdentity{ID: AnalyzerSubjectID, Commit: strings.Repeat("a", 40), Tree: strings.Repeat("b", 40)}, Snapshot: captureSnapshot(),
	}, lifecycle, executed)
	if err != nil {
		t.Fatal(err)
	}
	if observation.Outcome != measurement.OutcomeNoAnalysis || observation.Coverage.Status != measurement.CoverageUnavailable {
		t.Fatalf("analyzer failure observation = %#v, want unavailable no-analysis", observation)
	}
	if observation.Suppression.Claim != measurement.SuppressionNone || observation.Suppression.Status != measurement.CaptureComplete {
		t.Fatalf("analyzer failure suppression = %#v, want complete non-suppression", observation.Suppression)
	}
}

func TestRuntimeReportPreservesOpaqueAndUnsupportedControls(t *testing.T) {
	replay := measurement.RuntimeReplay{
		Complete: true, LossState: "none",
		Owners: []measurement.RuntimeReplayOwner{
			{Library: "direct.so", Owner: measurement.RuntimePackage{Name: "direct", Version: "1"}},
			{Library: "opaque.so", Owner: measurement.RuntimePackage{Name: "opaque", Version: "1"}},
			{Library: "unsupported.so", Owner: measurement.RuntimePackage{Name: "unsupported", Version: "1"}},
		},
		Events: []measurement.RuntimeReplayEvent{
			{Operation: "load", Library: "direct.so", Owner: measurement.RuntimePackage{Name: "direct", Version: "1"}},
			{Operation: "opaque", Library: "opaque.so", Owner: measurement.RuntimePackage{Name: "opaque", Version: "1"}},
			{Operation: "unsupported", Library: "unsupported.so", Owner: measurement.RuntimePackage{Name: "unsupported", Version: "1"}},
		},
	}
	report, opaque, unsupported := runtimeReport(replay)
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	ownership, loads := report.Build()
	pkg, match := ownership.Resolve(loads[0])
	if pkg.Name != "direct" || match == runtimereach.MatchNone {
		t.Fatalf("runtime load resolution = %#v/%q, want direct concrete owner", pkg, match)
	}
	if !opaque["opaque"] || !unsupported["unsupported"] {
		t.Fatalf("runtime control state opaque=%v unsupported=%v", opaque, unsupported)
	}
}

func TestRuntimeCaptureRecordsProductionReachabilityWithoutStaticAnalyzer(t *testing.T) {
	fixtures := measurement.DefaultFixtureManifest()
	fixtureReference := measurement.ArtifactReference{
		ID:     "runtime-library-loads-input",
		Digest: "sha256:2ea65181344c35516df313a44c68258c348e9d83d07c04cfef98855ae7ebadca",
	}
	resolved, err := fixtures.ResolveFixtureSubject(fixtureReference, "pkg:reachbench/runtime/library_loads#controlPositive")
	if err != nil {
		t.Fatal(err)
	}
	cell := ExecutionCell{
		CaseID: "runtime-library-loads-control-positive", CohortID: "runtime", ModeID: "library_loads", BindingID: "runtime", AnalyzerID: "runtime-library-loads",
		Configuration: captureArtifact("configuration"), SubjectID: resolved.Subject.ID, Fixture: fixtureReference, BoundaryID: "sca/reachability/runtime/library-loads",
	}
	materializer := newFixtureMaterializer(t, &fixtureToolRunner{}, "linux/amd64")
	fixture, err := materializer.Materialize(context.Background(), FixtureMaterializationRequest{
		Specification: resolved.Specification, WorkRoot: privateMaterializerRoot(t), CellKey: opaqueCellKey(cell),
	})
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := newCaptureLifecycle()
	if err != nil {
		t.Fatal(err)
	}
	executed, err := runRuntimeLibraryLoads(context.Background(), nil, fixture, resolved, lifecycle)
	if err != nil {
		t.Fatal(err)
	}
	if !executed.lifecycleRecorded || executed.analyzer != nil {
		t.Fatalf("runtime execution = %#v, want persisted runtime claim without a static analyzer", executed)
	}
	observation, err := (&ProductionCapture{}).observation(context.Background(), CaptureRequest{
		Cell: cell, Analyzer: RevisionIdentity{ID: AnalyzerSubjectID, Commit: strings.Repeat("a", 40), Tree: strings.Repeat("b", 40)}, Snapshot: captureSnapshot(),
	}, lifecycle, executed)
	if err != nil {
		t.Fatal(err)
	}
	if observation.Outcome != measurement.OutcomeReachable || observation.Positive == nil {
		t.Fatalf("runtime observation = %#v, want reachable positive result", observation)
	}
	if observation.Suppression.Claim != measurement.SuppressionNone {
		t.Fatalf("runtime suppression = %#v, want no suppression", observation.Suppression)
	}
}

func TestProductionCaptureStoresOneCanonicalRuntimeArtifact(t *testing.T) {
	fixtureReference := measurement.ArtifactReference{
		ID:     "runtime-library-loads-input",
		Digest: "sha256:2ea65181344c35516df313a44c68258c348e9d83d07c04cfef98855ae7ebadca",
	}
	cell := ExecutionCell{
		CaseID: "runtime-library-loads-control-positive", CohortID: "runtime", ModeID: "library_loads", BindingID: "runtime", AnalyzerID: "runtime-library-loads",
		Configuration: captureArtifact("configuration"), SubjectID: "pkg:reachbench/runtime/library_loads#controlPositive", Fixture: fixtureReference, BoundaryID: "sca/reachability/runtime/library-loads",
	}
	materializer := newFixtureMaterializer(t, &fixtureToolRunner{}, "linux/amd64")
	capture, err := NewProductionCapture(ProductionCaptureDependencies{Materializer: materializer})
	if err != nil {
		t.Fatal(err)
	}
	rawRoot := t.TempDir()
	evidenceStore, err := benchcycle.NewEvidenceStore(rawRoot, reachabilityEvidenceLimits())
	if err != nil {
		t.Fatal(err)
	}
	workRoot := privateMaterializerRoot(t)
	result, err := capture.Capture(context.Background(), CaptureRequest{
		Cell: cell, Repetition: 1, WorkRoot: workRoot,
		Analyzer: RevisionIdentity{ID: AnalyzerSubjectID, Commit: strings.Repeat("a", 40), Tree: strings.Repeat("b", 40)}, Snapshot: captureSnapshot(),
		attempt: benchcycle.AttemptAddress{CellKey: "runtime-capture", Repetition: 1}, evidence: evidenceStore,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.EvidenceReceipts) != 1 {
		t.Fatalf("evidence receipts = %#v, want exactly one raw artifact", result.EvidenceReceipts)
	}
	receipt := result.EvidenceReceipts[0]
	raw, err := os.ReadFile(filepath.Join(rawRoot, filepath.FromSlash(receipt.Reference)))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), workRoot) {
		t.Fatal("canonical raw artifact included a private materialization root")
	}
	if strings.Contains(string(raw), receipt.Reference) {
		t.Fatalf("canonical raw artifact copied its physical evidence reference %q", receipt.Reference)
	}
	if result.Observation.Outcome != measurement.OutcomeReachable || result.Observation.Suppression.Claim != measurement.SuppressionNone {
		t.Fatalf("runtime capture observation = %#v", result.Observation)
	}
}

func TestProductionCapturePHPAndRubySymbolsKeepDeclarationProvenanceRaiseOnly(t *testing.T) {
	tests := []struct {
		name       string
		fixtureID  string
		cohortID   string
		subjectID  string
		symbolPath string
		line       int
	}{
		{"php", "php-symbols-tier2-input", "php", "pkg:reachbench/php/symbols_tier2#symbolPositive", "fixtures/php/symbols_tier2/main.php", 25},
		{"ruby", "ruby-symbols-tier2-input", "ruby", "pkg:reachbench/ruby/symbols_tier2#symbolPositive", "fixtures/ruby/symbols_tier2/main.rb", 18},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			specification := materializerFixture(t, tt.fixtureID)
			digest, err := measurement.DigestFixtureSpecification(specification)
			if err != nil {
				t.Fatal(err)
			}
			materializer := newFixtureMaterializer(t, &fixtureToolRunner{}, "linux/amd64")
			capture, err := NewProductionCapture(ProductionCaptureDependencies{Materializer: materializer})
			if err != nil {
				t.Fatal(err)
			}
			rawRoot := t.TempDir()
			evidenceStore, err := benchcycle.NewEvidenceStore(rawRoot, reachabilityEvidenceLimits())
			if err != nil {
				t.Fatal(err)
			}
			workRoot := privateMaterializerRoot(t)
			cell := ExecutionCell{
				CaseID: tt.name + "-local-provenance", CohortID: tt.cohortID, ModeID: "symbols_tier2", BindingID: "api", AnalyzerID: "symbols",
				Configuration: captureArtifact("configuration"), SubjectID: tt.subjectID,
				Fixture: measurement.ArtifactReference{ID: specification.ID, Digest: digest}, BoundaryID: "sca/reachability/" + tt.cohortID + "/symbols",
			}
			result, err := capture.Capture(context.Background(), CaptureRequest{
				Cell: cell, Repetition: 1, WorkRoot: workRoot,
				Analyzer: RevisionIdentity{ID: AnalyzerSubjectID, Commit: strings.Repeat("a", 40), Tree: strings.Repeat("b", 40)}, Snapshot: captureSnapshot(),
				attempt: benchcycle.AttemptAddress{CellKey: tt.name + "-local-provenance", Repetition: 1}, evidence: evidenceStore,
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.Observation.Outcome != measurement.OutcomeReachable || result.Observation.Suppression.Claim != measurement.SuppressionNone {
				t.Fatalf("local symbol observation = %#v", result.Observation)
			}
			if len(result.EvidenceReceipts) != 1 {
				t.Fatalf("evidence receipts = %#v", result.EvidenceReceipts)
			}
			raw, err := os.ReadFile(filepath.Join(rawRoot, filepath.FromSlash(result.EvidenceReceipts[0].Reference)))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), workRoot) {
				t.Fatalf("canonical raw evidence leaked private materialization root: %s", raw)
			}
			if !strings.Contains(string(raw), tt.symbolPath) || !strings.Contains(string(raw), fmt.Sprintf("\"Line\":%d", tt.line)) {
				t.Fatalf("canonical raw evidence lost declaration provenance: %s", raw)
			}
		})
	}
}

func captureArtifact(id string) measurement.ArtifactReference {
	return measurement.ArtifactReference{ID: id, Digest: "sha256:" + strings.Repeat("c", 64)}
}

func captureSnapshot() measurement.SnapshotIdentity {
	return measurement.SnapshotIdentity{Source: captureArtifact("source"), SBOM: captureArtifact("sbom"), Run: captureArtifact("run")}
}
