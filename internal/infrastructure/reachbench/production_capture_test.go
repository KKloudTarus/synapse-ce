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
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
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
	target string
}

func (analyzer *captureTestAnalyzer) Analyze(_ context.Context, target string, _ []string) (*reachability.Analysis, error) {
	analyzer.calls++
	analyzer.target = target
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

func TestImportSubjectsRejectsManifestCapabilities(t *testing.T) {
	subjects, err := importSubjects(measurement.ResolvedFixtureSubject{
		Subject: measurement.FixtureSubject{
			ID:      "pkg:pypi/reachbench-unsupported@1.0.0",
			Locator: measurement.FixtureLocator{Kind: measurement.FixtureLocatorManifestCapability},
		},
	}, "pypi")
	if err != nil {
		t.Fatal(err)
	}
	if len(subjects) != 0 {
		t.Fatalf("manifest capability import subjects = %#v, want none", subjects)
	}
}

func TestFixturePackagePURLVersionsScopedNPMIdentity(t *testing.T) {
	for _, testCase := range []struct {
		identity string
		want     string
	}{
		{identity: "npm:@reachbench/lexical", want: "pkg:npm/@reachbench/lexical@benchmark-v1"},
		{identity: "npm:@reachbench/lexical@1.0.0", want: "pkg:npm/@reachbench/lexical@1.0.0"},
		{identity: "pypi:reachbench", want: "pkg:pypi/reachbench@benchmark-v1"},
	} {
		if got := fixturePackagePURL(testCase.identity); got != testCase.want {
			t.Errorf("fixturePackagePURL(%q) = %q, want %q", testCase.identity, got, testCase.want)
		}
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

func TestProductionCaptureMarksGoManifestCapabilityNoCoverageUnsupported(t *testing.T) {
	contract := measurement.DefaultReachabilityBenchmark()
	var cell ExecutionCell
	for _, item := range contract.Corpus.Cases {
		if item.ID != "go-source-tier2-control-no-coverage" {
			continue
		}
		if item.Fixture == nil {
			t.Fatal("frozen Go no-coverage control has no fixture")
		}
		cell = ExecutionCell{
			CaseID: item.ID, CohortID: item.CohortID, ModeID: item.ModeID, BindingID: "api", AnalyzerID: "sca-go-source-tier2",
			Configuration: captureArtifact("configuration"), SubjectID: item.SubjectID, Fixture: *item.Fixture,
			BoundaryID: "sca/reachability/go-source-tier2/api",
		}
		break
	}
	if cell.CaseID == "" {
		t.Fatal("frozen Go no-coverage control is missing")
	}

	capture, err := NewProductionCapture(ProductionCaptureDependencies{
		Materializer: newFixtureMaterializer(t, &fixtureToolRunner{}, "linux/amd64"),
	})
	if err != nil {
		t.Fatal(err)
	}
	evidenceStore, err := benchcycle.NewEvidenceStore(t.TempDir(), reachabilityEvidenceLimits())
	if err != nil {
		t.Fatal(err)
	}
	result, err := capture.Capture(context.Background(), CaptureRequest{
		Cell: cell, Repetition: 1, WorkRoot: privateMaterializerRoot(t),
		Analyzer: RevisionIdentity{ID: AnalyzerSubjectID, Commit: measurement.TrustedBaselineRevision, Tree: strings.Repeat("b", 40)},
		Snapshot: captureSnapshot(), attempt: benchcycle.AttemptAddress{CellKey: "go-manifest-capability", Repetition: 1}, evidence: evidenceStore,
	})
	if err != nil {
		t.Fatal(err)
	}
	coverage := result.Observation.Coverage
	if !result.Observation.Invoked || result.Observation.Outcome != measurement.OutcomeNoAnalysis ||
		coverage.Status != measurement.CoverageUnavailable || len(coverage.Reasons) != 1 || coverage.Reasons[0].Code != measurement.CoverageReasonUnsupported {
		t.Fatalf("Go manifest capability observation = %#v, want invoked unsupported no-analysis", result.Observation)
	}
	if result.Observation.Suppression.Claim != measurement.SuppressionNone || len(result.EvidenceReceipts) != 1 {
		t.Fatalf("Go manifest capability capture = %#v", result)
	}
}

func TestProductionCaptureExercisesJavaScriptLexicalDependency(t *testing.T) {
	contract := measurement.DefaultReachabilityBenchmark()
	cases := make(map[string]measurement.ContractCase)
	for _, item := range contract.Corpus.Cases {
		if item.CohortID == "javascript" && item.ModeID == "lexical" {
			cases[item.ID] = item
		}
	}
	capture, err := NewProductionCapture(ProductionCaptureDependencies{
		Materializer: newFixtureMaterializer(t, &fixtureToolRunner{}, "linux/amd64"),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, testCase := range []struct {
		caseID   string
		outcome  measurement.Outcome
		coverage measurement.CoverageStatus
	}{
		{caseID: "javascript-lexical-control-no-coverage", outcome: measurement.OutcomeNoAnalysis, coverage: measurement.CoverageUnavailable},
		{caseID: "javascript-lexical-control-opaque", outcome: measurement.OutcomeConditionallyReachable, coverage: measurement.CoveragePartial},
		{caseID: "javascript-lexical-control-positive", outcome: measurement.OutcomeReachable, coverage: measurement.CoverageComplete},
		{caseID: "javascript-lexical-control-unreachable", outcome: measurement.OutcomePresentUnreached, coverage: measurement.CoverageComplete},
	} {
		t.Run(testCase.caseID, func(t *testing.T) {
			item, ok := cases[testCase.caseID]
			if !ok || item.Fixture == nil {
				t.Fatalf("frozen lexical case %q is missing", testCase.caseID)
			}
			evidenceStore, storeErr := benchcycle.NewEvidenceStore(t.TempDir(), reachabilityEvidenceLimits())
			if storeErr != nil {
				t.Fatal(storeErr)
			}
			result, captureErr := capture.Capture(context.Background(), CaptureRequest{
				Cell: ExecutionCell{
					CaseID: item.ID, CohortID: item.CohortID, ModeID: item.ModeID, BindingID: "api",
					AnalyzerID: "sca-javascript-symbol-tier2", Configuration: captureArtifact("configuration"),
					SubjectID: item.SubjectID, Fixture: *item.Fixture, BoundaryID: "sca/reachability/javascript-symbol-tier2/api",
				},
				Repetition: 1, WorkRoot: privateMaterializerRoot(t),
				Analyzer: RevisionIdentity{ID: AnalyzerSubjectID, Commit: measurement.TrustedBaselineRevision, Tree: strings.Repeat("b", 40)},
				Snapshot: captureSnapshot(), attempt: benchcycle.AttemptAddress{CellKey: testCase.caseID, Repetition: 1}, evidence: evidenceStore,
			})
			if captureErr != nil {
				t.Fatal(captureErr)
			}
			if result.Observation.Outcome != testCase.outcome || result.Observation.Coverage.Status != testCase.coverage {
				t.Fatalf("observation = %#v, want outcome %q coverage %q", result.Observation, testCase.outcome, testCase.coverage)
			}
			if result.Observation.Suppression.Claim != measurement.SuppressionNone || len(result.Observation.Suppression.Effects) != 0 {
				t.Fatalf("lexical suppression = %#v, want none", result.Observation.Suppression)
			}
		})
	}
}

func TestCoverageFromRecordedAnalysisUsesSubjectEvidence(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		requested []string
		analysis  *reachability.Analysis
		status    measurement.CoverageStatus
		reason    measurement.CoverageReasonCode
	}{
		{
			name:      "all requested symbols answered",
			requested: []string{"first", "second"},
			analysis:  &reachability.Analysis{Results: []reachability.Result{{Symbol: "first"}, {Symbol: "second"}}},
			status:    measurement.CoverageComplete,
		},
		{
			name:      "some requested symbols answered",
			requested: []string{"first", "second"},
			analysis:  &reachability.Analysis{Results: []reachability.Result{{Symbol: "first"}}},
			status:    measurement.CoveragePartial,
			reason:    measurement.CoverageReasonUnknown,
		},
		{
			name:      "no requested symbols answered",
			requested: []string{"subject"},
			analysis:  &reachability.Analysis{},
			status:    measurement.CoverageUnavailable,
			reason:    measurement.CoverageReasonUnknown,
		},
		{
			name:      "analysis blind construct establishes partial coverage",
			requested: []string{"subject"},
			analysis:  &reachability.Analysis{BlindConstructs: []string{"reflection"}},
			status:    measurement.CoveragePartial,
			reason:    measurement.CoverageReasonOpaque,
		},
		{
			name:      "relevant result blind construct establishes partial coverage",
			requested: []string{"subject"},
			analysis:  &reachability.Analysis{Results: []reachability.Result{{Symbol: "subject", BlindConstructs: []string{"dynamic dispatch"}}}},
			status:    measurement.CoveragePartial,
			reason:    measurement.CoverageReasonOpaque,
		},
		{
			name:      "relevant unknown marker establishes partial coverage",
			requested: []string{"subject"},
			analysis:  &reachability.Analysis{Results: []reachability.Result{{Symbol: "subject", Path: []string{"coverage:unknown"}}}},
			status:    measurement.CoveragePartial,
			reason:    measurement.CoverageReasonUnknown,
		},
		{
			name:      "unrelated blind result does not answer the subject",
			requested: []string{"subject"},
			analysis:  &reachability.Analysis{Results: []reachability.Result{{Symbol: "other", BlindConstructs: []string{"reflection"}}}},
			status:    measurement.CoverageUnavailable,
			reason:    measurement.CoverageReasonUnknown,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			coverage := coverageFromRecordedAnalysis(testCase.requested, testCase.analysis, coverageAnswersRequestedSymbols)
			if coverage.Status != testCase.status {
				t.Fatalf("coverage status = %q, want %q", coverage.Status, testCase.status)
			}
			if testCase.reason == "" {
				if len(coverage.Reasons) != 0 {
					t.Fatalf("coverage reasons = %#v, want none", coverage.Reasons)
				}
				return
			}
			if len(coverage.Reasons) != 1 || coverage.Reasons[0].Code != testCase.reason {
				t.Fatalf("coverage reasons = %#v, want %q", coverage.Reasons, testCase.reason)
			}
		})
	}
}

func TestOutcomeFromRecordedAnalysisSeparatesMeasurementFromJudgments(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		coverage measurement.ObservedCoverage
		analysis *reachability.Analysis
		want     measurement.Outcome
	}{
		{name: "reachable", coverage: completeCoverage(), analysis: &reachability.Analysis{Results: []reachability.Result{{Symbol: "subject", Reachable: true}}}, want: measurement.OutcomeReachable},
		{name: "reachable with partial coverage", coverage: partialCoverage(measurement.CoverageReasonOpaque), analysis: &reachability.Analysis{Results: []reachability.Result{{Symbol: "subject", Reachable: true, BlindConstructs: []string{"dynamic dispatch"}}}}, want: measurement.OutcomeConditionallyReachable},
		{name: "reachable with unknown path", coverage: partialCoverage(measurement.CoverageReasonUnknown), analysis: &reachability.Analysis{Results: []reachability.Result{{Symbol: "subject", Reachable: true, Path: []string{"coverage:unknown"}}}}, want: measurement.OutcomeConditionallyReachable},
		{name: "complete negative measurement", coverage: completeCoverage(), analysis: &reachability.Analysis{Results: []reachability.Result{{Symbol: "subject"}}}, want: measurement.OutcomePresentUnreached},
		{name: "partial negative measurement", coverage: partialCoverage(measurement.CoverageReasonOpaque), analysis: &reachability.Analysis{Results: []reachability.Result{{Symbol: "subject"}}}, want: measurement.OutcomeConditionallyReachable},
		{name: "unavailable measurement", coverage: unavailableCoverage(measurement.CoverageReasonFailed), want: measurement.OutcomeNoAnalysis},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := outcomeFromRecordedAnalysis(testCase.coverage, testCase.analysis); got != testCase.want {
				t.Fatalf("outcome = %q, want %q", got, testCase.want)
			}
		})
	}
}

func TestCallGraphCoverageRequiresEntrypointAuthority(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		requirement analysisCoverageRequirement
		analysis    *reachability.Analysis
		status      measurement.CoverageStatus
		reason      measurement.CoverageReasonCode
	}{
		{
			name:        "Tier-2 call graph without entrypoints is unavailable",
			requirement: coverageRequiresEntrypointAuthority,
			analysis:    &reachability.Analysis{Results: []reachability.Result{{Symbol: "subject"}}},
			status:      measurement.CoverageUnavailable,
			reason:      measurement.CoverageReasonUnknown,
		},
		{
			name:        "Tier-2 call graph with recorded entrypoints is complete",
			requirement: coverageRequiresEntrypointAuthority,
			analysis:    &reachability.Analysis{Entrypoints: []string{"main.main"}, Results: []reachability.Result{{Symbol: "subject"}}},
			status:      measurement.CoverageComplete,
		},
		{
			name:        "Tier-1 import analysis does not require entrypoints",
			requirement: coverageAnswersRequestedSymbols,
			analysis:    &reachability.Analysis{Results: []reachability.Result{{Symbol: "subject"}}},
			status:      measurement.CoverageComplete,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			coverage := coverageFromRecordedAnalysis([]string{"subject"}, testCase.analysis, testCase.requirement)
			if coverage.Status != testCase.status {
				t.Fatalf("coverage status = %q, want %q", coverage.Status, testCase.status)
			}
			if testCase.reason == "" {
				if len(coverage.Reasons) != 0 {
					t.Fatalf("coverage reasons = %#v, want none", coverage.Reasons)
				}
				return
			}
			if len(coverage.Reasons) != 1 || coverage.Reasons[0].Code != testCase.reason {
				t.Fatalf("coverage reasons = %#v, want %q", coverage.Reasons, testCase.reason)
			}
		})
	}
}

func TestRunStaticWithNoSubjectsReportsUnsupportedCoverage(t *testing.T) {
	lifecycle, err := newCaptureLifecycle()
	if err != nil {
		t.Fatal(err)
	}
	called := false
	executed, err := runStatic(context.Background(), MaterializedFixture{Root: "/private/fixture"}, measurement.ResolvedFixtureSubject{}, lifecycle, coverageAnswersRequestedSymbols, nil,
		func() (staticAnalyzer, error) {
			called = true
			return &captureTestAnalyzer{}, nil
		},
		func(staticAnalyzer) (*reachproof.Coordinator, error) {
			return nil, errors.New("coordinator must not be constructed")
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if called || !executed.invoked || executed.coverage.Status != measurement.CoverageUnavailable || len(executed.coverage.Reasons) != 1 || executed.coverage.Reasons[0].Code != measurement.CoverageReasonUnsupported {
		t.Fatalf("zero-subject static execution = %#v, analyzer called = %t", executed, called)
	}
}

func TestRunStaticTargetsMetadataDerivedAnalysisRoot(t *testing.T) {
	root := t.TempDir()
	analysisRoot := filepath.Join(root, "fixtures", "go", "app")
	if err := os.MkdirAll(analysisRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"main.go", "go.mod"} {
		if err := os.WriteFile(filepath.Join(analysisRoot, name), []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fixture := MaterializedFixture{
		Root: root,
		Specification: measurement.FixtureSpecification{Entries: []measurement.FixtureEntry{
			{Path: "fixtures/go/app/main.go"}, {Path: "fixtures/go/app/go.mod"},
		}},
		inputPaths: map[string]string{
			"fixtures/go/app/main.go": "fixtures/go/app/main.go",
			"fixtures/go/app/go.mod":  "fixtures/go/app/go.mod",
		},
	}
	lifecycle, err := newCaptureLifecycle()
	if err != nil {
		t.Fatal(err)
	}
	delegate := &captureTestAnalyzer{result: &reachability.Analysis{Results: []reachability.Result{{Symbol: "target"}}}}
	_, err = runStatic(context.Background(), fixture, measurement.ResolvedFixtureSubject{}, lifecycle, coverageAnswersRequestedSymbols,
		[]ports.ReachabilitySubject{{FindingID: "finding", Symbols: []string{"target"}}},
		func() (staticAnalyzer, error) { return delegate, nil },
		func(analyzer staticAnalyzer) (*reachproof.Coordinator, error) {
			coordinator, err := reachproof.NewCoordinator(analyzer, lifecycle.judgments, lifecycle.audit, lifecycle.clock)
			if err != nil {
				return nil, err
			}
			return coordinator.WithRaiseOnly(), nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if delegate.target != analysisRoot {
		t.Fatalf("static analysis target = %q, want nested metadata root %q", delegate.target, analysisRoot)
	}
}

func TestGoSourceTier2SubjectsUseCallGraphIdentity(t *testing.T) {
	resolved := measurement.ResolvedFixtureSubject{Subject: measurement.FixtureSubject{
		ID:              "pkg:reachbench/go/source_tier2#controlOpaque",
		PackageIdentity: "example.invalid/reachbench/go-source-tier2",
		Locator: measurement.FixtureLocator{
			Kind:   measurement.FixtureLocatorSourceSymbol,
			Symbol: "controlOpaque",
		},
	}}
	subjects := goSourceTier2Subjects(resolved)
	if len(subjects) != 1 || len(subjects[0].Symbols) != 1 {
		t.Fatalf("Go source subjects = %#v", subjects)
	}
	if got, want := subjects[0].Symbols[0], "example.invalid/reachbench/go-source-tier2.controlOpaque"; got != want {
		t.Fatalf("Go source symbol = %q, want %q", got, want)
	}
}

func TestSymbolSubjectsRejectManifestCapabilityLocator(t *testing.T) {
	manifest := measurement.ResolvedFixtureSubject{Subject: measurement.FixtureSubject{
		ID:      "pkg:reachbench/javascript/lexical#controlNoCoverage",
		Locator: measurement.FixtureLocator{Kind: measurement.FixtureLocatorManifestCapability, Symbol: "parser-unavailable"},
	}}
	if subjects := symbolSubjects(manifest); len(subjects) != 0 {
		t.Fatalf("manifest capability subjects = %#v, want none", subjects)
	}
	source := manifest
	source.Subject.Locator.Kind = measurement.FixtureLocatorSourceSymbol
	if subjects := symbolSubjects(source); len(subjects) != 1 || len(subjects[0].Symbols) != 1 || subjects[0].Symbols[0] != "parser-unavailable" {
		t.Fatalf("source symbol subjects = %#v", subjects)
	}
}

func TestJVMCoarseCoverageDoesNotTreatUnreferencedAsDeadCode(t *testing.T) {
	if coverage := jvmCoarseCoverage(measurement.FixtureLocatorManifestCapability, sbom.ReachabilityReachable); coverage.Status != measurement.CoverageUnavailable || coverage.Reasons[0].Code != measurement.CoverageReasonUnsupported {
		t.Fatalf("manifest capability coverage = %#v", coverage)
	}
	if coverage := jvmCoarseCoverage(measurement.FixtureLocatorPackageDependency, sbom.ReachabilityReachable); coverage.Status != measurement.CoverageComplete {
		t.Fatalf("reachable JVM coarse coverage = %#v", coverage)
	}
	if coverage := jvmCoarseCoverage(measurement.FixtureLocatorPackageDependency, sbom.ReachabilityUnreferenced); coverage.Status != measurement.CoveragePartial || coverage.Reasons[0].Code != measurement.CoverageReasonOpaque {
		t.Fatalf("unreferenced JVM coarse coverage = %#v", coverage)
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

func TestProductionCaptureMeasuresNegativeWithoutPersistingSuppression(t *testing.T) {
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
	executed, err := runStatic(context.Background(), MaterializedFixture{Root: t.TempDir()}, resolved, lifecycle, coverageRequiresEntrypointAuthority,
		[]ports.ReachabilitySubject{{FindingID: shared.ID(resolved.Subject.ID), Symbols: []string{"controlUnreachable"}}},
		func() (staticAnalyzer, error) { return delegate, nil },
		func(analyzer staticAnalyzer) (*reachproof.Coordinator, error) {
			coordinator, coordinatorErr := reachproof.NewCoordinator(analyzer, lifecycle.judgments, lifecycle.audit, lifecycle.clock)
			if coordinatorErr != nil {
				return nil, coordinatorErr
			}
			return coordinator.WithRaiseOnly(), nil
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
		t.Fatalf("suppression = %#v, want no fabricated downstream effect", observation.Suppression)
	}
	judgments, err := lifecycle.judgments.List(context.Background(), productionCaptureEngagementID)
	if err != nil {
		t.Fatal(err)
	}
	claims := judgment.WinningReachabilityClaims(judgments)
	if winner, ok := claims[cell.SubjectID]; ok {
		t.Fatalf("persisted winner = %#v, want no negative benchmark judgment", winner)
	}
}

func TestProductionCaptureKeepsReachablePartialOutcomeConditional(t *testing.T) {
	lifecycle, err := newCaptureLifecycle()
	if err != nil {
		t.Fatal(err)
	}
	resolved := measurement.ResolvedFixtureSubject{Subject: measurement.FixtureSubject{
		ID:              "pkg:reachbench/go/source_tier2#controlOpaque",
		PackageIdentity: "example.invalid/reachbench/go-source-tier2",
		Locator:         measurement.FixtureLocator{Kind: measurement.FixtureLocatorSourceSymbol, Symbol: "controlOpaque"},
	}}
	symbol := "example.invalid/reachbench/go-source-tier2.controlOpaque"
	delegate := &captureTestAnalyzer{result: &reachability.Analysis{
		Results:     []reachability.Result{{Symbol: symbol, Reachable: true, BlindConstructs: []string{"dynamic_dispatch"}}},
		Entrypoints: []string{"example.invalid/reachbench/go-source-tier2.main"},
	}}
	executed, err := runStatic(context.Background(), MaterializedFixture{Root: t.TempDir()}, resolved, lifecycle, coverageRequiresEntrypointAuthority,
		[]ports.ReachabilitySubject{{FindingID: shared.ID(resolved.Subject.ID), Symbols: []string{symbol}}},
		func() (staticAnalyzer, error) { return delegate, nil },
		func(analyzer staticAnalyzer) (*reachproof.Coordinator, error) {
			coordinator, coordinatorErr := reachproof.NewCoordinator(analyzer, lifecycle.judgments, lifecycle.audit, lifecycle.clock)
			if coordinatorErr != nil {
				return nil, coordinatorErr
			}
			return coordinator.WithRaiseOnly(), nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	cell := ExecutionCell{
		CaseID: "go-opaque", CohortID: "go", ModeID: "source_tier2", BindingID: "api", AnalyzerID: "sca-go-source-tier2",
		Configuration: captureArtifact("configuration"), SubjectID: resolved.Subject.ID, Fixture: captureArtifact("fixture"), BoundaryID: "sca/reachability/go-source-tier2/api",
	}
	observation, err := (&ProductionCapture{}).observation(context.Background(), CaptureRequest{
		Cell: cell, Analyzer: RevisionIdentity{ID: AnalyzerSubjectID, Commit: strings.Repeat("a", 40), Tree: strings.Repeat("b", 40)}, Snapshot: captureSnapshot(),
	}, lifecycle, executed)
	if err != nil {
		t.Fatal(err)
	}
	if observation.Outcome != measurement.OutcomeConditionallyReachable || observation.Coverage.Status != measurement.CoveragePartial {
		t.Fatalf("opaque observation = %#v, want conditionally_reachable with partial coverage", observation)
	}
	if observation.Positive == nil {
		t.Fatal("affirmative opaque result must retain positive evidence")
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
		ID: "pkg:reachbench/go/source_tier2#controlPositive", Locator: measurement.FixtureLocator{Symbol: "controlPositive"},
	}}
	executed, err := runStatic(context.Background(), MaterializedFixture{Root: t.TempDir()}, resolved, lifecycle, coverageRequiresEntrypointAuthority,
		[]ports.ReachabilitySubject{{FindingID: shared.ID(resolved.Subject.ID), Symbols: []string{"controlPositive"}}},
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
