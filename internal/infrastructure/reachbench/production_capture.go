package reachbench

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/jssymbols"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/runtimereach"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/symbolcanon"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/benchcycle"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	asttool "github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ast"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/dotnetreach"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/gobinreach"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/jsimports"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/jsresolve"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/jvmreach"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/pyimports"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/srcimports"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/taintcallgraph"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/analysis"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/jsreach"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/nugetreach"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/pyreach"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachability"
	measurement "github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachproof"
	runtimeusecase "github.com/KKloudTarus/synapse-ce/internal/usecase/runtimereach"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/rustsymreach"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/srcreach"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/symreach"
)

const productionCaptureEngagementID shared.ID = "reachbench-production-capture"

// fixtureMaterializer is deliberately no wider than the verified fixture boundary
// ProductionCapture needs. It lets tests exercise the adapter without a toolchain.
type fixtureMaterializer interface {
	Materialize(context.Context, FixtureMaterializationRequest) (MaterializedFixture, error)
}

// semanticFactsProvider is the shared production synapse-ast surface needed by
// the Python and JavaScript semantic modes.
type semanticFactsProvider interface {
	ports.PythonFactsProvider
	ports.JsFactsProvider
}

// ProductionCaptureDependencies are trusted package-owned construction inputs.
// They carry helper locations, never target-derived values.
type ProductionCaptureDependencies struct {
	Materializer             fixtureMaterializer
	Fixtures                 measurement.FixtureManifest
	CallGraphBinary          string
	ASTBinary                string
	SemanticFacts            semanticFactsProvider
	JVMPointsTo              bool
	EnableJSLexicalNegatives bool
}

// ProductionCapture runs the frozen corpus through the same analyzers and
// judgment/evidence coordinators used by production composition.
type ProductionCapture struct {
	materializer             fixtureMaterializer
	fixtures                 measurement.FixtureManifest
	callGraphBinary          string
	facts                    semanticFactsProvider
	jvmPointsTo              bool
	enableJSLexicalNegatives bool
	modes                    map[string]productionMode
}

type productionMode func(context.Context, *ProductionCapture, MaterializedFixture, measurement.ResolvedFixtureSubject, captureLifecycle) (execution, error)

type execution struct {
	invoked           bool
	coverage          measurement.ObservedCoverage
	analyzer          *recordingAnalyzer
	analyzerError     error
	lifecycleRecorded bool
	outcome           *measurement.Outcome
	detail            string
}

// NewProductionCapture validates a closed registry of the frozen production
// analyzer forms. An unregistered or newly added cohort/mode must fail closed.
func NewProductionCapture(dependencies ProductionCaptureDependencies) (*ProductionCapture, error) {
	if dependencies.Materializer == nil {
		return nil, errors.New("reachability production capture requires a fixture materializer")
	}
	fixtures := dependencies.Fixtures
	if fixtures.ID == "" {
		fixtures = measurement.DefaultFixtureManifest()
	}
	if err := fixtures.Validate(); err != nil {
		return nil, fmt.Errorf("validate production capture fixtures: %w", err)
	}
	facts := dependencies.SemanticFacts
	if facts == nil {
		facts = asttool.New(dependencies.ASTBinary)
	}
	capture := &ProductionCapture{
		materializer:             dependencies.Materializer,
		fixtures:                 fixtures,
		callGraphBinary:          dependencies.CallGraphBinary,
		facts:                    facts,
		jvmPointsTo:              dependencies.JVMPointsTo,
		enableJSLexicalNegatives: dependencies.EnableJSLexicalNegatives,
	}
	capture.modes = capture.productionModes()
	if err := validateProductionModes(capture.modes); err != nil {
		return nil, err
	}
	return capture, nil
}

var _ CaptureAdapter = (*ProductionCapture)(nil)

func (capture *ProductionCapture) productionModes() map[string]productionMode {
	return map[string]productionMode{
		"go\x00source_tier2":            runGoSourceTier2,
		"go\x00binary":                  runGoBinary,
		"python\x00import":              runPythonImport,
		"python\x00semantic":            runPythonSemantic,
		"javascript\x00import":          runJavaScriptImport,
		"javascript\x00lexical":         runJavaScriptLexical,
		"javascript\x00interprocedural": runJavaScriptInterprocedural,
		"rust\x00import":                runRustImport,
		"rust\x00symbols_tier2":         runRustSymbols,
		"php\x00import":                 runPHPImport,
		"php\x00symbols_tier2":          runPHPSymbols,
		"ruby\x00import":                runRubyImport,
		"ruby\x00symbols_tier2":         runRubySymbols,
		"dotnet\x00build_aware_import":  runDotNetImport,
		"dotnet\x00symbols_tier2":       runDotNetSymbols,
		"c_cpp\x00symbols_tier2":        runCPPSymbols,
		"jvm\x00coarse":                 runJVMCoarse,
		"jvm\x00tier2":                  runJVMTier2,
		"runtime\x00library_loads":      runRuntimeLibraryLoads,
	}
}

func validateProductionModes(modes map[string]productionMode) error {
	expected := []string{
		"go\x00source_tier2", "go\x00binary", "python\x00import", "python\x00semantic",
		"javascript\x00import", "javascript\x00lexical", "javascript\x00interprocedural",
		"rust\x00import", "rust\x00symbols_tier2", "php\x00import", "php\x00symbols_tier2",
		"ruby\x00import", "ruby\x00symbols_tier2", "dotnet\x00build_aware_import",
		"dotnet\x00symbols_tier2", "c_cpp\x00symbols_tier2", "jvm\x00coarse", "jvm\x00tier2",
		"runtime\x00library_loads",
	}
	if len(modes) != len(expected) {
		return fmt.Errorf("production capture registry has %d modes, want %d", len(modes), len(expected))
	}
	for _, key := range expected {
		if modes[key] == nil {
			return fmt.Errorf("production capture registry lacks %q", strings.ReplaceAll(key, "\x00", "/"))
		}
	}
	for key := range modes {
		found := false
		for _, expectedKey := range expected {
			if key == expectedKey {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("production capture registry has unexpected %q", strings.ReplaceAll(key, "\x00", "/"))
		}
	}
	return nil
}

// Capture materializes the exact fixture identity carried by the cell. It does
// not consult the benchmark oracle, expected outcome, or category labels.
func (capture *ProductionCapture) Capture(ctx context.Context, request CaptureRequest) (CaptureResult, error) {
	if ctx == nil {
		return CaptureResult{}, errors.New("production reachability capture requires a context")
	}
	if err := validateCaptureCell(request.Cell); err != nil {
		return CaptureResult{}, err
	}
	mode, ok := capture.modes[request.Cell.CohortID+"\x00"+request.Cell.ModeID]
	if !ok {
		return CaptureResult{}, fmt.Errorf("production capture does not support %s/%s", request.Cell.CohortID, request.Cell.ModeID)
	}
	resolved, err := capture.fixtures.ResolveFixtureSubject(request.Cell.Fixture, request.Cell.SubjectID)
	if err != nil {
		return CaptureResult{}, fmt.Errorf("resolve production capture fixture subject: %w", err)
	}
	fixture, err := capture.materializer.Materialize(ctx, FixtureMaterializationRequest{
		Specification: resolved.Specification,
		WorkRoot:      request.WorkRoot,
		CellKey:       opaqueCellKey(request.Cell),
	})
	if err != nil {
		return CaptureResult{}, fmt.Errorf("materialize production capture fixture: %w", err)
	}
	if strings.TrimSpace(fixture.Root) == "" {
		return CaptureResult{}, errors.New("materialized production capture fixture has no root")
	}
	lifecycle, err := newCaptureLifecycle()
	if err != nil {
		return CaptureResult{}, err
	}
	executed, err := mode(ctx, capture, fixture, resolved, lifecycle)
	if err != nil {
		return CaptureResult{}, fmt.Errorf("capture %s/%s: %w", request.Cell.CohortID, request.Cell.ModeID, err)
	}
	observation, err := capture.observation(ctx, request, lifecycle, executed)
	if err != nil {
		return CaptureResult{}, err
	}
	raw, err := capture.rawEvidence(request, fixture, resolved, executed, observation)
	if err != nil {
		return CaptureResult{}, err
	}
	receipt, err := request.StoreRawEvidence(ctx, bytes.NewReader(raw))
	if err != nil {
		return CaptureResult{}, fmt.Errorf("store production capture raw evidence: %w", err)
	}
	return CaptureResult{Observation: observation, EvidenceReceipts: []benchcycle.EvidenceReceipt{receipt}}, nil
}

func validateCaptureCell(cell ExecutionCell) error {
	for _, named := range []struct{ name, value string }{
		{"case", cell.CaseID}, {"cohort", cell.CohortID}, {"mode", cell.ModeID}, {"binding", cell.BindingID},
		{"analyzer", cell.AnalyzerID}, {"subject", cell.SubjectID}, {"boundary", cell.BoundaryID},
	} {
		if strings.TrimSpace(named.value) == "" {
			return fmt.Errorf("production capture cell has blank %s identity", named.name)
		}
	}
	if strings.TrimSpace(cell.Fixture.ID) == "" || strings.TrimSpace(cell.Fixture.Digest) == "" {
		return errors.New("production capture cell has no fixture identity")
	}
	if strings.TrimSpace(cell.Configuration.ID) == "" || strings.TrimSpace(cell.Configuration.Digest) == "" {
		return errors.New("production capture cell has no configuration identity")
	}
	return nil
}

type analysisCoverageRequirement uint8

const (
	coverageAnswersRequestedSymbols analysisCoverageRequirement = iota
	coverageRequiresEntrypointAuthority
)

func runStatic(
	ctx context.Context,
	fixture MaterializedFixture,
	resolved measurement.ResolvedFixtureSubject,
	lifecycle captureLifecycle,
	requirement analysisCoverageRequirement,
	subjects []ports.ReachabilitySubject,
	newAnalyzer func() (staticAnalyzer, error),
	newCoordinator func(staticAnalyzer) (*reachproof.Coordinator, error),
) (execution, error) {
	if len(subjects) == 0 {
		return execution{invoked: true, coverage: unavailableCoverage(measurement.CoverageReasonUnsupported)}, nil
	}
	delegate, err := newAnalyzer()
	if err != nil {
		return execution{}, err
	}
	recording := &recordingAnalyzer{delegate: delegate, materializedRoot: fixture.Root}
	coordinator, err := newCoordinator(recording)
	if err != nil {
		return execution{}, err
	}
	_, recordErr := coordinator.Record(ctx, productionCaptureEngagementID, fixture.Root, subjects)
	if recordErr != nil {
		if recording.err != nil {
			return execution{invoked: true, coverage: unavailableCoverage(measurement.CoverageReasonFailed), analyzer: recording, analyzerError: recording.err}, nil
		}
		return execution{}, fmt.Errorf("record production judgment: %w", recordErr)
	}
	return execution{invoked: true, coverage: coverageFromRecordedAnalysis(recording.symbols, recording.result, requirement), analyzer: recording}, nil
}

type staticAnalyzer interface {
	Analyze(context.Context, string, []string) (*reachability.Analysis, error)
}

var errNilAnalyzerResult = errors.New("production analyzer returned a nil result")

type recordingAnalyzer struct {
	delegate         staticAnalyzer
	materializedRoot string
	calls            int
	symbols          []string
	result           *reachability.Analysis
	err              error
}

func (analyzer *recordingAnalyzer) Analyze(ctx context.Context, target string, subjects []string) (*reachability.Analysis, error) {
	if analyzer.calls != 0 {
		return nil, errors.New("production capture analyzer invoked more than once")
	}
	analyzer.calls++
	analyzer.symbols = append([]string(nil), subjects...)
	result, err := analyzer.delegate.Analyze(ctx, target, subjects)
	if err == nil && result == nil {
		err = errNilAnalyzerResult
	}
	analyzer.err = err
	if err != nil {
		return result, err
	}
	analyzer.result = normalizeAnalysisPaths(result, analyzer.materializedRoot)
	return analyzer.result, nil
}

func normalizeAnalysisPaths(result *reachability.Analysis, root string) *reachability.Analysis {
	if result == nil {
		return nil
	}
	copyResult := *result
	copyResult.Entrypoints = normalizePathStrings(result.Entrypoints, root)
	copyResult.Results = make([]reachability.Result, len(result.Results))
	for index, item := range result.Results {
		copyResult.Results[index] = item
		copyResult.Results[index].Path = normalizePathStrings(item.Path, root)
	}
	return &copyResult
}

// coverageFromRecordedAnalysis derives the measured coverage only from the symbols the
// analyzer received and the analysis it returned. It never consults benchmark labels.
func coverageFromRecordedAnalysis(requested []string, analysis *reachability.Analysis, requirement analysisCoverageRequirement) measurement.ObservedCoverage {
	requestedSymbols := make(map[string]struct{}, len(requested))
	for _, symbol := range requested {
		symbol = strings.TrimSpace(symbol)
		if symbol != "" {
			requestedSymbols[symbol] = struct{}{}
		}
	}
	if len(requestedSymbols) == 0 {
		return unavailableCoverage(measurement.CoverageReasonUnsupported)
	}
	if analysis == nil {
		return unavailableCoverage(measurement.CoverageReasonFailed)
	}

	if requirement == coverageRequiresEntrypointAuthority && !hasNonblank(analysis.Entrypoints) {
		return unavailableCoverage(measurement.CoverageReasonUnknown)
	}

	answered := make(map[string]struct{}, len(requestedSymbols))
	blind := hasNonblank(analysis.BlindConstructs)
	unknown := containsCoverageUnknown(analysis.Entrypoints)
	for _, result := range analysis.Results {
		symbol := strings.TrimSpace(result.Symbol)
		if _, requested := requestedSymbols[symbol]; !requested {
			continue
		}
		answered[symbol] = struct{}{}
		blind = blind || hasNonblank(result.BlindConstructs)
		unknown = unknown || containsCoverageUnknown(result.Path)
	}
	switch {
	case blind:
		return partialCoverage(measurement.CoverageReasonOpaque)
	case unknown:
		return partialCoverage(measurement.CoverageReasonUnknown)
	case len(answered) == len(requestedSymbols):
		return completeCoverage()
	case len(answered) > 0:
		return partialCoverage(measurement.CoverageReasonUnknown)
	default:
		return unavailableCoverage(measurement.CoverageReasonUnknown)
	}
}

func hasNonblank(values []string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

func containsCoverageUnknown(values []string) bool {
	for _, value := range values {
		if strings.Contains(value, "coverage:unknown") {
			return true
		}
	}
	return false
}

func normalizePathStrings(values []string, root string) []string {
	out := make([]string, len(values))
	for index, value := range values {
		out[index] = strings.ReplaceAll(value, root, "fixture://root")
	}
	return out
}

func completeCoverage() measurement.ObservedCoverage {
	return measurement.ObservedCoverage{
		Status:      measurement.CoverageComplete,
		Obligations: []measurement.CoverageObligation{{ID: "production-analysis", Status: measurement.CoverageComplete}},
	}
}

func unavailableCoverage(reason measurement.CoverageReasonCode) measurement.ObservedCoverage {
	return measurement.ObservedCoverage{
		Status:      measurement.CoverageUnavailable,
		Obligations: []measurement.CoverageObligation{{ID: "production-analysis", Status: measurement.CoverageUnavailable}},
		Reasons:     []measurement.CoverageReason{{Code: reason}},
	}
}

func partialCoverage(reason measurement.CoverageReasonCode) measurement.ObservedCoverage {
	return measurement.ObservedCoverage{
		Status:      measurement.CoveragePartial,
		Obligations: []measurement.CoverageObligation{{ID: "production-analysis", Status: measurement.CoveragePartial}},
		Reasons:     []measurement.CoverageReason{{Code: reason}},
	}
}

func runGoSourceTier2(ctx context.Context, capture *ProductionCapture, fixture MaterializedFixture, resolved measurement.ResolvedFixtureSubject, lifecycle captureLifecycle) (execution, error) {
	subjects := symbolSubjects(resolved)
	return runStatic(ctx, fixture, resolved, lifecycle, coverageRequiresEntrypointAuthority, subjects,
		func() (staticAnalyzer, error) {
			return reachability.NewService(taintcallgraph.New(capture.callGraphBinary))
		},
		func(analyzer staticAnalyzer) (*reachproof.Coordinator, error) {
			return reachproof.NewCoordinator(analyzer, lifecycle.judgments, lifecycle.audit, lifecycle.clock)
		},
	)
}

func runPythonImport(ctx context.Context, _ *ProductionCapture, fixture MaterializedFixture, resolved measurement.ResolvedFixtureSubject, lifecycle captureLifecycle) (execution, error) {
	subjects, err := importSubjects(resolved, "pypi")
	if err != nil {
		return execution{}, err
	}
	return runStatic(ctx, fixture, resolved, lifecycle, coverageAnswersRequestedSymbols, subjects,
		func() (staticAnalyzer, error) {
			return pyreach.New(pyimports.New(), func(ctx context.Context, dir string) (map[string]bool, bool) {
				return srcimports.DirectDependencies(ctx, dir, "pypi")
			})
		},
		func(analyzer staticAnalyzer) (*reachproof.Coordinator, error) {
			return reachproof.NewCoordinatorForTier(analyzer, lifecycle.judgments, lifecycle.audit, lifecycle.clock, judgment.Tier1)
		},
	)
}

func runRustImport(ctx context.Context, _ *ProductionCapture, fixture MaterializedFixture, resolved measurement.ResolvedFixtureSubject, lifecycle captureLifecycle) (execution, error) {
	return runSourceImport(ctx, fixture, resolved, lifecycle, "cargo", srcimports.NewRustScanner(), srcimports.RustCandidates, reachproof.LanguageRust)
}

func runPHPImport(ctx context.Context, _ *ProductionCapture, fixture MaterializedFixture, resolved measurement.ResolvedFixtureSubject, lifecycle captureLifecycle) (execution, error) {
	return runSourceImport(ctx, fixture, resolved, lifecycle, "composer", srcimports.NewPHPScanner(), srcimports.PHPCandidates, reachproof.LanguagePHP)
}

func runRubyImport(ctx context.Context, _ *ProductionCapture, fixture MaterializedFixture, resolved measurement.ResolvedFixtureSubject, lifecycle captureLifecycle) (execution, error) {
	return runSourceImport(ctx, fixture, resolved, lifecycle, "gem", srcimports.NewRubyScanner(), srcimports.RubyCandidates, reachproof.LanguageRuby)
}

func runSourceImport(ctx context.Context, fixture MaterializedFixture, resolved measurement.ResolvedFixtureSubject, lifecycle captureLifecycle, purlType string, scanner ports.SourceImportScanner, candidates srcreach.CandidateNamer, language reachproof.Language) (execution, error) {
	subjects, err := importSubjects(resolved, purlType)
	if err != nil {
		return execution{}, err
	}
	return runStatic(ctx, fixture, resolved, lifecycle, coverageAnswersRequestedSymbols, subjects,
		func() (staticAnalyzer, error) {
			return srcreach.New(scanner, candidates, func(ctx context.Context, dir string) (map[string]bool, bool) {
				return srcimports.DirectDependencies(ctx, dir, purlType)
			})
		},
		func(analyzer staticAnalyzer) (*reachproof.Coordinator, error) {
			return reachproof.NewCoordinatorForLanguage(analyzer, lifecycle.judgments, lifecycle.audit, lifecycle.clock, judgment.Tier1, language)
		},
	)
}

func runDotNetImport(ctx context.Context, _ *ProductionCapture, fixture MaterializedFixture, resolved measurement.ResolvedFixtureSubject, lifecycle captureLifecycle) (execution, error) {
	subjects, err := importSubjects(resolved, "nuget")
	if err != nil {
		return execution{}, err
	}
	return runStatic(ctx, fixture, resolved, lifecycle, coverageAnswersRequestedSymbols, subjects,
		func() (staticAnalyzer, error) {
			return nugetreach.New(srcimports.NewDotNetScanner(), dotnetreach.Loader{}, func(ctx context.Context, dir string) (map[string]bool, bool) {
				return srcimports.DirectDependencies(ctx, dir, "nuget")
			})
		},
		func(analyzer staticAnalyzer) (*reachproof.Coordinator, error) {
			coordinator, err := reachproof.NewCoordinatorForLanguage(analyzer, lifecycle.judgments, lifecycle.audit, lifecycle.clock, judgment.Tier1, reachproof.LanguageDotNet)
			if err != nil {
				return nil, err
			}
			return coordinator.WithSkipUnresolvedSubjects(), nil
		},
	)
}

func runGoBinary(ctx context.Context, _ *ProductionCapture, fixture MaterializedFixture, resolved measurement.ResolvedFixtureSubject, lifecycle captureLifecycle) (execution, error) {
	return runSymbolAnalyzer(ctx, fixture, resolved, lifecycle, "golang", symbolcanon.Go, gobinreach.New(), judgment.Tier2, reachproof.LanguageGoBinary, true)
}

func runRustSymbols(ctx context.Context, _ *ProductionCapture, fixture MaterializedFixture, resolved measurement.ResolvedFixtureSubject, lifecycle captureLifecycle) (execution, error) {
	analyzer, err := rustsymreach.New(srcimports.NewRustSymbolScanner())
	if err != nil {
		return execution{}, err
	}
	return runStatic(ctx, fixture, resolved, lifecycle, coverageAnswersRequestedSymbols, symbolSubjects(resolved),
		func() (staticAnalyzer, error) { return analyzer, nil },
		func(recording staticAnalyzer) (*reachproof.Coordinator, error) {
			coordinator, err := reachproof.NewCoordinatorForLanguage(recording, lifecycle.judgments, lifecycle.audit, lifecycle.clock, judgment.Tier2, reachproof.LanguageRust)
			if err != nil {
				return nil, err
			}
			return coordinator.WithRaiseOnly(), nil
		},
	)
}

func runPHPSymbols(ctx context.Context, _ *ProductionCapture, fixture MaterializedFixture, resolved measurement.ResolvedFixtureSubject, lifecycle captureLifecycle) (execution, error) {
	return runSymbolAnalyzer(ctx, fixture, resolved, lifecycle, "composer", symbolcanon.PHP, srcimports.NewPHPSymbolScanner(), judgment.Tier2, reachproof.LanguagePHP, true)
}

func runRubySymbols(ctx context.Context, _ *ProductionCapture, fixture MaterializedFixture, resolved measurement.ResolvedFixtureSubject, lifecycle captureLifecycle) (execution, error) {
	return runSymbolAnalyzer(ctx, fixture, resolved, lifecycle, "gem", symbolcanon.Ruby, srcimports.NewRubySymbolScanner(), judgment.Tier2, reachproof.LanguageRuby, true)
}

func runDotNetSymbols(ctx context.Context, _ *ProductionCapture, fixture MaterializedFixture, resolved measurement.ResolvedFixtureSubject, lifecycle captureLifecycle) (execution, error) {
	return runSymbolAnalyzer(ctx, fixture, resolved, lifecycle, "nuget", symbolcanon.DotNet, srcimports.NewDotNetSymbolScanner(), judgment.Tier2, reachproof.LanguageDotNet, true)
}

func runCPPSymbols(ctx context.Context, _ *ProductionCapture, fixture MaterializedFixture, resolved measurement.ResolvedFixtureSubject, lifecycle captureLifecycle) (execution, error) {
	return runSymbolAnalyzer(ctx, fixture, resolved, lifecycle, "conan", symbolcanon.Cpp, srcimports.NewCppSymbolScanner(), judgment.Tier2, reachproof.LanguageCPP, true)
}

func runSymbolAnalyzer(ctx context.Context, fixture MaterializedFixture, resolved measurement.ResolvedFixtureSubject, lifecycle captureLifecycle, purlType string, language symbolcanon.Language, scanner symreach.SymbolReferenceScanner, tier judgment.ReachabilityTier, proofLanguage reachproof.Language, raiseOnly bool) (execution, error) {
	return runStatic(ctx, fixture, resolved, lifecycle, coverageAnswersRequestedSymbols, symbolSubjects(resolved),
		func() (staticAnalyzer, error) { return symreach.New(purlType, language, scanner) },
		func(analyzer staticAnalyzer) (*reachproof.Coordinator, error) {
			coordinator, err := reachproof.NewCoordinatorForLanguage(analyzer, lifecycle.judgments, lifecycle.audit, lifecycle.clock, tier, proofLanguage)
			if err != nil {
				return nil, err
			}
			if raiseOnly {
				return coordinator.WithRaiseOnly(), nil
			}
			return coordinator, nil
		},
	)
}

func symbolSubjects(resolved measurement.ResolvedFixtureSubject) []ports.ReachabilitySubject {
	if resolved.Subject.Locator.Kind == measurement.FixtureLocatorManifestCapability {
		return nil
	}
	symbol := strings.TrimSpace(resolved.Subject.Locator.Symbol)
	if symbol == "" {
		return nil
	}
	packagePURL := fixturePackagePURL(resolved.Subject.PackageIdentity)
	return []ports.ReachabilitySubject{{
		FindingID:   shared.ID(resolved.Subject.ID),
		PackagePURL: packagePURL,
		Symbols:     []string{symbol},
	}}
}

func importSubjects(resolved measurement.ResolvedFixtureSubject, wantType string) ([]ports.ReachabilitySubject, error) {
	name, kind, canonical, ok := parseFrozenPURL(resolved.Subject.ID)
	if !ok || kind != wantType {
		return nil, fmt.Errorf("fixture subject %q is not an exact %s package URL", resolved.Subject.ID, wantType)
	}
	return []ports.ReachabilitySubject{{
		FindingID:   shared.ID(resolved.Subject.ID),
		PackagePURL: canonical,
		Symbols:     []string{name},
	}}, nil
}

func parseFrozenPURL(value string) (name, kind, canonical string, ok bool) {
	if !strings.HasPrefix(value, "pkg:") || strings.ContainsAny(value, "?#") || strings.IndexFunc(value, unicode.IsSpace) >= 0 {
		return "", "", "", false
	}
	rest := strings.TrimPrefix(value, "pkg:")
	kind, rest, ok = strings.Cut(rest, "/")
	if !ok || kind == "" {
		return "", "", "", false
	}
	if kind == "npm" {
		versionSeparator := strings.LastIndex(rest, "@")
		if versionSeparator <= 0 || strings.Contains(strings.TrimPrefix(rest[:versionSeparator], "@"), "@") {
			return "", "", "", false
		}
		name, _, ok = jsresolution.ParseNPMPURL(value)
		if !ok {
			return "", "", "", false
		}
		return name, kind, value, true
	}
	name, version, ok := strings.Cut(rest, "@")
	if !ok || name == "" || version == "" || strings.Contains(version, "@") || strings.ContainsAny(name+version, " \t\r\n") {
		return "", "", "", false
	}
	return name, kind, value, true
}

func fixturePackagePURL(identity string) string {
	identity = strings.TrimSpace(identity)
	if strings.HasPrefix(identity, "pkg:") {
		return identity
	}
	if kind, rest, ok := strings.Cut(identity, ":"); ok && kind != "" && rest != "" {
		if !strings.Contains(rest, "@") {
			rest += "@benchmark-v1"
		}
		return "pkg:" + kind + "/" + rest
	}
	return "pkg:generic/fixture@benchmark-v1"
}

func runPythonSemantic(ctx context.Context, capture *ProductionCapture, fixture MaterializedFixture, resolved measurement.ResolvedFixtureSubject, lifecycle captureLifecycle) (execution, error) {
	purl := fixturePackagePURL(resolved.Subject.PackageIdentity)
	symbol, ok := pyreach.SymbolSubject(purl, resolved.Subject.Locator.Symbol)
	if !ok {
		return execution{invoked: true, coverage: unavailableCoverage(measurement.CoverageReasonUnsupported)}, nil
	}
	analyzer, err := pyreach.NewTier2Analyzer(capture.facts)
	if err != nil {
		return execution{}, err
	}
	subjects, err := analyzer.AnswerableSubjects(ctx, fixture.Root, []ports.ReachabilitySubject{{FindingID: shared.ID(resolved.Subject.ID), PackagePURL: purl, Symbols: []string{symbol}}})
	if err != nil {
		return execution{invoked: true, coverage: unavailableCoverage(measurement.CoverageReasonFailed), analyzerError: err}, nil
	}
	return runStatic(ctx, fixture, resolved, lifecycle, coverageRequiresEntrypointAuthority, subjects,
		func() (staticAnalyzer, error) { return analyzer, nil },
		func(recording staticAnalyzer) (*reachproof.Coordinator, error) {
			return reachproof.NewCoordinatorForLanguage(recording, lifecycle.judgments, lifecycle.audit, lifecycle.clock, judgment.Tier2, reachproof.LanguagePython)
		},
	)
}

func runJavaScriptImport(ctx context.Context, _ *ProductionCapture, fixture MaterializedFixture, resolved measurement.ResolvedFixtureSubject, lifecycle captureLifecycle) (execution, error) {
	subjects, err := importSubjects(resolved, "npm")
	if err != nil {
		return execution{}, err
	}
	analyzer, err := jsreach.New(jsimports.New(), jsresolve.NewResolver(), fixtureSBOMProvider{components: []sbom.Component{{Name: subjects[0].Symbols[0], Version: "benchmark-v1", PURL: subjects[0].PackagePURL}}})
	if err != nil {
		return execution{}, err
	}
	return runStatic(ctx, fixture, resolved, lifecycle, coverageAnswersRequestedSymbols, subjects,
		func() (staticAnalyzer, error) { return analyzer, nil },
		func(recording staticAnalyzer) (*reachproof.Coordinator, error) {
			return reachproof.NewCoordinatorForLanguage(recording, lifecycle.judgments, lifecycle.audit, lifecycle.clock, judgment.Tier1, reachproof.LanguageJavaScript)
		},
	)
}

func runJavaScriptLexical(ctx context.Context, capture *ProductionCapture, fixture MaterializedFixture, resolved measurement.ResolvedFixtureSubject, lifecycle captureLifecycle) (execution, error) {
	purl := fixturePackagePURL(resolved.Subject.PackageIdentity)
	symbol, ok := jssymbols.Subject(purl, resolved.Subject.Locator.Symbol)
	if !ok {
		return execution{invoked: true, coverage: unavailableCoverage(measurement.CoverageReasonUnsupported)}, nil
	}
	analyzer, err := jsreach.NewSymbolAnalyzer(jsimports.New(), jsresolve.NewResolver(), fixtureSBOMProvider{components: []sbom.Component{{Name: purl, Version: "benchmark-v1", PURL: purl}}})
	if err != nil {
		return execution{}, err
	}
	subjects, err := analyzer.AnswerableSubjects(ctx, fixture.Root, []ports.ReachabilitySubject{{FindingID: shared.ID(resolved.Subject.ID), PackagePURL: purl, Symbols: []string{symbol}}})
	if err != nil {
		return execution{invoked: true, coverage: unavailableCoverage(measurement.CoverageReasonFailed), analyzerError: err}, nil
	}
	return runStatic(ctx, fixture, resolved, lifecycle, coverageAnswersRequestedSymbols, subjects,
		func() (staticAnalyzer, error) { return analyzer, nil },
		func(recording staticAnalyzer) (*reachproof.Coordinator, error) {
			coordinator, err := reachproof.NewCoordinatorForLanguage(recording, lifecycle.judgments, lifecycle.audit, lifecycle.clock, judgment.Tier2, reachproof.LanguageJavaScript)
			if err != nil {
				return nil, err
			}
			if !capture.enableJSLexicalNegatives {
				return coordinator.WithRaiseOnly(), nil
			}
			return coordinator, nil
		},
	)
}

func runJavaScriptInterprocedural(ctx context.Context, capture *ProductionCapture, fixture MaterializedFixture, resolved measurement.ResolvedFixtureSubject, lifecycle captureLifecycle) (execution, error) {
	encoded := jsreach.EncodeNPMSubjects(symbolSubjects(resolved))
	analyzer, err := jsreach.NewInterprocAnalyzer(capture.facts)
	if err != nil {
		return execution{}, err
	}
	return runStatic(ctx, fixture, resolved, lifecycle, coverageRequiresEntrypointAuthority, encoded,
		func() (staticAnalyzer, error) { return analyzer, nil },
		func(recording staticAnalyzer) (*reachproof.Coordinator, error) {
			coordinator, err := reachproof.NewCoordinatorForLanguage(recording, lifecycle.judgments, lifecycle.audit, lifecycle.clock, judgment.Tier2, reachproof.LanguageJavaScript)
			if err != nil {
				return nil, err
			}
			return coordinator.WithRaiseOnly(), nil
		},
	)
}

type fixtureSBOMProvider struct{ components []sbom.Component }

func (provider fixtureSBOMProvider) SBOMFor(_ context.Context, targetRef string) (*sbom.SBOM, error) {
	return &sbom.SBOM{ID: "reachbench-fixture-sbom", TargetRef: targetRef, Source: "reachbench", Components: append([]sbom.Component(nil), provider.components...)}, nil
}

func runJVMCoarse(ctx context.Context, _ *ProductionCapture, fixture MaterializedFixture, resolved measurement.ResolvedFixtureSubject, lifecycle captureLifecycle) (execution, error) {
	if resolved.Subject.Locator.Kind == measurement.FixtureLocatorManifestCapability {
		return execution{invoked: true, coverage: unavailableCoverage(measurement.CoverageReasonUnsupported), detail: "jvm-coarse"}, nil
	}
	components := []sbom.Component{{PURL: resolved.Subject.ID, Name: resolved.Subject.PackageIdentity}}
	_, err := jvmreach.New().Analyze(ctx, fixture.Root, components)
	if err != nil {
		return execution{invoked: true, coverage: unavailableCoverage(measurement.CoverageReasonFailed), analyzerError: err, detail: "jvm-coarse"}, nil
	}
	coverage := jvmCoarseCoverage(resolved.Subject.Locator.Kind, components[0].Reachability)
	if coverage.Status == measurement.CoverageUnavailable {
		return execution{invoked: true, coverage: coverage, detail: "jvm-coarse"}, nil
	}
	outcome := jvmCoarseOutcome(components[0].Reachability)
	coordinator, err := reachproof.NewJVMVerdictCoordinator(lifecycle.judgments, lifecycle.audit, lifecycle.clock)
	if err != nil {
		return execution{}, err
	}
	_, err = coordinator.WithRaiseOnly().RecordVerdicts(ctx, productionCaptureEngagementID, []ports.JVMReachabilityVerdict{{
		FindingID: shared.ID(resolved.Subject.ID), Reachable: components[0].Reachability == sbom.ReachabilityReachable,
	}})
	if err != nil {
		return execution{}, fmt.Errorf("record JVM coarse verdict: %w", err)
	}
	return execution{invoked: true, coverage: coverage, lifecycleRecorded: true, outcome: &outcome, detail: "jvm-coarse"}, nil
}

func jvmCoarseCoverage(locator measurement.FixtureLocatorKind, reachability string) measurement.ObservedCoverage {
	if locator == measurement.FixtureLocatorManifestCapability {
		return unavailableCoverage(measurement.CoverageReasonUnsupported)
	}
	switch reachability {
	case sbom.ReachabilityReachable:
		return completeCoverage()
	case sbom.ReachabilityUnreferenced:
		return partialCoverage(measurement.CoverageReasonOpaque)
	default:
		return unavailableCoverage(measurement.CoverageReasonUnsupported)
	}
}

func jvmCoarseOutcome(reachability string) measurement.Outcome {
	if reachability == sbom.ReachabilityReachable {
		return measurement.OutcomeReachable
	}
	return measurement.OutcomeConditionallyReachable
}

func runJVMTier2(ctx context.Context, capture *ProductionCapture, fixture MaterializedFixture, resolved measurement.ResolvedFixtureSubject, lifecycle captureLifecycle) (execution, error) {
	if resolved.Subject.Locator.Kind == measurement.FixtureLocatorManifestCapability {
		return execution{invoked: true, coverage: unavailableCoverage(measurement.CoverageReasonUnsupported), detail: "jvm-tier2"}, nil
	}
	if _, kind, _, ok := parseFrozenPURL(resolved.Subject.ID); !ok || kind != "maven" {
		return execution{}, fmt.Errorf("JVM fixture subject %q is not an exact Maven package URL", resolved.Subject.ID)
	}
	recording := &recordingAnalyzer{delegate: jvmreach.NewTier2(capture.jvmPointsTo), materializedRoot: fixture.Root}
	coordinator, err := reachproof.NewJVMTier2Coordinator(recording, lifecycle.judgments, lifecycle.audit, lifecycle.clock)
	if err != nil {
		return execution{}, err
	}
	_, recordErr := coordinator.Record(ctx, productionCaptureEngagementID, fixture.Root, []ports.ReachabilitySubject{{
		FindingID: shared.ID(resolved.Subject.ID), PackagePURL: resolved.Subject.ID, Symbols: []string{resolved.Subject.Locator.Symbol},
	}})
	if recordErr != nil {
		if recording.err != nil {
			return execution{invoked: true, coverage: unavailableCoverage(measurement.CoverageReasonFailed), analyzer: recording, analyzerError: recording.err, detail: "jvm-tier2"}, nil
		}
		return execution{}, fmt.Errorf("record JVM tier-2 verdict: %w", recordErr)
	}
	return execution{invoked: true, coverage: coverageFromRecordedAnalysis(recording.symbols, recording.result, coverageRequiresEntrypointAuthority), analyzer: recording, lifecycleRecorded: true, detail: "jvm-tier2"}, nil
}

func runRuntimeLibraryLoads(ctx context.Context, _ *ProductionCapture, fixture MaterializedFixture, resolved measurement.ResolvedFixtureSubject, lifecycle captureLifecycle) (execution, error) {
	replayPath, ownershipPath, err := runtimeReplayPaths(fixture, resolved.Specification)
	if err != nil {
		return execution{}, err
	}
	replayFile, err := os.Open(replayPath)
	if err != nil {
		return execution{}, fmt.Errorf("open materialized runtime replay: %w", err)
	}
	defer replayFile.Close()
	ownershipFile, err := os.Open(ownershipPath)
	if err != nil {
		return execution{}, fmt.Errorf("open materialized runtime ownership: %w", err)
	}
	defer ownershipFile.Close()
	replay, err := measurement.DecodeRuntimeReplay(replayFile, ownershipFile)
	if err != nil {
		return execution{}, fmt.Errorf("decode materialized runtime replay: %w", err)
	}

	report, opaqueOwner, unsupportedOwner := runtimeReport(replay)
	if err := report.Validate(); err != nil {
		return execution{}, fmt.Errorf("validate runtime production report: %w", err)
	}
	ownership, loads := report.Build()
	coverage := completeCoverage()
	if len(report.Coverage) > 0 {
		coverage = partialCoverage(measurement.CoverageReasonOpaque)
	}
	name, _, _, ok := parseFrozenPURL(resolved.Subject.PackageIdentity)
	if !ok {
		return execution{}, fmt.Errorf("runtime fixture subject %q has invalid package identity", resolved.Subject.ID)
	}
	if unsupportedOwner[name] {
		return execution{invoked: true, coverage: unavailableCoverage(measurement.CoverageReasonUnsupported), detail: "runtime-library-loads"}, nil
	}
	if opaqueOwner[name] {
		outcome := measurement.OutcomeConditionallyReachable
		return execution{invoked: true, coverage: partialCoverage(measurement.CoverageReasonOpaque), outcome: &outcome, detail: "runtime-library-loads"}, nil
	}
	if err := lifecycle.findings.Upsert(ctx, []finding.Finding{{
		ID: shared.ID(resolved.Subject.ID), EngagementID: productionCaptureEngagementID, Title: "benchmark runtime package", Kind: finding.KindSCA,
		DedupKey: vulnerability.DedupKey("reachbench-runtime", name, runtimeVersion(resolved.Subject.PackageIdentity)),
	}}); err != nil {
		return execution{}, fmt.Errorf("store synthetic runtime finding: %w", err)
	}
	coordinator, err := runtimeusecase.NewCoordinator(lifecycle.judgments, lifecycle.audit, lifecycle.clock)
	if err != nil {
		return execution{}, err
	}
	service, err := runtimeusecase.NewService(lifecycle.findings, coordinator)
	if err != nil {
		return execution{}, err
	}
	minted, err := service.Attribute(ctx, productionCaptureEngagementID, ownership, loads)
	if err != nil {
		return execution{}, fmt.Errorf("attribute runtime loads: %w", err)
	}
	return execution{invoked: true, coverage: coverage, lifecycleRecorded: minted > 0, detail: "runtime-library-loads"}, nil
}

func runtimeReplayPaths(fixture MaterializedFixture, specification measurement.FixtureSpecification) (string, string, error) {
	var replay, ownership string
	for _, entry := range specification.Entries {
		switch entry.Role {
		case measurement.FixtureEntryReplay:
			replay = entry.Path
		case measurement.FixtureEntryOwnership:
			ownership = entry.Path
		}
	}
	if replay == "" || ownership == "" {
		return "", "", errors.New("runtime fixture lacks replay or ownership input")
	}
	replayPath, err := fixture.ResolveInput(replay)
	if err != nil {
		return "", "", err
	}
	ownershipPath, err := fixture.ResolveInput(ownership)
	if err != nil {
		return "", "", err
	}
	return replayPath, ownershipPath, nil
}

func runtimeReport(replay measurement.RuntimeReplay) (runtimereach.Report, map[string]bool, map[string]bool) {
	report := runtimereach.Report{}
	for _, owner := range replay.Owners {
		report.PackageFiles = append(report.PackageFiles, runtimereach.PackageFiles{
			Package: runtimereach.PackageRef{Name: owner.Owner.Name, Version: owner.Owner.Version},
			Files:   []runtimereach.OwnedFile{{Path: "/" + owner.Library}},
		})
	}
	opaque, unsupported := map[string]bool{}, map[string]bool{}
	for _, event := range replay.Events {
		switch event.Operation {
		case "load":
			report.Loads = append(report.Loads, runtimereach.LoadEvent{Path: "/" + event.Library})
		case "opaque":
			opaque[event.Owner.Name] = true
		case "unsupported":
			unsupported[event.Owner.Name] = true
		}
	}
	if !replay.Complete || replay.LossState != "none" {
		report.Coverage = append(report.Coverage, runtimereach.CoverageTruncated)
	}
	return report, opaque, unsupported
}

func runtimeVersion(identity string) string {
	_, _, canonical, ok := parseFrozenPURL(identity)
	if !ok {
		return "benchmark-v1"
	}
	_, version, ok := strings.Cut(canonical[strings.LastIndex(canonical, "/")+1:], "@")
	if !ok || version == "" {
		return "benchmark-v1"
	}
	return version
}

type captureLifecycle struct {
	judgments *analysis.Service
	evidence  *evidence.Service
	findings  *memory.FindingRepository
	audit     *captureAudit
	clock     fixedCaptureClock
}

func newCaptureLifecycle() (captureLifecycle, error) {
	clock := fixedCaptureClock{now: time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)}
	audit := &captureAudit{once: map[string]struct{}{}}
	evidenceService, err := evidence.NewService(memory.NewEvidenceStore(), nil, audit, clock, &captureIDSequence{prefix: "reachbench-evidence"})
	if err != nil {
		return captureLifecycle{}, fmt.Errorf("create production evidence lifecycle: %w", err)
	}
	judgmentService, err := analysis.NewService(memory.NewJudgmentStore(), evidenceService, audit, clock, &captureIDSequence{prefix: "reachbench-judgment"})
	if err != nil {
		return captureLifecycle{}, fmt.Errorf("create production judgment lifecycle: %w", err)
	}
	return captureLifecycle{judgments: judgmentService, evidence: evidenceService, findings: memory.NewFindingRepository(), audit: audit, clock: clock}, nil
}

type fixedCaptureClock struct{ now time.Time }

func (clock fixedCaptureClock) Now() time.Time { return clock.now }

type captureIDSequence struct {
	prefix string
	next   uint64
}

func (sequence *captureIDSequence) NewID() shared.ID {
	sequence.next++
	return shared.ID(fmt.Sprintf("%s-%06d", sequence.prefix, sequence.next))
}

type captureAudit struct {
	mu   sync.Mutex
	once map[string]struct{}
}

func (audit *captureAudit) Record(context.Context, ports.AuditEntry) error { return nil }
func (audit *captureAudit) RecordOnce(ctx context.Context, entry ports.AuditEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	audit.mu.Lock()
	defer audit.mu.Unlock()
	key := entry.Metadata["idempotency_key"]
	if key != "" {
		if _, ok := audit.once[key]; ok {
			return nil
		}
		audit.once[key] = struct{}{}
	}
	return nil
}

func (capture *ProductionCapture) observation(ctx context.Context, request CaptureRequest, lifecycle captureLifecycle, executed execution) (measurement.MeasuredObservation, error) {
	observation := measurement.MeasuredObservation{
		CaseID: request.Cell.CaseID, BindingID: request.Cell.BindingID, Invoked: executed.invoked,
		Outcome: measurement.OutcomeNoAnalysis, Coverage: executed.coverage, OutputCapture: measurement.CaptureComplete,
		Analyzer:      measurement.ArtifactReference{ID: request.Cell.AnalyzerID, Digest: benchmark.SHA256Digest([]byte(request.Analyzer.Commit + "\x00" + request.Analyzer.Tree))},
		Configuration: request.Cell.Configuration,
		Suppression:   measurement.SuppressionCapture{Claim: measurement.SuppressionNone, Status: measurement.CaptureComplete},
	}
	if executed.outcome != nil {
		observation.Outcome = *executed.outcome
	}
	if executed.analyzerError != nil || (!executed.lifecycleRecorded && (executed.analyzer == nil || executed.analyzer.result == nil)) {
		if observation.Coverage.Status == "" {
			observation.Coverage = unavailableCoverage(measurement.CoverageReasonFailed)
		}
		return observation, nil
	}
	judgments, err := lifecycle.judgments.List(ctx, productionCaptureEngagementID)
	if err != nil {
		return measurement.MeasuredObservation{}, fmt.Errorf("list captured judgments: %w", err)
	}
	winner, claim, ok, err := winningCaptureJudgment(judgments, shared.ID(request.Cell.SubjectID))
	if err != nil {
		return measurement.MeasuredObservation{}, err
	}
	if !ok {
		return observation, nil
	}
	switch claim.Reachable {
	case judgment.Reachable:
		if executed.analyzer != nil && analysisHasUnknownPath(executed.analyzer.result) {
			observation.Outcome = measurement.OutcomeConditionallyReachable
			observation.Coverage = partialCoverage(measurement.CoverageReasonOpaque)
		} else {
			observation.Outcome = measurement.OutcomeReachable
		}
	case judgment.NotReachable:
		observation.Outcome = measurement.OutcomePresentUnreached
	default:
		observation.Outcome = measurement.OutcomeNoAnalysis
	}
	if claim.Reachable == judgment.Reachable {
		observation.Positive = &measurement.PositiveEvidence{Snapshot: request.Snapshot, Evidence: judgmentReference(winner)}
	}
	if claim.SuppressesFinding() {
		evidences, err := lifecycle.evidence.List(ctx, productionCaptureEngagementID)
		if err != nil {
			return measurement.MeasuredObservation{}, fmt.Errorf("list captured evidence: %w", err)
		}
		if len(evidences) == 0 {
			return measurement.MeasuredObservation{}, errors.New("suppressing judgment has no sealed evidence")
		}
		proofEvidence := evidences[len(evidences)-1]
		observation.Suppression = measurement.SuppressionCapture{
			Claim: measurement.SuppressionProduced, Status: measurement.CaptureComplete,
			Effects: []measurement.SuppressionEffect{{Kind: measurement.EffectSuppressingJudgment, Proof: measurement.SuppressionProof{
				Judgment: judgmentReference(winner), SubjectID: request.Cell.SubjectID, BoundaryID: request.Cell.BoundaryID,
				Proposer: winner.ProposedBy, Verifier: winner.VerifiedBy, Snapshot: request.Snapshot,
				Analyzer: observation.Analyzer, Configuration: request.Cell.Configuration,
				Evidence:          measurement.ArtifactReference{ID: proofEvidence.ID.String(), Digest: "sha256:" + proofEvidence.Hash},
				MissingProvenance: []string{"analyzer_identity", "completeness_contract", "configuration_identity", "snapshot_identity"},
			}}},
		}
	}
	return observation, nil
}

func analysisHasUnknownPath(analysis *reachability.Analysis) bool {
	if analysis == nil {
		return false
	}
	for _, result := range analysis.Results {
		for _, value := range result.Path {
			if strings.Contains(value, "coverage:unknown") {
				return true
			}
		}
	}
	return false
}

func judgmentReference(item judgment.Judgment) measurement.ArtifactReference {
	encoded, err := benchmark.CanonicalJSON(item)
	if err != nil {
		return measurement.ArtifactReference{ID: item.ID.String(), Digest: "sha256:" + strings.Repeat("0", 64)}
	}
	return measurement.ArtifactReference{ID: item.ID.String(), Digest: benchmark.SHA256Digest(encoded)}
}

func winningCaptureJudgment(items []judgment.Judgment, subjectID shared.ID) (judgment.Judgment, judgment.ReachabilityClaim, bool, error) {
	claims := judgment.WinningReachabilityClaims(items)
	claim, exists := claims[subjectID.String()]
	if !exists {
		return judgment.Judgment{}, judgment.ReachabilityClaim{}, false, nil
	}
	var winner judgment.Judgment
	found := false
	for _, item := range items {
		if !item.Publishable() || item.Capability != judgment.CapReachability || item.SubjectKind != judgment.SubjectFinding || item.SubjectID != subjectID {
			continue
		}
		candidate, ok := item.Claim.(judgment.ReachabilityClaim)
		if !ok {
			continue
		}
		if !found || candidate.Supersedes(claimFromJudgment(winner)) {
			winner, found = item, true
		}
	}
	if !found {
		return judgment.Judgment{}, judgment.ReachabilityClaim{}, false, errors.New("reachability winner has no persisted judgment")
	}
	persisted := claimFromJudgment(winner)
	if !reflect.DeepEqual(persisted, claim) {
		return judgment.Judgment{}, judgment.ReachabilityClaim{}, false, errors.New("reachability claim winner disagrees with persisted judgment winner")
	}
	return winner, claim, true, nil
}

func claimFromJudgment(item judgment.Judgment) judgment.ReachabilityClaim {
	claim, _ := item.Claim.(judgment.ReachabilityClaim)
	return claim
}

func (capture *ProductionCapture) rawEvidence(request CaptureRequest, fixture MaterializedFixture, resolved measurement.ResolvedFixtureSubject, executed execution, observation measurement.MeasuredObservation) ([]byte, error) {
	manifestDigest, err := fixture.ManifestDigest()
	if err != nil {
		return nil, fmt.Errorf("digest materialized fixture: %w", err)
	}
	type analyzerEvidence struct {
		Calls      int                    `json:"calls"`
		ErrorClass string                 `json:"error_class,omitempty"`
		Analysis   *reachability.Analysis `json:"analysis,omitempty"`
	}
	var analyzer analyzerEvidence
	if executed.analyzer != nil {
		analyzer.Calls = executed.analyzer.calls
		analyzer.Analysis = executed.analyzer.result
	}
	if executed.analyzerError != nil {
		analyzer.ErrorClass = fmt.Sprintf("%T", executed.analyzerError)
	}
	payload := struct {
		SchemaVersion         string                       `json:"schema_version"`
		Cell                  ExecutionCell                `json:"cell"`
		FixtureManifestDigest string                       `json:"fixture_manifest_digest"`
		FixtureSubject        measurement.FixtureSubject   `json:"fixture_subject"`
		Analyzer              analyzerEvidence             `json:"analyzer"`
		Outcome               measurement.Outcome          `json:"outcome"`
		Coverage              measurement.ObservedCoverage `json:"coverage"`
	}{"synapse-reachability-production-capture-v1", request.Cell, manifestDigest, resolved.Subject, analyzer, observation.Outcome, observation.Coverage}
	return benchmark.CanonicalJSON(payload)
}
