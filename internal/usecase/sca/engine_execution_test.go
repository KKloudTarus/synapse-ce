package sca

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/importedsbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	evidenceuc "github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type unavailableProvenanceSource struct{ fakeVuln }

func (unavailableProvenanceSource) Provenance() (string, string) { return "", "" }

func TestUnavailableDetectionProvenanceCannotEstablishCompleteCoverage(t *testing.T) {
	for _, imported := range []bool{false, true} {
		t.Run(map[bool]string{false: "source", true: "imported"}[imported], func(t *testing.T) {
			svc := newSvc(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAcquirer{dir: t.TempDir()}, &fakeAudit{}, &fakeDetector{})
			svc.sources = []ports.DetectionSource{fakeVuln{}, unavailableProvenanceSource{}}
			doc := &sbom.SBOM{TargetRef: "myrepo", Components: []sbom.Component{{Name: "pkg", Version: "1.0.0"}}}
			svc.sbomGen = staticSBOM{doc: doc}
			var result *ScanResult
			var err error
			if imported {
				result, err = svc.runImportedSBOMPipeline(context.Background(), "operator", "e1", time.Now(), importedsbom.Record{}, doc, ScanOptions{Mode: ScanModeFull}, func(string, int, []ports.ScanDebugEvent) {}, "")
			} else {
				result, err = svc.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "myrepo"})
			}
			if err != nil {
				t.Fatal(err)
			}
			outcome, _ := result.engineOutcome("sca")
			if outcome.Coverage != scanrun.CoveragePartial || outcome.Reason != scanrun.ReasonUnavailable || result.EngineCoverage.Complete() {
				t.Fatalf("missing detection source counted complete: %+v", outcome)
			}
		})
	}
}

func TestImportedSBOMWithoutDetectionSourcesHasIncompleteSCACoverage(t *testing.T) {
	svc := newSvc(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAcquirer{dir: t.TempDir()}, &fakeAudit{}, &fakeDetector{})
	svc.sources = nil
	doc := &sbom.SBOM{TargetRef: "myrepo", Components: []sbom.Component{{Name: "pkg", Version: "1.0.0"}}}
	result, err := svc.runImportedSBOMPipeline(context.Background(), "operator", "e1", time.Now(), importedsbom.Record{}, doc, ScanOptions{Mode: ScanModeFull}, func(string, int, []ports.ScanDebugEvent) {}, "")
	if err != nil {
		t.Fatal(err)
	}
	if outcome, _ := result.engineOutcome("sca"); outcome.Coverage != scanrun.CoveragePartial || result.EngineCoverage.Complete() {
		t.Fatalf("empty detection corpus counted complete: %+v", outcome)
	}
}

type recordingComparisonSource struct {
	comparisonSourceStub
	calls int
}

func (s *recordingComparisonSource) FileChanges(context.Context, string, string, string) ([]projectanalysis.FileChange, error) {
	s.calls++
	return nil, nil
}

func TestExpiredExecutionDoesNotStartProjectComparisonDuringPublication(t *testing.T) {
	svc := newSvc(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, fakeClock{}, &fakeAcquirer{}, &fakeAudit{}, &fakeDetector{})
	source := &recordingComparisonSource{}
	svc.SetProjectSourceArtifactStore(&recordingSourceArtifacts{})
	svc.SetProjectComparisonSource(source)
	execution, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	result := &ScanResult{Comparison: projectanalysis.Comparison{Available: true, MergeBase: "base"}}
	svc.captureProjectComparison(execution, "e1", "analysis", "/workspace", "head", result)
	if source.calls != 0 || result.Comparison.Available {
		t.Fatalf("source work escaped expired budget: calls=%d result=%+v", source.calls, result.Comparison)
	}
}

type contextAwareEvidence struct{ fakeEvidence }

func (s *contextAwareEvidence) Append(ctx context.Context, items []evidence.Evidence) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.fakeEvidence.Append(ctx, items)
}

func TestOwnedScanDeadlineStillSealsPartialSourceCoverage(t *testing.T) {
	audit := &fakeAudit{}
	clock := fakeClock{t: time.Unix(0, 0).UTC()}
	store := &contextAwareEvidence{}
	vault, err := evidenceuc.NewService(store, nil, audit, clock, fakeIDs{})
	if err != nil {
		t.Fatal(err)
	}
	svc := newSvc(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, clock, &fakeAcquirer{dir: t.TempDir()}, audit, &fakeDetector{})
	svc.evidence = vault
	svc.SetSASTAnalyzer(&deadlineSAST{})
	svc.timeout = 10 * time.Millisecond
	result, err := svc.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "myrepo"})
	if err != nil || result == nil || result.EngineCoverage.Complete() || len(store.items) != 1 {
		t.Fatalf("partial publication result=%+v links=%d err=%v", result, len(store.items), err)
	}
}

func TestScanPublicationPreservesValuesAndParentCancellation(t *testing.T) {
	parent, cancelParent := context.WithCancel(shared.WithTenant(context.Background(), "tenant"))
	defer cancelParent()
	execution, cancelExecution := context.WithDeadline(parent, time.Now().Add(-time.Second))
	defer cancelExecution()
	execution = context.WithValue(execution, scanBudgetParentKey{}, parent)
	execution = context.WithValue(execution, inventoryAdmissionContextKey{}, sbom.InventoryAdmission{Generation: 7})
	publication, cancelPublication, err := scanPublicationContext(execution)
	defer cancelPublication()
	if err != nil || publication.Err() != nil {
		t.Fatalf("owned budget was not renewed: %v", err)
	}
	if admission, ok := inventoryAdmissionFrom(publication); !ok || admission.Generation != 7 {
		t.Fatalf("lost inventory admission: %+v", admission)
	}
	if tenant, ok := shared.TenantFrom(publication); !ok || tenant != "tenant" {
		t.Fatalf("lost tenant: %q", tenant)
	}
	deadline, ok := publication.Deadline()
	if !ok || time.Until(deadline) > 10*time.Second || time.Until(deadline) < 9*time.Second {
		t.Fatalf("unbounded publication deadline: %v", deadline)
	}
	cancelParent()
	select {
	case <-publication.Done():
	case <-time.After(time.Second):
		t.Fatal("publication did not receive parent cancellation")
	}
	if !errors.Is(publication.Err(), context.Canceled) {
		t.Fatalf("publication ignored parent cancellation: %v", publication.Err())
	}
	if _, cancel, err := scanPublicationContext(execution); !errors.Is(err, context.Canceled) {
		cancel()
		t.Fatalf("cancelled parent was renewed: %v", err)
	} else {
		cancel()
	}
	arbitrary, cancelArbitrary := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelArbitrary()
	if _, cancel, err := scanPublicationContext(arbitrary); !errors.Is(err, context.DeadlineExceeded) {
		cancel()
		t.Fatalf("arbitrary deadline was renewed: %v", err)
	} else {
		cancel()
	}
}

func TestScanPublicationDoesNotInheritNearlySpentExecutionBudget(t *testing.T) {
	parent := context.Background()
	execution, cancelExecution := context.WithTimeout(parent, time.Millisecond)
	defer cancelExecution()
	execution = context.WithValue(execution, scanBudgetParentKey{}, parent)
	publication, cancelPublication, err := scanPublicationContext(execution)
	defer cancelPublication()
	if err != nil {
		t.Fatal(err)
	}
	<-execution.Done()
	if publication.Err() != nil {
		t.Fatalf("publication inherited spent scan budget: %v", publication.Err())
	}
}

type failingLicenseScanner struct{ err error }

type failingLegacyTaint struct{ err error }

func (s failingLegacyTaint) Scan(context.Context, shared.ID, string) (int, error) {
	return 0, s.err
}

type failingCorrelatedTaint struct{ *staticTaintCoverage }

func (s failingCorrelatedTaint) ScanCorrelated(context.Context, shared.ID, string, []ports.ReachabilitySubject) (ports.TaintScanOutcome, error) {
	return s.outcome, s.err
}

func TestSemanticInvocationErrorsCannotBeOverwrittenByCoverage(t *testing.T) {
	for _, engine := range []string{"taint_go", "taint_python", "taint_javascript", "taint_java"} {
		for _, kind := range []string{"coverage", "correlated", "legacy"} {
			for _, failure := range []error{context.DeadlineExceeded, context.Canceled, errors.New("analyzer unavailable")} {
				t.Run(engine+"/"+kind+"/"+failure.Error(), func(t *testing.T) {
					svc := newSvc(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAcquirer{dir: t.TempDir()}, &fakeAudit{}, &fakeDetector{})
					fixture := &staticTaintCoverage{err: failure, outcome: ports.TaintScanOutcome{Coverage: ports.AnalysisCoverage{Analyzer: engine, Status: ports.AnalysisCoverageComplete, Complete: true, Available: true}}}
					var scanner ports.TaintScanner = fixture
					if kind == "legacy" {
						scanner = failingLegacyTaint{err: failure}
					} else if kind == "correlated" {
						scanner = failingCorrelatedTaint{fixture}
					}
					switch engine {
					case "taint_go":
						svc.SetTaint(scanner)
					case "taint_python":
						svc.SetPythonTaint(scanner)
					case "taint_javascript":
						svc.SetJsTaint(scanner)
					case "taint_java":
						svc.SetJavaTaint(scanner)
					}
					result, err := svc.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "myrepo"})
					if result == nil || (errors.Is(failure, context.Canceled) && !errors.Is(err, context.Canceled)) || (!errors.Is(failure, context.Canceled) && err != nil) {
						t.Fatalf("result=%+v err=%v", result, err)
					}
					want := scanrun.EngineFailed
					if errors.Is(failure, context.DeadlineExceeded) {
						want = scanrun.EngineTimedOut
					} else if errors.Is(failure, context.Canceled) {
						want = scanrun.EngineCancelled
					}
					outcome, _ := result.engineOutcome(engine)
					if outcome.Execution != want || outcome.Coverage == scanrun.CoverageComplete || len(result.AnalysisCoverage) != 0 {
						t.Fatalf("failed semantic invocation overwritten: %+v coverage=%+v", outcome, result.AnalysisCoverage)
					}
				})
			}
		}
	}
}

func (s failingLicenseScanner) Scan(context.Context, *sbom.SBOM) ([]ports.LicenseFinding, error) {
	return nil, s.err
}

func TestImportedScanFailurePreservesCompletedAndIncompleteInventory(t *testing.T) {
	for _, version := range []string{"1.0.0", ""} {
		t.Run("version="+version, func(t *testing.T) {
			svc := newSvc(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAcquirer{dir: t.TempDir()}, &fakeAudit{}, &fakeDetector{})
			failure := errors.New("license scanner unavailable")
			svc.licScan = failingLicenseScanner{err: failure}
			doc := &sbom.SBOM{TargetRef: "myrepo", Components: []sbom.Component{{Name: "pkg", Version: version}}}
			result, err := svc.runImportedSBOMPipeline(context.Background(), "operator", "e1", time.Now(), importedsbom.Record{}, doc, ScanOptions{Mode: ScanModeFull}, func(string, int, []ports.ScanDebugEvent) {}, "")
			if !errors.Is(err, failure) || result == nil || result.SBOM != doc {
				t.Fatalf("lost imported inventory: result=%+v err=%v", result, err)
			}
			for _, engine := range []string{"inventory", "dependency_resolution"} {
				outcome, _ := result.engineOutcome(engine)
				want := scanrun.CoverageComplete
				if version == "" {
					want = scanrun.CoveragePartial
				}
				if outcome.Execution != scanrun.EngineCompleted || outcome.Coverage != want {
					t.Fatalf("%s outcome=%+v want coverage=%s", engine, outcome, want)
				}
			}
			license, _ := result.engineOutcome("licenses")
			if license.Execution != scanrun.EngineFailed || result.EngineCoverage.Complete() {
				t.Fatalf("license failure lost: %+v coverage=%+v", license, result.EngineCoverage)
			}
		})
	}
}

func TestExpiredCoreBudgetDoesNotInvokeAcquisition(t *testing.T) {
	acquirer := &fakeAcquirer{dir: t.TempDir()}
	svc := newSvc(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, fakeClock{t: time.Unix(0, 0).UTC()}, acquirer, &fakeAudit{}, &fakeDetector{})
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	result, err := svc.runPipeline(ctx, "operator", "e1", time.Now(), ports.AcquireRequest{Kind: ports.TargetLocal, Value: "myrepo"}, ScanOptions{Mode: ScanModeFull}, func(string, int, []ports.ScanDebugEvent) {}, "")
	if !errors.Is(err, context.DeadlineExceeded) || result == nil || acquirer.called {
		t.Fatalf("expired acquisition: called=%v result=%+v err=%v", acquirer.called, result, err)
	}
	inventory, _ := result.engineOutcome("inventory")
	if inventory.Execution != scanrun.EngineNotRun || inventory.Reason != scanrun.ReasonBudgetExhausted {
		t.Fatalf("unstarted inventory mislabeled: %+v", inventory)
	}
}

func TestScanEvidenceSealsCanonicalEngineOutcomes(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	base := &ScanResult{ExecutionMode: ScanModeFull, EngineOutcomes: []scanrun.EngineOutcome{
		{Engine: "sca", Required: true, Execution: scanrun.EngineCompleted, Coverage: scanrun.CoverageComplete, Reason: scanrun.ReasonNone},
		{Engine: "inventory", Required: true, Execution: scanrun.EngineCompleted, Coverage: scanrun.CoverageComplete, Reason: scanrun.ReasonNone},
	}}
	first, err := scanEvidenceContent("tester", now, base)
	if err != nil {
		t.Fatal(err)
	}
	reordered := *base
	reordered.EngineOutcomes = []scanrun.EngineOutcome{base.EngineOutcomes[1], base.EngineOutcomes[0]}
	second, err := scanEvidenceContent("tester", now, &reordered)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("engine outcome order changed evidence bytes")
	}
	mutated := *base
	mutated.EngineOutcomes = scanrun.CloneEngineOutcomes(base.EngineOutcomes)
	mutated.EngineOutcomes[0].Required = false
	changed, err := scanEvidenceContent("tester", now, &mutated)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, changed) {
		t.Fatal("requiredness mutation did not change evidence")
	}
	invalid := *base
	invalid.EngineOutcomes = []scanrun.EngineOutcome{{Engine: "sca", Required: true, Execution: scanrun.EngineCompleted, Coverage: scanrun.CoverageComplete, Reason: scanrun.ReasonTruncated}}
	if _, err := scanEvidenceContent("tester", now, &invalid); err == nil {
		t.Fatal("invalid engine outcome was accepted into evidence")
	}
}

type contextFailingSource struct{ err error }

func (s contextFailingSource) Name() string { return "context-failing" }
func (s contextFailingSource) Scan(context.Context, *sbom.SBOM) ([]vulnerability.RawFinding, error) {
	return nil, s.err
}

func TestDetectionSourceContextFailureStopsLaterSources(t *testing.T) {
	for _, err := range []error{context.DeadlineExceeded, context.Canceled} {
		t.Run(err.Error(), func(t *testing.T) {
			later := &countingVuln{}
			svc := &Service{sources: []ports.DetectionSource{contextFailingSource{err: err}, later}}
			_, _, got := svc.scanWithSources(context.Background(), &sbom.SBOM{}, newScanDebugTrace(func([]ports.ScanDebugEvent) {}))
			if !errors.Is(got, err) {
				t.Fatalf("error=%v, want %v", got, err)
			}
			if later.calls != 0 {
				t.Fatalf("later source ran %d times", later.calls)
			}
		})
	}
}

func TestDetectionInterruptionRetainsEarlierSourceFindings(t *testing.T) {
	raw := vulnerability.RawFinding{Source: "healthy", AdvisoryID: "CVE-2026-1", Component: "pkg", Version: "1.0.0", Severity: shared.SeverityHigh}
	for _, imported := range []bool{false, true} {
		t.Run(map[bool]string{false: "source", true: "imported"}[imported], func(t *testing.T) {
			svc := newSvc(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAcquirer{dir: t.TempDir()}, &fakeAudit{}, &fakeDetector{})
			svc.sources = []ports.DetectionSource{staticVuln{raw}, contextFailingSource{err: context.DeadlineExceeded}}
			doc := &sbom.SBOM{TargetRef: "myrepo", Components: []sbom.Component{{Name: "pkg", Version: "1.0.0", PURL: "pkg:npm/pkg@1.0.0"}}}
			svc.sbomGen = staticSBOM{doc: doc}
			var result *ScanResult
			var err error
			if imported {
				result, err = svc.runImportedSBOMPipeline(context.Background(), "operator", "e1", time.Unix(0, 0).UTC(), importedsbom.Record{TargetRef: "myrepo"}, doc, ScanOptions{Mode: ScanModeFull}, func(string, int, []ports.ScanDebugEvent) {}, "")
			} else {
				result, err = svc.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "myrepo"})
			}
			if !errors.Is(err, context.DeadlineExceeded) || result == nil {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if len(result.Vulnerabilities) != 1 || result.Vulnerabilities[0].ID != raw.AdvisoryID {
				t.Fatalf("earlier source finding was lost: %+v", result.Vulnerabilities)
			}
			outcome, _ := result.engineOutcome("sca")
			if outcome.Execution != scanrun.EngineTimedOut || outcome.Coverage != scanrun.CoveragePartial {
				t.Fatalf("sca outcome=%+v", outcome)
			}
		})
	}
}

type rootFSFailingOwnedSBOM struct{ rootfs string }

func (g rootFSFailingOwnedSBOM) Generate(_ context.Context, ref string) (*sbom.SBOM, error) {
	if ref == g.rootfs {
		return nil, errors.New("rootfs manifests unavailable")
	}
	return &sbom.SBOM{Source: "ownsbom", TargetRef: ref}, nil
}

func TestOwnedImageRootFSManifestFailureMakesInventoryPartial(t *testing.T) {
	rootfs := t.TempDir()
	svc := newSvc(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAcquirer{dir: t.TempDir(), rootfs: rootfs, image: &sbom.ImageInfo{}}, &fakeAudit{}, &fakeDetector{})
	svc.sbomGen = rootFSFailingOwnedSBOM{rootfs: rootfs}
	result, err := svc.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "myrepo"})
	if err != nil {
		t.Fatal(err)
	}
	inventory, ok := result.engineOutcome("inventory")
	if !ok || inventory.Coverage != scanrun.CoveragePartial || inventory.Reason != scanrun.ReasonAnalysisIncomplete {
		t.Fatalf("inventory outcome=%+v", inventory)
	}
	if result.EngineCoverage.Complete() || result.Completeness.Confident {
		t.Fatalf("rootfs inventory failure appeared complete: coverage=%+v completeness=%+v", result.EngineCoverage, result.Completeness)
	}
}

func TestImportedSealFailureReturnsCompletedEngineFacts(t *testing.T) {
	clock := fakeClock{t: time.Unix(0, 0).UTC()}
	vault, err := evidenceuc.NewService(&fakeEvidence{err: errors.New("evidence unavailable")}, nil, &fakeAudit{}, clock, fakeIDs{})
	if err != nil {
		t.Fatal(err)
	}
	svc := newSvc(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, clock, &fakeAcquirer{dir: t.TempDir()}, &fakeAudit{}, &fakeDetector{})
	svc.evidence = vault
	doc := &sbom.SBOM{TargetRef: "myrepo", Components: []sbom.Component{{Name: "pkg", Version: "1", PURL: "pkg:npm/pkg@1"}}}
	result, err := svc.runImportedSBOMPipeline(context.Background(), "operator", "e1", clock.t, importedsbom.Record{TargetRef: "myrepo"}, doc, ScanOptions{Mode: ScanModeFull}, func(string, int, []ports.ScanDebugEvent) {}, "evidence")
	if err == nil || result == nil {
		t.Fatalf("seal failure result=%+v err=%v", result, err)
	}
	for _, engine := range []string{"inventory", "dependency_resolution", "sca", "licenses"} {
		outcome, ok := result.engineOutcome(engine)
		if !ok || outcome.Execution != scanrun.EngineCompleted {
			t.Fatalf("%s outcome=%+v", engine, outcome)
		}
	}
}

func TestFailedJobRetainsCompletedCoreEngines(t *testing.T) {
	jobs := newFakeJobStore()
	svc := newAsyncSvc(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAcquirer{dir: t.TempDir()}, &fakeAudit{}, &fakeDetector{}, jobs, fakeIDs{})
	svc.sources = []ports.DetectionSource{failingVuln{err: errors.New("source unavailable")}}
	svc.strictSources = true
	job := ports.ScanJob{ID: "job", EngagementID: "e1", Status: ports.ScanRunning, StartedAt: time.Unix(0, 0).UTC()}
	if err := jobs.CreateRunning(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	if err := svc.runScanJob(shared.WithTenant(context.Background(), shared.DefaultTenant), "operator", "e1", job.StartedAt, ports.AcquireRequest{Kind: ports.TargetLocal, Value: "myrepo"}, ScanOptions{Mode: ScanModeFull}, job); err != nil {
		t.Fatal(err)
	}
	got, err := jobs.GetJob(context.Background(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != ports.ScanFailed {
		t.Fatalf("job status %s", got.Status)
	}
	result := &ScanResult{EngineOutcomes: got.EngineOutcomes}
	for engine, execution := range map[string]scanrun.EngineExecution{"inventory": scanrun.EngineCompleted, "dependency_resolution": scanrun.EngineCompleted, "sca": scanrun.EngineFailed, "licenses": scanrun.EngineNotRun} {
		outcome, ok := result.engineOutcome(engine)
		if !ok || outcome.Execution != execution {
			t.Fatalf("%s outcome %+v, want %s", engine, outcome, execution)
		}
	}
}

type deadlineSAST struct{ calls int }

func (*deadlineSAST) Name() string { return "deadline-sast" }
func (s *deadlineSAST) AnalyzeSource(ctx context.Context, _ string) ([]ports.SASTRawFinding, error) {
	s.calls++
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestExpiredSourceBudgetDoesNotInvokeLaterEngines(t *testing.T) {
	svc := newSvc(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAcquirer{dir: t.TempDir()}, &fakeAudit{}, &fakeDetector{})
	sast := &deadlineSAST{}
	secrets := &countingSecretScanner{}
	iac := &recordingMisconfigScanner{}
	svc.SetSASTAnalyzer(sast)
	svc.SetSecretScanner(secrets)
	svc.SetMisconfigScanner(iac)
	svc.timeout = 10 * time.Millisecond
	result, err := svc.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "myrepo"})
	if err != nil {
		t.Fatal(err)
	}
	if sast.calls != 1 || secrets.calls != 0 || len(iac.roots) != 0 {
		t.Fatalf("invocations: sast=%d secrets=%d iac=%v", sast.calls, secrets.calls, iac.roots)
	}
	for _, engine := range []string{"secrets", "iac"} {
		outcome, _ := result.engineOutcome(engine)
		if outcome.Execution != scanrun.EngineNotRun || outcome.Reason != scanrun.ReasonBudgetExhausted {
			t.Fatalf("later %s outcome %+v", engine, outcome)
		}
	}
	outcome, _ := result.engineOutcome("sast")
	if outcome.Execution != scanrun.EngineTimedOut {
		t.Fatalf("interrupted sast %+v", outcome)
	}
	inventory, _ := result.engineOutcome("inventory")
	if inventory.Execution != scanrun.EngineCompleted {
		t.Fatalf("discarded completed inventory %+v", inventory)
	}
	for _, warning := range []string{
		stageBudgetWarning("static analysis"),
		stageBudgetWarning("secret scan"),
		stageBudgetWarning("infrastructure-as-code scan"),
	} {
		if !containsWarning(result.SourceWarnings, warning) {
			t.Fatalf("source warnings %q missing legacy deadline warning %q", result.SourceWarnings, warning)
		}
	}
}

func TestSkippedSourceDeadlineWarningDoesNotTreatCancellationAsBudgetExhausted(t *testing.T) {
	result := &ScanResult{EngineOutcomes: []scanrun.EngineOutcome{{
		Engine: "secrets", Required: true, Execution: scanrun.EngineNotRun,
		Coverage: scanrun.CoverageUnknown, Reason: scanrun.ReasonBudgetExhausted,
	}}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	skipped, err := result.skipEngineForContext("secrets", ctx)
	if !skipped || !errors.Is(err, context.Canceled) {
		t.Fatalf("skip cancellation = (%t, %v)", skipped, err)
	}
	result.appendDeadlineWarningForSkippedSourceEngine("secrets")
	if len(result.SourceWarnings) != 0 {
		t.Fatalf("caller cancellation must not fabricate a deadline warning: %q", result.SourceWarnings)
	}
}

type countingHistorySecretScanner struct {
	calls        int
	historyCalls int
}

func (*countingHistorySecretScanner) Name() string { return "counting-history-secret-scanner" }
func (s *countingHistorySecretScanner) ScanFiles(context.Context, string) (ports.SecretScanReport, error) {
	s.calls++
	return ports.SecretScanReport{}, nil
}
func (s *countingHistorySecretScanner) ScanHistory(context.Context, string) (ports.SecretScanReport, error) {
	s.historyCalls++
	return ports.SecretScanReport{}, nil
}

func TestExpiredSourceBudgetSkipsSelectedSecretHistoryWithSecrets(t *testing.T) {
	svc := newSvc(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAcquirer{dir: t.TempDir()}, &fakeAudit{}, &fakeDetector{})
	sast := &deadlineSAST{}
	secrets := &countingHistorySecretScanner{}
	svc.SetSASTAnalyzer(sast)
	svc.SetSecretScanner(secrets)
	svc.SetSecretHistoryEnabled(true)
	svc.timeout = 10 * time.Millisecond
	result, err := svc.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "myrepo"})
	if err != nil {
		t.Fatal(err)
	}
	if sast.calls != 1 || secrets.calls != 0 || secrets.historyCalls != 0 {
		t.Fatalf("invocations: sast=%d secrets=%d history=%d", sast.calls, secrets.calls, secrets.historyCalls)
	}
	for _, engine := range []string{"secrets", "secret_history"} {
		outcome, _ := result.engineOutcome(engine)
		if outcome.Execution != scanrun.EngineNotRun || outcome.Reason != scanrun.ReasonBudgetExhausted {
			t.Fatalf("%s outcome %+v, want not_run/budget_exhausted", engine, outcome)
		}
	}
	if !containsWarning(result.SourceWarnings, "git-history secret scan skipped: "+context.DeadlineExceeded.Error()) {
		t.Fatalf("source warnings %q missing history deadline warning", result.SourceWarnings)
	}
}

func TestExpiredSourceBudgetPreservesIneligibleSecretHistoryPlan(t *testing.T) {
	run := func(t *testing.T, scanner ports.SecretScanner, historyEnabled bool, want scanrun.EngineReason) *ScanResult {
		t.Helper()
		svc := newSvc(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAcquirer{dir: t.TempDir()}, &fakeAudit{}, &fakeDetector{})
		svc.SetSASTAnalyzer(&deadlineSAST{})
		svc.SetSecretScanner(scanner)
		svc.SetSecretHistoryEnabled(historyEnabled)
		svc.timeout = 10 * time.Millisecond
		result, err := svc.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "myrepo"})
		if err != nil {
			t.Fatal(err)
		}
		history, _ := result.engineOutcome("secret_history")
		if history.Execution != scanrun.EngineNotRun || history.Reason != want {
			t.Fatalf("history outcome %+v, want not_run/%s", history, want)
		}
		for _, warning := range result.SourceWarnings {
			if warning == "git-history secret scan skipped: "+context.DeadlineExceeded.Error() {
				t.Fatalf("ineligible history must not emit a deadline warning: %q", result.SourceWarnings)
			}
		}
		return result
	}

	t.Run("unsupported enabled", func(t *testing.T) {
		secrets := &countingSecretScanner{}
		run(t, secrets, true, scanrun.ReasonUnavailable)
		if secrets.calls != 0 {
			t.Fatalf("expired secret scanner calls=%d", secrets.calls)
		}
	})
	t.Run("supported disabled", func(t *testing.T) {
		secrets := &countingHistorySecretScanner{}
		run(t, secrets, false, scanrun.ReasonNotSelected)
		if secrets.calls != 0 || secrets.historyCalls != 0 {
			t.Fatalf("expired secret scanner calls=%d history=%d", secrets.calls, secrets.historyCalls)
		}
	})
}

type deadlineHistorySecretScanner struct {
	calls        int
	historyCalls int
}

func (*deadlineHistorySecretScanner) Name() string { return "deadline-history-secret-scanner" }
func (s *deadlineHistorySecretScanner) ScanFiles(ctx context.Context, _ string) (ports.SecretScanReport, error) {
	s.calls++
	<-ctx.Done()
	return ports.SecretScanReport{}, ctx.Err()
}
func (s *deadlineHistorySecretScanner) ScanHistory(context.Context, string) (ports.SecretScanReport, error) {
	s.historyCalls++
	return ports.SecretScanReport{}, nil
}

func TestExpiredSecretScanBudgetSkipsSelectedHistoryWithLegacyWarning(t *testing.T) {
	svc := newSvc(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAcquirer{dir: t.TempDir()}, &fakeAudit{}, &fakeDetector{})
	secrets := &deadlineHistorySecretScanner{}
	svc.SetSecretScanner(secrets)
	svc.SetSecretHistoryEnabled(true)
	svc.timeout = 10 * time.Millisecond
	result, err := svc.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "myrepo"})
	if err != nil {
		t.Fatal(err)
	}
	if secrets.calls != 1 || secrets.historyCalls != 0 {
		t.Fatalf("invocations: secrets=%d history=%d", secrets.calls, secrets.historyCalls)
	}
	secret, _ := result.engineOutcome("secrets")
	if secret.Execution != scanrun.EngineTimedOut || secret.Reason != scanrun.ReasonDeadlineExceeded {
		t.Fatalf("secrets outcome %+v, want timed_out/deadline_exceeded", secret)
	}
	history, _ := result.engineOutcome("secret_history")
	if history.Execution != scanrun.EngineNotRun || history.Reason != scanrun.ReasonBudgetExhausted {
		t.Fatalf("history outcome %+v, want not_run/budget_exhausted", history)
	}
	if !containsWarning(result.SourceWarnings, "git-history secret scan skipped: "+context.DeadlineExceeded.Error()) {
		t.Fatalf("source warnings %q missing history deadline warning", result.SourceWarnings)
	}
}

type deadlineUnsupportedHistorySecretScanner struct{ calls int }

func (*deadlineUnsupportedHistorySecretScanner) Name() string {
	return "deadline-unsupported-history-secret-scanner"
}
func (s *deadlineUnsupportedHistorySecretScanner) ScanFiles(ctx context.Context, _ string) (ports.SecretScanReport, error) {
	s.calls++
	<-ctx.Done()
	return ports.SecretScanReport{}, ctx.Err()
}

func TestExpiredSecretScanBudgetPreservesUnavailableHistory(t *testing.T) {
	svc := newSvc(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAcquirer{dir: t.TempDir()}, &fakeAudit{}, &fakeDetector{})
	secrets := &deadlineUnsupportedHistorySecretScanner{}
	svc.SetSecretScanner(secrets)
	svc.SetSecretHistoryEnabled(true)
	svc.timeout = 10 * time.Millisecond
	result, err := svc.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "myrepo"})
	if err != nil {
		t.Fatal(err)
	}
	if secrets.calls != 1 {
		t.Fatalf("secret calls=%d", secrets.calls)
	}
	history, _ := result.engineOutcome("secret_history")
	if history.Execution != scanrun.EngineNotRun || history.Reason != scanrun.ReasonUnavailable {
		t.Fatalf("history outcome %+v, want not_run/unavailable", history)
	}
	for _, warning := range result.SourceWarnings {
		if warning == "git-history secret scan skipped: "+context.DeadlineExceeded.Error() {
			t.Fatalf("unavailable history must not emit a deadline warning: %q", result.SourceWarnings)
		}
	}
}

func TestExpiredSecretScanBudgetPreservesDisabledHistory(t *testing.T) {
	svc := newSvc(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAcquirer{dir: t.TempDir()}, &fakeAudit{}, &fakeDetector{})
	secrets := &deadlineHistorySecretScanner{}
	svc.SetSecretScanner(secrets)
	svc.timeout = 10 * time.Millisecond
	result, err := svc.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "myrepo"})
	if err != nil {
		t.Fatal(err)
	}
	if secrets.calls != 1 || secrets.historyCalls != 0 {
		t.Fatalf("invocations: secrets=%d history=%d", secrets.calls, secrets.historyCalls)
	}
	history, _ := result.engineOutcome("secret_history")
	if history.Execution != scanrun.EngineNotRun || history.Reason != scanrun.ReasonNotSelected {
		t.Fatalf("history outcome %+v, want not_run/not_selected", history)
	}
	for _, warning := range result.SourceWarnings {
		if warning == "git-history secret scan skipped: "+context.DeadlineExceeded.Error() {
			t.Fatalf("disabled history must not emit a deadline warning: %q", result.SourceWarnings)
		}
	}
}

type historyDeadlineSecretScanner struct{ historyCalls int }

func (*historyDeadlineSecretScanner) Name() string { return "history-deadline-secret-scanner" }
func (*historyDeadlineSecretScanner) ScanFiles(context.Context, string) (ports.SecretScanReport, error) {
	return ports.SecretScanReport{}, nil
}
func (s *historyDeadlineSecretScanner) ScanHistory(context.Context, string) (ports.SecretScanReport, error) {
	s.historyCalls++
	return ports.SecretScanReport{}, fmt.Errorf("history scan: %w", context.DeadlineExceeded)
}

func TestRunningSecretHistoryDeadlineKeepsLegacyWarning(t *testing.T) {
	svc := newSvc(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAcquirer{dir: t.TempDir()}, &fakeAudit{}, &fakeDetector{})
	secrets := &historyDeadlineSecretScanner{}
	svc.SetSecretScanner(secrets)
	svc.SetSecretHistoryEnabled(true)
	result, err := svc.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "myrepo"})
	if err != nil {
		t.Fatal(err)
	}
	if secrets.historyCalls != 1 {
		t.Fatalf("history calls=%d", secrets.historyCalls)
	}
	history, _ := result.engineOutcome("secret_history")
	if history.Execution != scanrun.EngineTimedOut || history.Reason != scanrun.ReasonDeadlineExceeded {
		t.Fatalf("history outcome %+v, want timed_out/deadline_exceeded", history)
	}
	want := "git-history secret scan skipped: history scan: " + context.DeadlineExceeded.Error()
	if !containsWarning(result.SourceWarnings, want) {
		t.Fatalf("source warnings %q missing history deadline warning %q", result.SourceWarnings, want)
	}
}

func containsWarning(warnings []string, want string) bool {
	for _, warning := range warnings {
		if warning == want {
			return true
		}
	}
	return false
}

type filesystemSecretScanner struct {
	root      string
	truncated bool
	err       error
}

func (*filesystemSecretScanner) Name() string { return "filesystem-secrets" }
func (s *filesystemSecretScanner) ScanFiles(_ context.Context, path string) (ports.SecretScanReport, error) {
	if path == s.root {
		return ports.SecretScanReport{Truncated: s.truncated}, s.err
	}
	return ports.SecretScanReport{}, nil
}

type filesystemMisconfigScanner struct {
	root      string
	truncated bool
	err       error
}

func (*filesystemMisconfigScanner) Name() string { return "filesystem-iac" }
func (s *filesystemMisconfigScanner) ScanConfigs(ctx context.Context, path string) ([]ports.MisconfigRawFinding, error) {
	report, err := s.ScanConfigsReport(ctx, path)
	return report.Findings, err
}
func (s *filesystemMisconfigScanner) ScanConfigsReport(_ context.Context, path string) (ports.MisconfigScanReport, error) {
	if path == s.root {
		return ports.MisconfigScanReport{Truncated: s.truncated}, s.err
	}
	return ports.MisconfigScanReport{}, nil
}

func TestFilesystemSecondPassCannotEraseCoverageGaps(t *testing.T) {
	for _, tc := range []struct {
		name      string
		truncated bool
		err       error
	}{{"truncated", true, nil}, {"failed", false, errors.New("filesystem failure")}} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			svc := newSvc(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAcquirer{dir: t.TempDir(), rootfs: root, image: &sbom.ImageInfo{}}, &fakeAudit{}, &fakeDetector{})
			svc.SetSecretScanner(&filesystemSecretScanner{root: root, truncated: tc.truncated, err: tc.err})
			svc.SetMisconfigScanner(&filesystemMisconfigScanner{root: root, truncated: tc.truncated, err: tc.err})
			result, err := svc.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "myrepo"})
			if err != nil {
				t.Fatal(err)
			}
			for _, engine := range []string{"secrets", "iac"} {
				outcome, _ := result.engineOutcome(engine)
				if outcome.Coverage != scanrun.CoveragePartial || !outcome.Required {
					t.Fatalf("%s lost filesystem gap: %+v", engine, outcome)
				}
			}
			if result.EngineCoverage.Complete() {
				t.Fatal("incomplete filesystem promoted to complete coverage")
			}
		})
	}
}
