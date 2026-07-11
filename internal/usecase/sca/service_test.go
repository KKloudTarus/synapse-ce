package sca

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/importedsbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	evidenceuc "github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeEngRepo struct {
	eng *engdom.Engagement
	err error
}

func (f *fakeEngRepo) Create(context.Context, *engdom.Engagement) error { return nil }
func (f *fakeEngRepo) Update(context.Context, *engdom.Engagement) error { return nil }
func (f *fakeEngRepo) Delete(context.Context, shared.ID) error          { return nil }
func (f *fakeEngRepo) GetByID(context.Context, shared.ID) (*engdom.Engagement, error) {
	return f.eng, f.err
}
func (f *fakeEngRepo) GetByIDInTenant(context.Context, shared.ID, shared.ID) (*engdom.Engagement, error) {
	return f.eng, f.err
}
func (f *fakeEngRepo) List(context.Context, shared.ID) ([]*engdom.Engagement, error) {
	return nil, nil
}

type fakeClock struct{ t time.Time }

func (c fakeClock) Now() time.Time { return c.t }

type fakeAudit struct{ entries []ports.AuditEntry }

func (f *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	f.entries = append(f.entries, e)
	return nil
}

type fakeAcquirer struct {
	dir     string
	cleaned int
	called  bool
}

func (f *fakeAcquirer) Acquire(_ context.Context, _ ports.AcquireRequest) (*ports.Workspace, error) {
	f.called = true
	return &ports.Workspace{Dir: f.dir, Cleanup: func() error { f.cleaned++; return nil }}, nil
}

type fakeDetector struct{ gotPath string }

func (f *fakeDetector) Detect(_ context.Context, p string) ([]ports.DetectedLanguage, error) {
	f.gotPath = p
	return []ports.DetectedLanguage{{Name: "Go", Percent: 100}}, nil
}

type fakeSBOM struct{}

func (fakeSBOM) Generate(_ context.Context, ref string) (*sbom.SBOM, error) {
	return &sbom.SBOM{TargetRef: ref}, nil
}

type staticSBOM struct{ doc *sbom.SBOM }

func (s staticSBOM) Generate(context.Context, string) (*sbom.SBOM, error) { return s.doc, nil }

type countingSBOM struct{ calls int }

func (s *countingSBOM) Generate(context.Context, string) (*sbom.SBOM, error) {
	s.calls++
	return &sbom.SBOM{}, nil
}

type fakeVuln struct{}

func (fakeVuln) Name() string { return "fake" }
func (fakeVuln) Scan(_ context.Context, _ *sbom.SBOM) ([]vulnerability.RawFinding, error) {
	return nil, nil
}

type failingVuln struct{ err error }

func (f failingVuln) Name() string { return "failing-source" }
func (f failingVuln) Scan(context.Context, *sbom.SBOM) ([]vulnerability.RawFinding, error) {
	return nil, f.err
}

type countingVuln struct{ calls int }

func (c *countingVuln) Name() string { return "counting" }
func (c *countingVuln) Scan(context.Context, *sbom.SBOM) ([]vulnerability.RawFinding, error) {
	c.calls++
	return []vulnerability.RawFinding{{Source: "counting", AdvisoryID: "CVE-1", Component: "pkg", Version: "1.0.0", Severity: shared.SeverityHigh}}, nil
}

type fakeLic struct{}

func (fakeLic) Scan(_ context.Context, _ *sbom.SBOM) ([]ports.LicenseFinding, error) {
	return nil, nil
}

type staticLic struct{ findings []ports.LicenseFinding }

func (s staticLic) Scan(context.Context, *sbom.SBOM) ([]ports.LicenseFinding, error) {
	return s.findings, nil
}

type countingLic struct{ calls int }

func (c *countingLic) Scan(context.Context, *sbom.SBOM) ([]ports.LicenseFinding, error) {
	c.calls++
	return []ports.LicenseFinding{{License: "MIT", Category: sbom.LicensePermissive, Verdict: ports.LicenseAllow, Components: []string{"pkg"}}}, nil
}

func engagementWithScope(t *testing.T, inScope ...string) *engdom.Engagement {
	t.Helper()
	e, err := engdom.New("e1", "", "test", "", time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	var ts []engdom.Target
	for _, v := range inScope {
		ts = append(ts, engdom.Target{Kind: engdom.TargetRepo, Value: v})
	}
	e.Scope = engdom.Scope{InScope: ts}
	return e
}

func newSvc(repo ports.EngagementRepository, clk ports.Clock, acq ports.Acquirer, audit ports.AuditLogger, det ports.LanguageDetector) *Service {
	return NewService(repo, nil, nil, nil, nil, nil, nil, nil, ports.Provenance{}, clk, audit, shared.SeverityHigh, 0, acq, det, fakeSBOM{}, []ports.DetectionSource{fakeVuln{}}, nil, fakeLic{}, nil)
}

func newSvcWithSources(repo ports.EngagementRepository, clk ports.Clock, acq ports.Acquirer, audit ports.AuditLogger, det ports.LanguageDetector, sources []ports.DetectionSource) *Service {
	return NewService(repo, nil, nil, nil, nil, nil, nil, nil, ports.Provenance{}, clk, audit, shared.SeverityHigh, 0, acq, det, fakeSBOM{}, sources, nil, fakeLic{}, nil)
}

func TestScanInScopeRunsAndAudits(t *testing.T) {
	repo := &fakeEngRepo{eng: engagementWithScope(t, "myrepo")}
	acq := &fakeAcquirer{dir: "/tmp/ws"}
	audit := &fakeAudit{}
	det := &fakeDetector{}
	svc := newSvc(repo, fakeClock{t: time.Unix(0, 0).UTC()}, acq, audit, det)

	res, err := svc.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: "local", Value: "myrepo"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.Target != "myrepo" {
		t.Errorf("result target = %q, want myrepo", res.Target)
	}
	if det.gotPath != "/tmp/ws" {
		t.Errorf("detector scanned %q, want workspace dir", det.gotPath)
	}
	if acq.cleaned != 1 {
		t.Errorf("workspace cleanup ran %d times, want 1", acq.cleaned)
	}
	if len(audit.entries) != 1 || audit.entries[0].Action != "sca.scan" || audit.entries[0].Actor != "operator" {
		t.Errorf("want one attributed sca.scan audit entry, got %+v", audit.entries)
	}
	if len(res.DebugEvents) == 0 {
		t.Fatal("scan result should include debug trace events")
	}
	assertDebugEvent(t, res.DebugEvents, stageVulns, "fake", ports.ScanDebugSucceeded)
	assertDebugEvent(t, res.DebugEvents, stageLicense, "license-policy", ports.ScanDebugSucceeded)
}

func TestScanStampsSBOMCreationTime(t *testing.T) {
	// The producers (fakeSBOM here) return an SBOM with no creation time; the pipeline must stamp it from
	// the scan clock so the NTIA "timestamp" minimum element is present on Synapse's own SBOM.
	repo := &fakeEngRepo{eng: engagementWithScope(t, "myrepo")}
	clkTime := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	svc := newSvc(repo, fakeClock{t: clkTime}, &fakeAcquirer{dir: "/tmp/ws"}, &fakeAudit{}, &fakeDetector{})

	res, err := svc.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: "local", Value: "myrepo"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.SBOM == nil {
		t.Fatal("scan result has no SBOM")
	}
	if res.SBOM.Audit.CreatedAt.IsZero() {
		t.Error("SBOM creation time (NTIA minimum element) must be stamped, got zero")
	}
	if !res.SBOM.Audit.CreatedAt.Equal(clkTime) {
		t.Errorf("SBOM CreatedAt = %v, want scan clock %v", res.SBOM.Audit.CreatedAt, clkTime)
	}
	if q := res.SBOMQuality; q.Score > 0 { // and the quality scorer must now credit the timestamp element
		for _, e := range q.Elements {
			if e.ID == "ntia-timestamp" && e.Score != 100 {
				t.Errorf("ntia-timestamp element = %d, want 100 once the SBOM is stamped", e.Score)
			}
		}
	}
}

func TestScanUsesImportedSBOMWithoutAcquiringTarget(t *testing.T) {
	store := memory.NewImportedSBOMStore()
	data := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","metadata":{"component":{"name":"product-service"}},"components":[{"name":"pkg","version":"1.0.0","purl":"pkg:npm/pkg@1.0.0","licenses":[{"license":{"id":"MIT"}}]}],"dependencies":[{"ref":"pkg:npm/pkg@1.0.0","dependsOn":[]}]}`)
	if _, err := parseCycloneDX(data); err != nil {
		t.Fatalf("fixture parse: %v", err)
	}
	if err := store.SaveActive(context.Background(), importedsbom.Record{
		ID:              "sbom-1",
		TenantID:        "tenant-1",
		EngagementID:    "e1",
		Filename:        "SBOM.json",
		Format:          importedsbom.FormatCycloneDX,
		SpecVersion:     "1.4",
		TargetRef:       "product-service",
		ComponentCount:  1,
		DependencyCount: 1,
		SHA256:          hashHex(data),
		RawJSON:         data,
		CreatedBy:       "operator",
		CreatedAt:       time.Unix(100, 0).UTC(),
	}); err != nil {
		t.Fatalf("SaveActive: %v", err)
	}

	eng := engagementWithScope(t, "myrepo")
	eng.TenantID = "tenant-1"
	acq := &fakeAcquirer{dir: "/tmp/ws"}
	det := &fakeDetector{}
	gen := &countingSBOM{}
	vuln := &countingVuln{}
	lic := &countingLic{}
	svc := NewService(&fakeEngRepo{eng: eng}, nil, nil, nil, nil, nil, nil, nil, ports.Provenance{VulnDBSource: "osv.dev"}, fakeClock{t: time.Unix(200, 0).UTC()}, &fakeAudit{}, shared.SeverityHigh, 0, acq, det, gen, []ports.DetectionSource{vuln}, nil, lic, nil)
	svc.SetImportedSBOMStore(store)

	res, err := svc.ScanWithOptions(context.Background(), "operator", "e1", ports.AcquireRequest{}, ScanOptions{Mode: ScanModeFull})
	if err != nil {
		t.Fatalf("ScanWithOptions: %v", err)
	}
	if acq.called || det.gotPath != "" || gen.calls != 0 {
		t.Fatalf("workspace path was used: acq=%v det=%q sbomCalls=%d", acq.called, det.gotPath, gen.calls)
	}
	if vuln.calls != 1 || lic.calls != 1 {
		t.Fatalf("scanner calls vuln/lic = %d/%d, want 1/1", vuln.calls, lic.calls)
	}
	if res.Target != "product-service" || len(res.SBOM.Components) != 1 || len(res.SBOM.Dependencies) != 1 {
		t.Fatalf("result imported SBOM = target %q comps %d deps %d", res.Target, len(res.SBOM.Components), len(res.SBOM.Dependencies))
	}
}

func assertDebugEvent(t *testing.T, events []ports.ScanDebugEvent, stage, step string, status ports.ScanDebugStatus) {
	t.Helper()
	for _, ev := range events {
		if ev.Stage == stage && ev.Step == step && ev.Status == status {
			if ev.DurationMS < 0 {
				t.Fatalf("event %s/%s has negative duration: %d", stage, step, ev.DurationMS)
			}
			return
		}
	}
	t.Fatalf("missing debug event %s/%s/%s in %+v", stage, step, status, events)
}

func TestScanOutOfScopeForbidden(t *testing.T) {
	repo := &fakeEngRepo{eng: engagementWithScope(t, "allowed")}
	acq := &fakeAcquirer{dir: "/tmp/ws"}
	svc := newSvc(repo, fakeClock{t: time.Unix(0, 0).UTC()}, acq, &fakeAudit{}, &fakeDetector{})

	_, err := svc.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Value: "not-allowed"})
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("want ErrForbidden, got %v", err)
	}
	if acq.called {
		t.Error("acquirer must not run for an out-of-scope target")
	}
}

func TestScanDebugTraceCapturesVulnerabilitySourceFailure(t *testing.T) {
	repo := &fakeEngRepo{eng: engagementWithScope(t, "myrepo")}
	svc := newSvcWithSources(repo, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAcquirer{dir: "/tmp/ws"}, &fakeAudit{}, &fakeDetector{}, []ports.DetectionSource{failingVuln{err: errors.New("database unavailable")}})

	var events []ports.ScanDebugEvent
	_, err := svc.runPipeline(context.Background(), "operator", "e1", time.Unix(0, 0).UTC(), ports.AcquireRequest{Kind: "local", Value: "myrepo"}, ScanOptions{Mode: ScanModeFull}, func(_ string, _ int, evs []ports.ScanDebugEvent) {
		events = evs
	})
	if err == nil {
		t.Fatal("runPipeline should fail when a vulnerability source fails")
	}
	assertDebugEvent(t, events, stageVulns, "failing-source", ports.ScanDebugFailed)
}

func TestScanResultIncludesComponentLicenseAuditAndCoverageBreakdown(t *testing.T) {
	doc := &sbom.SBOM{Components: []sbom.Component{
		{
			Name:              "prod-lib",
			Version:           "1.0.0",
			PURL:              "pkg:npm/prod-lib@1.0.0",
			Scope:             sbom.ScopeProduction,
			Location:          "package-lock.json",
			Licenses:          []sbom.License{{SPDXID: "MIT"}},
			LicenseSource:     "sbom",
			LicenseConfidence: "declared",
		},
		{
			Name:              "prod-mystery",
			Version:           "2.0.0",
			PURL:              "pkg:maven/org.example/prod-mystery@2.0.0",
			Scope:             sbom.ScopeProduction,
			Location:          "pom.xml",
			UnknownReason:     sbom.ReasonMetadataMissing,
			LicenseConfidence: "unknown",
		},
		{
			Name:              "docs-mystery",
			Version:           "3.0.0",
			PURL:              "pkg:pypi/docs-mystery@3.0.0",
			Scope:             sbom.ScopeDocumentation,
			Location:          "docs/requirements.txt",
			UnknownReason:     sbom.ReasonNoLicenseDeclared,
			LicenseConfidence: "unknown",
		},
	}}
	svc := NewService(
		&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, nil, nil, nil, nil, nil, nil, nil,
		ports.Provenance{}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAudit{}, shared.SeverityHigh, 0,
		&fakeAcquirer{dir: "/tmp/ws"}, &fakeDetector{}, staticSBOM{doc: doc}, []ports.DetectionSource{fakeVuln{}}, nil,
		staticLic{findings: []ports.LicenseFinding{{License: "MIT", Category: sbom.LicensePermissive, Verdict: ports.LicenseAllow, Components: []string{"prod-lib"}}}}, nil,
	)

	res, err := svc.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: "local", Value: "myrepo"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.ComponentLicenses) != 3 {
		t.Fatalf("component_licenses len = %d, want 3: %+v", len(res.ComponentLicenses), res.ComponentLicenses)
	}
	if got := res.ComponentLicenses[0]; got.Component != "prod-lib" || got.License != "MIT" || got.Verdict != ports.LicenseAllow || got.Scope != sbom.ScopeProduction {
		t.Errorf("prod-lib audit = %+v, want MIT allow production", got)
	}
	if got := res.ComponentLicenses[1]; got.Component != "prod-mystery" || got.License != "" || got.Verdict != ports.LicenseWarn || got.UnknownReason != sbom.ReasonMetadataMissing {
		t.Errorf("prod-mystery audit = %+v, want unknown warn metadata_missing", got)
	}
	if res.LicenseCoverageBreakdown.ProductionUnknown != 1 {
		t.Errorf("production_unknown = %d, want 1", res.LicenseCoverageBreakdown.ProductionUnknown)
	}
	if got := res.LicenseCoverageBreakdown.ByScope[sbom.ScopeProduction]; got.Total != 2 || got.Detected != 1 || got.Unknown != 1 {
		t.Errorf("production coverage = %+v, want 2/1/1", got)
	}
	if got := res.LicenseCoverageBreakdown.ByEcosystem["npm"]; got.Total != 1 || got.Detected != 1 || got.Unknown != 0 {
		t.Errorf("npm coverage = %+v, want 1/1/0", got)
	}
}

func TestScanWithOptionsLicenseOnlySkipsVulnerabilitySources(t *testing.T) {
	vulnSrc := &countingVuln{}
	licScan := &countingLic{}
	svc := NewService(
		&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, nil, nil, nil, nil, nil, nil, nil,
		ports.Provenance{}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAudit{}, shared.SeverityHigh, 0,
		&fakeAcquirer{dir: "/tmp/ws"}, &fakeDetector{}, staticSBOM{doc: &sbom.SBOM{Components: []sbom.Component{{Name: "pkg", Version: "1.0.0", PURL: "pkg:npm/pkg@1.0.0", Licenses: []sbom.License{{SPDXID: "MIT"}}}}}},
		[]ports.DetectionSource{vulnSrc}, nil, licScan, nil,
	)

	res, err := svc.ScanWithOptions(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: "local", Value: "myrepo"}, ScanOptions{Mode: ScanModeLicenses})
	if err != nil {
		t.Fatalf("ScanWithOptions: %v", err)
	}
	if vulnSrc.calls != 0 {
		t.Fatalf("vulnerability source calls = %d, want 0", vulnSrc.calls)
	}
	if licScan.calls != 1 {
		t.Fatalf("license scanner calls = %d, want 1", licScan.calls)
	}
	if res.ScanMode != ScanModeLicenses || len(res.Vulnerabilities) != 0 || len(res.Licenses) != 1 {
		t.Fatalf("result mode/vulns/licenses = %q/%d/%d, want licenses/0/1", res.ScanMode, len(res.Vulnerabilities), len(res.Licenses))
	}
}

func TestStartScanWithOptionsLicenseOnlySkipsVulnerabilitySources(t *testing.T) {
	vulnSrc := &countingVuln{}
	licScan := &countingLic{}
	jobs := newFakeJobStore()
	svc := NewService(
		&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, nil, nil, nil, jobs, nil, nil, fakeIDs{},
		ports.Provenance{}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAudit{}, shared.SeverityHigh, 0,
		&fakeAcquirer{dir: "/tmp/ws"}, &fakeDetector{}, staticSBOM{doc: &sbom.SBOM{Components: []sbom.Component{{Name: "pkg", Version: "1.0.0", PURL: "pkg:npm/pkg@1.0.0", Licenses: []sbom.License{{SPDXID: "MIT"}}}}}},
		[]ports.DetectionSource{vulnSrc}, nil, licScan, nil,
	)

	job, err := svc.StartScanWithOptions(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: "local", Value: "myrepo"}, ScanOptions{Mode: ScanModeLicenses})
	if err != nil {
		t.Fatalf("StartScanWithOptions: %v", err)
	}
	for i := 0; i < 200; i++ {
		latest, err := jobs.GetJob(context.Background(), job.ID)
		if err != nil {
			t.Fatalf("GetJob: %v", err)
		}
		if latest.Status != ports.ScanRunning {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if vulnSrc.calls != 0 {
		t.Fatalf("vulnerability source calls = %d, want 0", vulnSrc.calls)
	}
	if licScan.calls != 1 {
		t.Fatalf("license scanner calls = %d, want 1", licScan.calls)
	}
	latest, err := jobs.GetJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("GetJob final: %v", err)
	}
	for _, ev := range latest.DebugEvents {
		if ev.Stage == stageVulns {
			t.Fatalf("license-only async scan should not emit vuln stage, got events %+v", latest.DebugEvents)
		}
	}
}

func TestScanWithOptionsVulnerabilitiesOnlySkipsLicenseScanner(t *testing.T) {
	vulnSrc := &countingVuln{}
	licScan := &countingLic{}
	svc := NewService(
		&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, nil, nil, nil, nil, nil, nil, nil,
		ports.Provenance{}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAudit{}, shared.SeverityHigh, 0,
		&fakeAcquirer{dir: "/tmp/ws"}, &fakeDetector{}, staticSBOM{doc: &sbom.SBOM{Components: []sbom.Component{{Name: "pkg", Version: "1.0.0", PURL: "pkg:npm/pkg@1.0.0"}}}},
		[]ports.DetectionSource{vulnSrc}, nil, licScan, nil,
	)

	res, err := svc.ScanWithOptions(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: "local", Value: "myrepo"}, ScanOptions{Mode: ScanModeVulnerabilities})
	if err != nil {
		t.Fatalf("ScanWithOptions: %v", err)
	}
	if vulnSrc.calls != 1 {
		t.Fatalf("vulnerability source calls = %d, want 1", vulnSrc.calls)
	}
	if licScan.calls != 0 {
		t.Fatalf("license scanner calls = %d, want 0", licScan.calls)
	}
	if res.ScanMode != ScanModeVulnerabilities || len(res.Vulnerabilities) != 1 || len(res.Licenses) != 0 {
		t.Fatalf("result mode/vulns/licenses = %q/%d/%d, want vulnerabilities/1/0", res.ScanMode, len(res.Vulnerabilities), len(res.Licenses))
	}
}

func TestScanWithOptionsMergesCachedComplementaryModeData(t *testing.T) {
	vulnSrc := &countingVuln{}
	licScan := &countingLic{}
	results := memory.NewScanResultStore()
	svc := NewService(
		&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, nil, nil, results, nil, nil, nil, nil,
		ports.Provenance{}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAudit{}, shared.SeverityHigh, 0,
		&fakeAcquirer{dir: "/tmp/ws"}, &fakeDetector{}, staticSBOM{doc: &sbom.SBOM{Components: []sbom.Component{{Name: "pkg", Version: "1.0.0", PURL: "pkg:npm/pkg@1.0.0", Licenses: []sbom.License{{SPDXID: "MIT"}}}}}},
		[]ports.DetectionSource{vulnSrc}, nil, licScan, nil,
	)

	first, err := svc.ScanWithOptions(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: "local", Value: "myrepo"}, ScanOptions{Mode: ScanModeVulnerabilities})
	if err != nil {
		t.Fatalf("vulnerability scan: %v", err)
	}
	if first.ScanMode != ScanModeVulnerabilities || len(first.Vulnerabilities) != 1 || len(first.Licenses) != 0 {
		t.Fatalf("first mode/vulns/licenses = %q/%d/%d, want vulnerabilities/1/0", first.ScanMode, len(first.Vulnerabilities), len(first.Licenses))
	}

	second, err := svc.ScanWithOptions(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: "local", Value: "myrepo"}, ScanOptions{Mode: ScanModeLicenses})
	if err != nil {
		t.Fatalf("license scan: %v", err)
	}
	if second.ScanMode != ScanModeFull || len(second.Vulnerabilities) != 1 || len(second.Licenses) != 1 {
		t.Fatalf("second mode/vulns/licenses = %q/%d/%d, want full/1/1", second.ScanMode, len(second.Vulnerabilities), len(second.Licenses))
	}

	data, err := svc.LatestResult(context.Background(), "e1")
	if err != nil {
		t.Fatalf("LatestResult: %v", err)
	}
	var latest ScanResult
	if err := json.Unmarshal(data, &latest); err != nil {
		t.Fatalf("decode latest: %v", err)
	}
	if latest.ScanMode != ScanModeFull || len(latest.Vulnerabilities) != 1 || len(latest.Licenses) != 1 {
		t.Fatalf("latest mode/vulns/licenses = %q/%d/%d, want full/1/1", latest.ScanMode, len(latest.Vulnerabilities), len(latest.Licenses))
	}
}

func TestScanWithOptionsInvalidMode(t *testing.T) {
	svc := newSvc(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAcquirer{dir: "/tmp/ws"}, &fakeAudit{}, &fakeDetector{})
	_, err := svc.ScanWithOptions(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: "local", Value: "myrepo"}, ScanOptions{Mode: "secrets"})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation, got %v", err)
	}
}

func TestScanOutsideAuthWindowForbidden(t *testing.T) {
	eng := engagementWithScope(t, "myrepo")
	to := time.Unix(1, 0).UTC()
	eng.AuthorizedTo = &to // window closes at t=1s
	repo := &fakeEngRepo{eng: eng}
	acq := &fakeAcquirer{dir: "/tmp/ws"}
	// clock is well after the window (beyond the 2-minute skew tolerance)
	svc := newSvc(repo, fakeClock{t: time.Unix(3600, 0).UTC()}, acq, &fakeAudit{}, &fakeDetector{})

	_, err := svc.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Value: "myrepo"})
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("want ErrForbidden (outside window), got %v", err)
	}
	if acq.called {
		t.Error("acquirer must not run outside the authorization window")
	}
}

func TestScanEngagementNotFound(t *testing.T) {
	repo := &fakeEngRepo{err: shared.ErrNotFound}
	svc := newSvc(repo, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAcquirer{}, &fakeAudit{}, &fakeDetector{})

	_, err := svc.Scan(context.Background(), "operator", "missing", ports.AcquireRequest{Value: "x"})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestMergeCachedScanResultPreservesComplementaryModeData(t *testing.T) {
	previous := ScanResult{
		ScanMode: ScanModeVulnerabilities,
		Vulnerabilities: []vulnerability.Vulnerability{{
			ID:        "CVE-1",
			Component: "pkg",
			Version:   "1.0.0",
			Severity:  shared.SeverityHigh,
		}},
		Findings: []finding.Finding{{DedupKey: "vuln:CVE-1:pkg:1.0.0"}},
	}
	current := &ScanResult{
		ScanMode: ScanModeLicenses,
		Licenses: []ports.LicenseFinding{{
			License:    "GPL-3.0-only",
			Category:   sbom.LicenseCopyleft,
			Verdict:    ports.LicenseDeny,
			Components: []string{"pkg"},
		}},
		Findings: []finding.Finding{{DedupKey: "license:GPL-3.0-only:pkg"}},
	}

	mergeCachedScanResult(current, previous, ScanOptions{Mode: ScanModeLicenses})

	if current.ScanMode != ScanModeFull {
		t.Fatalf("ScanMode = %q, want %q", current.ScanMode, ScanModeFull)
	}
	if got := len(current.Vulnerabilities); got != 1 {
		t.Fatalf("vulnerabilities = %d, want preserved previous vuln", got)
	}
	if got := len(current.Licenses); got != 1 {
		t.Fatalf("licenses = %d, want current license", got)
	}
	if got := len(current.Findings); got != 2 {
		t.Fatalf("findings = %d, want previous vuln + current license", got)
	}
	if current.Findings[0].DedupKey != "vuln:CVE-1:pkg:1.0.0" || current.Findings[1].DedupKey != "license:GPL-3.0-only:pkg" {
		t.Fatalf("unexpected merged findings: %+v", current.Findings)
	}
}

func TestMergeCachedScanResultPreservesLicenseDataForVulnMode(t *testing.T) {
	previous := ScanResult{
		ScanMode: ScanModeLicenses,
		Licenses: []ports.LicenseFinding{{License: "MIT", Category: sbom.LicensePermissive, Verdict: ports.LicenseAllow, Components: []string{"pkg"}}},
		Findings: []finding.Finding{{DedupKey: "license:MIT:pkg"}},
	}
	current := &ScanResult{
		ScanMode:        ScanModeVulnerabilities,
		Vulnerabilities: []vulnerability.Vulnerability{{ID: "CVE-2", Component: "pkg", Version: "1.0.0", Severity: shared.SeverityCritical}},
		Findings:        []finding.Finding{{DedupKey: "vuln:CVE-2:pkg:1.0.0"}},
	}

	mergeCachedScanResult(current, previous, ScanOptions{Mode: ScanModeVulnerabilities})

	if current.ScanMode != ScanModeFull {
		t.Fatalf("ScanMode = %q, want %q", current.ScanMode, ScanModeFull)
	}
	if got := len(current.Licenses); got != 1 {
		t.Fatalf("licenses = %d, want preserved previous license", got)
	}
	if got := len(current.Vulnerabilities); got != 1 {
		t.Fatalf("vulnerabilities = %d, want current vuln", got)
	}
	if got := len(current.Findings); got != 2 {
		t.Fatalf("findings = %d, want current vuln + previous license", got)
	}
}

// --- async scan (StartScan) ---

type fakeJobStore struct {
	mu   sync.Mutex
	jobs map[string]ports.ScanJob // by engagement id
}

func newFakeJobStore() *fakeJobStore { return &fakeJobStore{jobs: map[string]ports.ScanJob{}} }

func (f *fakeJobStore) Save(_ context.Context, j ports.ScanJob) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.jobs[j.EngagementID] = j
	return nil
}

func (f *fakeJobStore) LatestForEngagement(_ context.Context, id shared.ID) (ports.ScanJob, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	j, ok := f.jobs[id.String()]
	if !ok {
		return ports.ScanJob{}, shared.ErrNotFound
	}
	return j, nil
}

func (f *fakeJobStore) GetJob(_ context.Context, id string) (ports.ScanJob, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, j := range f.jobs {
		if j.ID == id {
			return j, nil
		}
	}
	return ports.ScanJob{}, shared.ErrNotFound
}

func (f *fakeJobStore) ListStaleRunning(_ context.Context, olderThan time.Time, _ int) ([]ports.ScanJob, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []ports.ScanJob{}
	for _, j := range f.jobs {
		if j.Status == ports.ScanRunning && j.StartedAt.Before(olderThan) {
			out = append(out, j)
		}
	}
	return out, nil
}

type fakeIDs struct{}

func (fakeIDs) NewID() shared.ID { return shared.ID("scan-job-1") }

func newAsyncSvc(repo ports.EngagementRepository, clk ports.Clock, acq ports.Acquirer, audit ports.AuditLogger, det ports.LanguageDetector, jobs ports.ScanJobStore, ids ports.IDGenerator) *Service {
	return NewService(repo, nil, nil, nil, jobs, nil, nil, ids, ports.Provenance{}, clk, audit, shared.SeverityHigh, 0, acq, det, fakeSBOM{}, []ports.DetectionSource{fakeVuln{}}, nil, fakeLic{}, nil)
}

func TestStartScanAsyncCompletes(t *testing.T) {
	repo := &fakeEngRepo{eng: engagementWithScope(t, "myrepo")}
	acq := &fakeAcquirer{dir: "/tmp/ws"}
	audit := &fakeAudit{}
	jobs := newFakeJobStore()
	svc := newAsyncSvc(repo, fakeClock{t: time.Unix(0, 0).UTC()}, acq, audit, &fakeDetector{}, jobs, fakeIDs{})

	job, err := svc.StartScan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: "local", Value: "myrepo"})
	if err != nil {
		t.Fatalf("StartScan: %v", err)
	}
	if job.Status != ports.ScanRunning {
		t.Errorf("initial status = %q, want running", job.Status)
	}
	// The audit must be recorded synchronously, before the goroutine runs any tool.
	if len(audit.entries) != 1 || audit.entries[0].Action != "sca.scan" {
		t.Errorf("want sca.scan audited before async run, got %+v", audit.entries)
	}

	// Poll LatestJob (concurrently with the running goroutine – run under -race) until terminal.
	var final ports.ScanJob
	for i := 0; i < 400; i++ {
		j, err := svc.LatestJob(context.Background(), "e1")
		if err != nil {
			t.Fatalf("LatestJob: %v", err)
		}
		final = j
		if j.Status != ports.ScanRunning {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if final.Status != ports.ScanSucceeded {
		t.Fatalf("final status = %q (stage %q, err %q), want succeeded", final.Status, final.Stage, final.Error)
	}
	if final.Progress != 100 {
		t.Errorf("final progress = %d, want 100", final.Progress)
	}
	if final.FinishedAt == nil {
		t.Error("FinishedAt must be set on completion")
	}
	assertDebugEvent(t, final.DebugEvents, stageVulns, "fake", ports.ScanDebugSucceeded)
	assertDebugEvent(t, final.DebugEvents, stageLicense, "license-policy", ports.ScanDebugSucceeded)
}

// TestFailStrandedScanJobFinalizes covers the SCA DeadLetterer hook: a dead-lettered scan job
// drives its backing ScanJob to a terminal failed state (parity with recon + agent), instead of
// leaving it stuck `running` with no result. Idempotent / no-op once terminal.
func TestFailStrandedScanJobFinalizes(t *testing.T) {
	jobs := newFakeJobStore()
	svc := newAsyncSvc(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, fakeClock{t: time.Unix(100, 0).UTC()}, &fakeAcquirer{dir: "/tmp/ws"}, &fakeAudit{}, &fakeDetector{}, jobs, fakeIDs{})
	ctx := context.Background()
	job := ports.ScanJob{ID: "job-1", EngagementID: "e1", Status: ports.ScanRunning, Stage: "sbom", Progress: 40}
	if err := jobs.Save(ctx, job); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(scaJobPayload{Actor: "operator", EngagementID: "e1", Job: job})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.FailStrandedScanJob(ctx, payload, errors.New("boom")); err != nil {
		t.Fatalf("FailStrandedScanJob: %v", err)
	}
	got, err := svc.LatestJob(ctx, "e1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != ports.ScanFailed {
		t.Fatalf("a stranded scan job must be finalized failed, got %q", got.Status)
	}
	if got.FinishedAt == nil || got.Error == "" {
		t.Errorf("finalized scan must set FinishedAt + Error: %+v", got)
	}
	// Idempotent: a second finalize on the now-terminal job is a clean no-op.
	if err := svc.FailStrandedScanJob(ctx, payload, errors.New("boom2")); err != nil {
		t.Fatalf("second finalize must no-op cleanly, got %v", err)
	}
}

// TestSweepStaleScansReclaims covers the stale-scan sweeper (parity with recon): a scan job
// stranded `running` past staleFor with no live owner is finalized failed.
func TestSweepStaleScansReclaims(t *testing.T) {
	jobs := newFakeJobStore()
	svc := newAsyncSvc(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, fakeClock{t: time.Unix(10000, 0).UTC()}, &fakeAcquirer{dir: "/tmp/ws"}, &fakeAudit{}, &fakeDetector{}, jobs, fakeIDs{})
	svc.SetRunLock(memory.NewRunLock())
	ctx := context.Background()
	// now = 10000s; staleFor 5m ⇒ olderThan = 9700s. StartedAt 1000s ⇒ stranded.
	stale := ports.ScanJob{ID: "job-stale", EngagementID: "e1", Status: ports.ScanRunning, Stage: "sbom", StartedAt: time.Unix(1000, 0).UTC()}
	if err := jobs.Save(ctx, stale); err != nil {
		t.Fatal(err)
	}
	n, err := svc.SweepStaleScans(ctx, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 stranded scan reclaimed, got %d", n)
	}
	got, err := svc.LatestJob(ctx, "e1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != ports.ScanFailed || got.FinishedAt == nil {
		t.Fatalf("stale scan must be finalized failed, got %q finished=%v", got.Status, got.FinishedAt)
	}
}

func TestStartScanOutOfScopeStartsNoJob(t *testing.T) {
	repo := &fakeEngRepo{eng: engagementWithScope(t, "allowed")}
	acq := &fakeAcquirer{dir: "/tmp/ws"}
	jobs := newFakeJobStore()
	svc := newAsyncSvc(repo, fakeClock{t: time.Unix(0, 0).UTC()}, acq, &fakeAudit{}, &fakeDetector{}, jobs, fakeIDs{})

	_, err := svc.StartScan(context.Background(), "operator", "e1", ports.AcquireRequest{Value: "not-allowed"})
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("want ErrForbidden, got %v", err)
	}
	if acq.called {
		t.Error("acquirer must not run for an out-of-scope async scan")
	}
	if _, err := svc.LatestJob(context.Background(), "e1"); !errors.Is(err, shared.ErrNotFound) {
		t.Error("no job should be persisted when the scan is gated out")
	}
}

func TestStartScanUnconfiguredErrors(t *testing.T) {
	repo := &fakeEngRepo{eng: engagementWithScope(t, "myrepo")}
	// nil jobs + ids (the CLI wiring): async is unavailable, must not nil-panic.
	svc := newSvc(repo, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAcquirer{dir: "/tmp/ws"}, &fakeAudit{}, &fakeDetector{})

	_, err := svc.StartScan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: "local", Value: "myrepo"})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation (async unavailable), got %v", err)
	}
}

func TestDiffRunsAndExplain(t *testing.T) {
	a := ports.ScanRun{
		ID: "a", FindingKeys: []string{"vuln:CVE-1:x:1", "vuln:CVE-2:y:1"},
		Manifest: ports.ScanManifest{GrypeDBVersion: "schema-5@2026-06-01", VulnDBSnapshot: "osv.dev@2026-06-01T00:00:00Z"},
	}
	b := ports.ScanRun{
		ID: "b", FindingKeys: []string{"vuln:CVE-2:y:1", "vuln:CVE-3:z:1"},
		Manifest: ports.ScanManifest{GrypeDBVersion: "schema-6@2026-06-20", VulnDBSnapshot: "osv.dev@2026-06-20T00:00:00Z"},
	}
	d := diffRuns(a, b)
	if len(d.Added) != 1 || d.Added[0] != "vuln:CVE-3:z:1" {
		t.Errorf("added = %v, want [vuln:CVE-3:z:1]", d.Added)
	}
	if len(d.Removed) != 1 || d.Removed[0] != "vuln:CVE-1:x:1" {
		t.Errorf("removed = %v, want [vuln:CVE-1:x:1]", d.Removed)
	}
	if d.Unchanged != 1 {
		t.Errorf("unchanged = %d, want 1", d.Unchanged)
	}
	joined := ""
	for _, e := range d.Explanation {
		joined += e + "\n"
	}
	if !strings.Contains(joined, "grype-db changed") || !strings.Contains(joined, "OSV.dev is a live source") {
		t.Errorf("explanation missing manifest deltas: %v", d.Explanation)
	}
}

func TestBuildManifestReproScore(t *testing.T) {
	tv := map[string]string{"syft": "1.45.1", "grype": "0.114.0", "kev-catalog": "2026.06.18", "epss-date": "2026-06-20"}
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"}}}
	m := buildManifest(tv, "osv.dev@2026-06-20T00:00:00Z", "schema-6@2026-06-20", doc)
	// pinned: syft, grype-db, kev-catalog, epss, correlation, sbom = 6; unpinned: osv.dev = 1
	if m.ReproScore != 6*100/7 {
		t.Errorf("repro score = %d, want %d", m.ReproScore, 6*100/7)
	}
	if m.SBOMSHA256 == "" || m.CorrelationVersion != 2 {
		t.Errorf("manifest incomplete: %+v", m)
	}
}

// fakeEvidence is a tamperable in-test evidence ledger.
type fakeEvidence struct{ items []evidence.Evidence }

func (f *fakeEvidence) Append(_ context.Context, items []evidence.Evidence) error {
	f.items = append(f.items, items...)
	return nil
}
func (f *fakeEvidence) ListByEngagement(_ context.Context, _ shared.ID) ([]evidence.Evidence, error) {
	return f.items, nil
}
func (f *fakeEvidence) Head(_ context.Context, _ shared.ID) (string, error) {
	if len(f.items) == 0 {
		return "", nil
	}
	return f.items[len(f.items)-1].Hash, nil
}

func TestEvidenceSealedAndVerifiable(t *testing.T) {
	repo := &fakeEngRepo{eng: engagementWithScope(t, "myrepo")}
	ev := &fakeEvidence{}
	evSvc, err := evidenceuc.NewService(ev, nil, &fakeAudit{}, fakeClock{t: time.Unix(100, 0).UTC()}, fakeIDs{})
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(repo, nil, nil, nil, nil, nil, evSvc, fakeIDs{}, ports.Provenance{}, fakeClock{t: time.Unix(100, 0).UTC()},
		&fakeAudit{}, shared.SeverityHigh, 0, &fakeAcquirer{dir: "/tmp/ws"}, &fakeDetector{}, fakeSBOM{},
		[]ports.DetectionSource{fakeVuln{}}, nil, fakeLic{}, nil)

	for i := 0; i < 2; i++ {
		if _, err := svc.Scan(context.Background(), "op", "e1", ports.AcquireRequest{Value: "myrepo"}); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := svc.VerifyEvidence(context.Background(), "e1")
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Intact || rep.Verified != 2 {
		t.Fatalf("chain should be intact with 2 links, got intact=%v verified=%d err=%q", rep.Intact, rep.Verified, rep.Error)
	}
	if rep.Items[1].PreviousHash != rep.Items[0].Hash {
		t.Error("second link must chain to the first")
	}
	// Tamper: mutate a stored link's content -> verification must fail.
	ev.items[0].Content = []byte("tampered")
	rep, _ = svc.VerifyEvidence(context.Background(), "e1")
	if rep.Intact {
		t.Error("tampered chain must fail verification")
	}
}
