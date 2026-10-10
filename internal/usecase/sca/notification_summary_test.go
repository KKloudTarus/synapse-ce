package sca

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/importedsbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestNotificationScanSummaryUsesCapturedAttemptRatherThanCache(t *testing.T) {
	actual := []finding.Finding{{ID: "actual", DedupKey: "actual", Kind: finding.KindSCA, Severity: shared.SeverityHigh}}
	cached := []finding.Finding{{ID: "cached", DedupKey: "cached", Kind: finding.KindSCA, Severity: shared.SeverityCritical}}
	result := &ScanResult{Findings: cached}
	result.notificationSummary = notification.NewScanSummary("https://git.example.test/repo", "git", true, actual)
	got := result.NotificationScanSummary("https://git.example.test/repo", "git")
	if got.Total != 1 || len(got.Keys) != 1 || got.Keys[0] != "actual" {
		t.Fatalf("summary = %+v, want the pre-cache attempt", got)
	}
}

func TestNotificationScanSummaryCapturesPipelineAttemptBeforeCachedResults(t *testing.T) {
	ctx := context.Background()
	results := memory.NewScanResultStore()
	seedNotificationSummaryCachedResult(t, ctx, results)

	svc := NewService(
		&fakeEngRepo{eng: engagementWithScope(t, "repo")}, nil, nil, results, nil, nil, nil, nil,
		ports.Provenance{}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAudit{}, shared.SeverityHigh, 0,
		&fakeAcquirer{dir: t.TempDir()}, &fakeDetector{}, staticSBOM{doc: &sbom.SBOM{Components: []sbom.Component{{Name: "pkg", Version: "1.0.0", PURL: "pkg:npm/pkg@1.0.0"}}}},
		[]ports.DetectionSource{staticVuln{{Source: "live", AdvisoryID: "CVE-live", Component: "pkg", Version: "1.0.0", Severity: shared.SeverityHigh}}}, nil, fakeLic{}, nil,
	)
	result, err := svc.ScanWithOptions(ctx, "operator", "e1", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "repo"}, ScanOptions{Mode: ScanModeVulnerabilities})
	if err != nil {
		t.Fatalf("ScanWithOptions: %v", err)
	}
	if !result.IncludesPreviousResults {
		t.Fatal("pipeline did not compose the seeded cached result")
	}
	assertObservedVulnerabilitySummary(t, result.NotificationScanSummary("repo", ports.TargetLocal))
}

func TestQueuedNotificationScanSummaryCapturesAttemptBeforeCachedResults(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), shared.DefaultTenant)
	results := memory.NewScanResultStore()
	seedNotificationSummaryCachedResult(t, ctx, results)
	jobs := newFakeJobStore()
	svc := notificationSummaryService(t, results, jobs)
	started := time.Unix(0, 0).UTC()
	job := ports.ScanJob{ID: "notification-summary-queued", EngagementID: "e1", Target: "repo", Kind: ports.TargetLocal, Status: ports.ScanRunning, StartedAt: started}
	if err := jobs.CreateRunning(ctx, job); err != nil {
		t.Fatal(err)
	}
	if err := svc.runScanJob(ctx, "operator", "e1", started, ports.AcquireRequest{Kind: ports.TargetLocal, Value: "repo"}, ScanOptions{Mode: ScanModeVulnerabilities}, job); err != nil {
		t.Fatalf("runScanJob: %v", err)
	}
	stored, err := jobs.GetJob(ctx, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertObservedVulnerabilitySummary(t, stored.NotificationSnapshot)
}

func TestImportedNotificationScanSummaryCapturesAttemptBeforeCachedResults(t *testing.T) {
	ctx := context.Background()
	results := memory.NewScanResultStore()
	seedNotificationSummaryCachedResult(t, ctx, results)
	svc := notificationSummaryService(t, results, nil)
	doc := &sbom.SBOM{TargetRef: "repo", Components: []sbom.Component{{Name: "pkg", Version: "1.0.0", PURL: "pkg:npm/pkg@1.0.0"}}}
	result, err := svc.runImportedSBOMPipeline(ctx, "operator", "e1", time.Unix(0, 0).UTC(), importedsbom.Record{TargetRef: "repo"}, doc, ScanOptions{Mode: ScanModeVulnerabilities}, func(string, int, []ports.ScanDebugEvent) {}, "")
	if err != nil {
		t.Fatalf("runImportedSBOMPipeline: %v", err)
	}
	if !result.IncludesPreviousResults {
		t.Fatal("imported pipeline did not compose the seeded cached result")
	}
	assertObservedVulnerabilitySummary(t, result.NotificationScanSummary("repo", ports.TargetUpload))
}

func seedNotificationSummaryCachedResult(t *testing.T, ctx context.Context, results *memory.ScanResultStore) {
	t.Helper()
	cached := finding.Finding{ID: "cached-license", DedupKey: "license:cached", Kind: finding.KindSCA, Severity: shared.SeverityLow}
	data, err := json.Marshal(ScanResult{
		Findings: []finding.Finding{cached},
		Licenses: []ports.LicenseFinding{{License: "MIT", Category: sbom.LicensePermissive, Verdict: ports.LicenseAllow, Components: []string{"cached-pkg"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := results.SaveResult(ctx, "e1", data); err != nil {
		t.Fatal(err)
	}
}

func notificationSummaryService(t *testing.T, results *memory.ScanResultStore, jobs ports.ScanJobStore) *Service {
	t.Helper()
	return NewService(
		&fakeEngRepo{eng: engagementWithScope(t, "repo")}, nil, nil, results, jobs, nil, nil, fakeIDs{},
		ports.Provenance{}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAudit{}, shared.SeverityHigh, 0,
		&fakeAcquirer{dir: t.TempDir()}, &fakeDetector{}, staticSBOM{doc: &sbom.SBOM{Components: []sbom.Component{{Name: "pkg", Version: "1.0.0", PURL: "pkg:npm/pkg@1.0.0"}}}},
		[]ports.DetectionSource{staticVuln{{Source: "live", AdvisoryID: "CVE-live", Component: "pkg", Version: "1.0.0", Severity: shared.SeverityHigh}}}, nil, fakeLic{}, nil,
	)
}

func assertObservedVulnerabilitySummary(t *testing.T, summary notification.ScanSummary) {
	t.Helper()
	if summary.Total != 1 || len(summary.Keys) != 1 || summary.Keys[0] != "vuln:CVE-live:pkg:1.0.0" {
		t.Fatalf("notification snapshot = %+v, want only the observed vulnerability attempt", summary)
	}
}
