package projectuc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/codequality"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

func newImportService(t *testing.T) (*Service, *memory.ProjectAnalysisStore, *memory.ScanJobStore, *memory.EngagementRepository) {
	t.Helper()
	return newImportServiceWithAudit(t, &captureAudit{})
}

func newImportServiceWithAudit(t *testing.T, audit *captureAudit) (*Service, *memory.ProjectAnalysisStore, *memory.ScanJobStore, *memory.EngagementRepository) {
	t.Helper()
	analyses := memory.NewProjectAnalysisStore()
	jobs := memory.NewScanJobStore()
	engagements := memory.NewEngagementRepository()
	// A real clock time and distinct ids: the recorder stamps issue timestamps from the clock, and the
	// import mints an analysis id that must not collide with the project's own id.
	svc := NewService(memory.NewProjectRepository(), engagements, fixedClock{now: time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)}, &sequentialIDs{}, audit, true)
	svc.SetAnalysisStore(analyses)
	svc.SetScanJobs(jobs)
	svc.SetRuleCatalog(projectRuleCatalog{rules: map[rule.Key]rule.Rule{
		"code-smell": {Key: "code-smell", Type: rule.TypeCodeSmell, Qualities: []rule.Quality{rule.QualityMaintainability}, RemediationEffort: 5},
	}})
	if _, err := svc.Create(context.Background(), CreateInput{TenantID: "tenant", CreatedBy: "alice", Name: "Project", Key: "project", SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}}); err != nil {
		t.Fatal(err)
	}
	return svc, analyses, jobs, engagements
}

func pipelineResult() *scauc.ScanResult {
	return &scauc.ScanResult{
		Target:       "/home/runner/work/app",
		SourceCommit: "0123456789abcdef0123456789abcdef01234567",
		Findings: []finding.Finding{
			{ID: "v1", DedupKey: "vuln:CVE-2024-1:lodash:4.17.15", Kind: finding.KindSCA, Severity: shared.SeverityHigh, Status: finding.StatusOpen, Title: "lodash"},
		},
		CodeQuality: &codequality.Report{
			Inventory: measure.Inventory{Files: []measure.FileInventory{{Path: "src/main.go", Language: "go", CodeLines: 100}}},
			Findings: []finding.Finding{
				{ID: "q1", DedupKey: "quality:code-smell:src/main.go:10", RuleKey: "code-smell", Kind: finding.KindQuality, Severity: shared.SeverityMedium, Status: finding.StatusOpen},
			},
		},
	}
}

// TestImportAnalysisRecordsAPipelineResult is the join the product lacked: a result produced by
// synapse-cli in a pipeline becomes a real analysis in the project's history, with the origin and the
// pipeline's own account of the run visible, and a scan-job record left behind so the status and job
// history show the run the way they show a server run.
func TestImportAnalysisRecordsAPipelineResult(t *testing.T) {
	ctx := context.Background()
	svc, analyses, jobs, engagements := newImportService(t)

	analysis, err := svc.ImportAnalysis(ctx, "tenant", "project", ImportAnalysisInput{
		Actor: "ci-bot",
		CI: projectanalysis.CIContext{
			Provider: "github-actions", RunURL: "https://github.com/acme/app/actions/runs/42", RunID: "42", Branch: "main", Actor: "octocat",
		},
		Result: pipelineResult(),
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if analysis.Origin != projectanalysis.OriginCI {
		t.Errorf("origin = %q, want %q", analysis.Origin, projectanalysis.OriginCI)
	}
	if analysis.CI == nil || analysis.CI.Provider != "github-actions" || analysis.CI.RunID != "42" || analysis.CI.Branch != "main" {
		t.Errorf("ci context was not carried: %+v", analysis.CI)
	}
	if analysis.SourceRef != "main" {
		t.Errorf("source ref = %q, want the pipeline's branch", analysis.SourceRef)
	}
	if analysis.SourceCommit != "0123456789abcdef0123456789abcdef01234567" {
		t.Errorf("source commit = %q, want the pipeline's commit", analysis.SourceCommit)
	}
	if analysis.Issues.Total == 0 {
		t.Error("the imported findings did not become issues; the analysis is empty")
	}

	// It is in the history, newest first, exactly like a server analysis.
	list, _, err := analyses.List(ctx, "tenant", shared.ID(analysis.ProjectID), "", 5, analysis.CreatedAt.Add(1), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != analysis.ID {
		t.Fatalf("history = %+v, want the imported analysis", list)
	}

	// A scan-job record exists and is already succeeded: the work happened in the pipeline.
	e, err := engagements.GetByProjectID(ctx, "tenant", shared.ID(analysis.ProjectID))
	if err != nil {
		t.Fatal(err)
	}
	job, err := jobs.LatestForEngagement(ctx, e.ID)
	if err != nil {
		t.Fatalf("latest job: %v", err)
	}
	if job.Status != ports.ScanSucceeded || job.Kind != "ci-import" || job.ID != analysis.ID {
		t.Errorf("job = %+v, want a succeeded ci-import job sharing the analysis id", job)
	}
}

// TestImportAnalysisMarksTheJobFailedWhenTheResultIsRejected: the job row is written before the
// recorder runs so the history shows the run. A payload the recorder refuses (here a duplicate
// canonical path in the inventory) must leave a failed job with the reason, never a succeeded
// ci-import job with no analysis behind it.
func TestImportAnalysisMarksTheJobFailedWhenTheResultIsRejected(t *testing.T) {
	ctx := context.Background()
	svc, analyses, jobs, engagements := newImportService(t)
	result := pipelineResult()
	result.CodeQuality.Inventory.Files = append(result.CodeQuality.Inventory.Files, measure.FileInventory{Path: "src/main.go", Language: "go", CodeLines: 1})

	_, err := svc.ImportAnalysis(ctx, "tenant", "project", ImportAnalysisInput{Actor: "ci-bot", Result: result})
	if err == nil || !strings.Contains(err.Error(), "duplicate canonical file path") {
		t.Fatalf("import err = %v, want the recorder's rejection", err)
	}
	contexts, err := engagements.ListProjectEngagements(ctx, "tenant")
	if err != nil || len(contexts) != 1 {
		t.Fatalf("project contexts = %v, %v", contexts, err)
	}
	job, err := jobs.LatestForEngagement(ctx, contexts[0].ID)
	if err != nil {
		t.Fatalf("latest job: %v", err)
	}
	if job.Status != ports.ScanFailed || job.Stage != "import-rejected" || !strings.Contains(job.Error, "duplicate canonical file path") {
		t.Fatalf("job = %+v, want a failed ci-import job carrying the rejection", job)
	}
	if list, _, err := analyses.List(ctx, "tenant", contexts[0].ProjectID, "", 5, time.Now().Add(time.Hour), ""); err != nil || len(list) != 0 {
		t.Fatalf("analyses = %v, %v; want none recorded", list, err)
	}
}

// TestImportAnalysisFailsWhenTheAuditCannotBeWritten: the import mutates project history, so a lost
// audit record is an error the pipeline sees, not a silent success.
func TestImportAnalysisFailsWhenTheAuditCannotBeWritten(t *testing.T) {
	ctx := context.Background()
	audit := &captureAudit{}
	svc, _, _, _ := newImportServiceWithAudit(t, audit)
	audit.fail = errors.New("audit chain sealed")

	_, err := svc.ImportAnalysis(ctx, "tenant", "project", ImportAnalysisInput{Actor: "ci-bot", Result: pipelineResult()})
	if err == nil || !strings.Contains(err.Error(), "audit imported analysis") || !errors.Is(err, audit.fail) {
		t.Fatalf("import err = %v, want the audit failure", err)
	}
}

// TestImportAnalysisIgnoresThePayloadGate pins the trust boundary: a pipeline that could ship its
// own gate definition could ship a passing one, so the server's managed gate decides.
func TestImportAnalysisIgnoresThePayloadGate(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := newImportService(t)
	result := pipelineResult()
	// A gate with no conditions would pass trivially if the server honoured it.
	result.Gate = qualitygate.Gate{Key: "pipeline-says-pass", Name: "attacker gate"}

	analysis, err := svc.ImportAnalysis(ctx, "tenant", "project", ImportAnalysisInput{Actor: "ci-bot", Result: result})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if analysis.GateInfo.Key == "pipeline-says-pass" {
		t.Fatalf("the payload's gate was honoured: %+v", analysis.GateInfo)
	}
}

// TestImportAnalysisRefusesBadInput covers the inputs that must not reach the recorder.
func TestImportAnalysisRefusesBadInput(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := newImportService(t)

	if _, err := svc.ImportAnalysis(ctx, "tenant", "project", ImportAnalysisInput{Actor: "ci-bot"}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("nil result err = %v, want validation", err)
	}
	if _, err := svc.ImportAnalysis(ctx, "tenant", "project", ImportAnalysisInput{Actor: "", Result: pipelineResult()}); err == nil {
		t.Error("an empty actor was accepted")
	}
	if _, err := svc.ImportAnalysis(ctx, "tenant", "missing", ImportAnalysisInput{Actor: "ci-bot", Result: pipelineResult()}); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("unknown project err = %v, want not found", err)
	}
	if _, err := svc.ImportAnalysis(ctx, "other-tenant", "project", ImportAnalysisInput{Actor: "ci-bot", Result: pipelineResult()}); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("cross-tenant err = %v, want not found", err)
	}
	bad := ImportAnalysisInput{Actor: "ci-bot", Result: pipelineResult(), CI: projectanalysis.CIContext{RunURL: "javascript:alert(1)"}}
	if _, err := svc.ImportAnalysis(ctx, "tenant", "project", bad); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("non-http run url err = %v, want validation", err)
	}
	long := ImportAnalysisInput{Actor: "ci-bot", Result: pipelineResult(), CI: projectanalysis.CIContext{Branch: strings.Repeat("x", 600)}}
	if _, err := svc.ImportAnalysis(ctx, "tenant", "project", long); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("over-long branch err = %v, want validation", err)
	}
}

// TestServerAnalysisStaysOriginServer keeps the existing path unchanged: a server-recorded analysis
// reads as origin server, including when the origin field is absent on rows written before it existed.
func TestServerAnalysisStaysOriginServer(t *testing.T) {
	ctx := context.Background()
	svc, analyses, _, engagements := newImportService(t)
	e, err := engagements.GetByProjectID(ctx, "tenant", shared.ID(mustProjectID(t, svc)))
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.RecordProjectAnalysis(ctx, e.ID, "job-1", time.Date(2026, 9, 5, 12, 5, 0, 0, time.UTC), pipelineResult()); err != nil {
		t.Fatal(err)
	}
	got, err := analyses.Get(ctx, "tenant", shared.ID(e.ProjectID), "job-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Origin != projectanalysis.OriginServer || got.CI != nil {
		t.Errorf("server analysis origin = %q ci = %+v, want server and nil", got.Origin, got.CI)
	}
	// A legacy row with no origin decodes as server.
	legacy, err := projectanalysis.Build(projectanalysis.Input{ID: "legacy", TenantID: "tenant", ProjectID: "p", ProjectKey: "project", CreatedAt: time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Origin != projectanalysis.OriginServer {
		t.Errorf("legacy origin = %q, want server", legacy.Origin)
	}
}

// sequentialIDs hands out distinct ids, so the project, its engagement and each imported analysis
// are separately addressable.
type sequentialIDs struct{ n int }

func (g *sequentialIDs) NewID() shared.ID {
	g.n++
	return shared.ID(fmt.Sprintf("id-%d", g.n))
}

func mustProjectID(t *testing.T, svc *Service) string {
	t.Helper()
	p, err := svc.Get(context.Background(), "tenant", "project")
	if err != nil {
		t.Fatal(err)
	}
	return p.ID.String()
}
