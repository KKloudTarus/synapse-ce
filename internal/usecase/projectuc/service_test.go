package projectuc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/hotspot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	qualitygatesuc "github.com/KKloudTarus/synapse-ce/internal/usecase/qualitygates"
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

type fixedIDs struct{}

func (fixedIDs) NewID() shared.ID { return "p1" }

type captureAudit struct{ entries []ports.AuditEntry }

func (a *captureAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.entries = append(a.entries, e)
	return nil
}

type cleanupArtifactStore struct {
	tenant, project shared.ID
	analysis        string
	deleted         bool
}

func (*cleanupArtifactStore) Capture(context.Context, shared.ID, shared.ID, string, string) (projectanalysis.SourceCapture, error) {
	return projectanalysis.SourceCapture{}, nil
}
func (*cleanupArtifactStore) CaptureBase(context.Context, shared.ID, shared.ID, string, map[string][]byte) (projectanalysis.SourceManifest, error) {
	return projectanalysis.SourceManifest{}, nil
}
func (*cleanupArtifactStore) Load(context.Context, shared.ID, shared.ID, string, string) ([]byte, projectanalysis.SourceFile, error) {
	return nil, projectanalysis.SourceFile{}, projectanalysis.ErrSourceNotRetained
}
func (*cleanupArtifactStore) LoadBase(context.Context, shared.ID, shared.ID, string, string) ([]byte, projectanalysis.SourceFile, error) {
	return nil, projectanalysis.SourceFile{}, projectanalysis.ErrSourceNotRetained
}
func (s *cleanupArtifactStore) DeleteAnalysis(_ context.Context, tenantID, projectID shared.ID, analysisID string) error {
	s.tenant, s.project, s.analysis, s.deleted = tenantID, projectID, analysisID, true
	return nil
}
func (*cleanupArtifactStore) DeleteProject(context.Context, shared.ID, shared.ID) error { return nil }
func (*cleanupArtifactStore) CleanupExpired(context.Context, time.Time) error           { return nil }

type projectRuleCatalog struct{ rules map[rule.Key]rule.Rule }

func (c projectRuleCatalog) List(context.Context) ([]rule.Rule, error) { return nil, nil }
func (c projectRuleCatalog) Get(_ context.Context, key rule.Key) (rule.Rule, error) {
	item, ok := c.rules[key]
	if !ok {
		return rule.Rule{}, shared.ErrNotFound
	}
	return item, nil
}

func TestProjectAcquireRequestUsesPriorGitCommit(t *testing.T) {
	analyses := memory.NewProjectAnalysisStore()
	svc := NewService(nil, nil, fixedClock{}, fixedIDs{}, &captureAudit{}, true)
	svc.SetAnalysisStore(analyses)
	p := &project.Project{ID: "project", TenantID: "tenant", SourceBinding: project.SourceBinding{Kind: project.SourceGit, Value: "https://example.test/repo.git", Ref: "main"}}
	if err := analyses.Save(context.Background(), projectanalysis.Analysis{ID: "previous", TenantID: "tenant", ProjectID: "project", CreatedAt: time.Unix(1, 0), SourceCommit: "immutable-commit", SourceRevision: projectanalysis.SourceRevision{Kind: projectanalysis.ScanKindGit}}); err != nil {
		t.Fatal(err)
	}
	request, err := svc.projectAcquireRequest(context.Background(), p)
	if err != nil || request.BaseRef != "main" || request.BaseCommit != "immutable-commit" {
		t.Fatalf("request=%+v err=%v", request, err)
	}
}

func TestProjectAcquireRequestPreservesExplicitBaseRef(t *testing.T) {
	svc := NewService(nil, nil, fixedClock{}, fixedIDs{}, &captureAudit{}, true)
	request, err := svc.projectAcquireRequest(context.Background(), &project.Project{SourceBinding: project.SourceBinding{Kind: project.SourceGit, Value: "https://example.test/repo.git", Ref: "main", BaseRef: "release"}})
	if err != nil || request.BaseRef != "release" || request.BaseCommit != "" {
		t.Fatalf("request=%+v err=%v", request, err)
	}
}

func TestRecordProjectAnalysisRemovesConfirmedOrphanArtifact(t *testing.T) {
	ctx := context.Background()
	projects := memory.NewProjectRepository()
	engagements := memory.NewEngagementRepository()
	analyses := memory.NewProjectAnalysisStore()
	artifacts := &cleanupArtifactStore{}
	svc := NewService(projects, engagements, fixedClock{}, fixedIDs{}, &captureAudit{}, true)
	svc.SetAnalysisStore(analyses)
	svc.SetSourceArtifactStore(artifacts)
	p, err := svc.Create(ctx, CreateInput{TenantID: "tenant", CreatedBy: "alice", Name: "Project", Key: "project", SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}})
	if err != nil {
		t.Fatal(err)
	}
	e, err := engagements.GetByProjectID(ctx, p.TenantID, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.RecordProjectAnalysis(ctx, e.ID, "job-1", time.Unix(1, 0), &scauc.ScanResult{}); err == nil {
		t.Fatal("expected missing rule catalog error")
	}
	if !artifacts.deleted || artifacts.tenant != p.TenantID || artifacts.project != p.ID || artifacts.analysis != "job-1" {
		t.Fatalf("cleanup=%+v, want tenant=%q project=%q analysis=job-1", artifacts, p.TenantID, p.ID)
	}
}

func TestReconcileSourceCaptureKeepsOnlySnapshotFiles(t *testing.T) {
	available := projectanalysis.SourceCapabilities{
		Source:       projectanalysis.Capability{Available: true},
		Comparison:   projectanalysis.Capability{Reason: projectanalysis.UnavailableFirstAnalysis},
		UnifiedDiff:  projectanalysis.Capability{Reason: projectanalysis.UnavailableFirstAnalysis},
		SplitDiff:    projectanalysis.Capability{Reason: projectanalysis.UnavailableFirstAnalysis},
		Highlighting: projectanalysis.Capability{Available: true},
	}
	snapshot := measure.Snapshot{Nodes: []measure.Node{{Path: "", Kind: measure.NodeProject}, {Path: "main.go", Kind: measure.NodeFile}}}
	caps, manifest := reconcileSourceCapture(snapshot, available, projectanalysis.SourceManifest{Files: []projectanalysis.SourceFile{
		{Path: "main.go", Digest: "digest", Available: true},
		{Path: "ignored.txt", Digest: "digest", Available: true},
	}})
	if !caps.Source.Available || len(manifest.Files) != 1 || manifest.Files[0].Path != "main.go" || manifest.Digest != manifest.ArtifactDigest() {
		t.Fatalf("caps=%+v manifest=%+v", caps, manifest)
	}
}

func TestReconcileSourceCaptureFailsClosedWhenSnapshotIsMissingCapturedFiles(t *testing.T) {
	available := projectanalysis.SourceCapabilities{
		Source:       projectanalysis.Capability{Available: true},
		Comparison:   projectanalysis.Capability{Reason: projectanalysis.UnavailableFirstAnalysis},
		UnifiedDiff:  projectanalysis.Capability{Reason: projectanalysis.UnavailableFirstAnalysis},
		SplitDiff:    projectanalysis.Capability{Reason: projectanalysis.UnavailableFirstAnalysis},
		Highlighting: projectanalysis.Capability{Available: true},
	}
	caps, manifest := reconcileSourceCapture(measure.Snapshot{Nodes: []measure.Node{{Path: "", Kind: measure.NodeProject}, {Path: "main.go", Kind: measure.NodeFile}}}, available, projectanalysis.SourceManifest{})
	if caps.Source.Available || caps.Source.Reason != projectanalysis.UnavailableCaptureFailed || len(manifest.Files) != 0 {
		t.Fatalf("caps=%+v manifest=%+v", caps, manifest)
	}
}

func TestServiceCRUDAndAudit(t *testing.T) {
	ctx := context.Background()
	audit := &captureAudit{}
	svc := NewService(memory.NewProjectRepository(), memory.NewEngagementRepository(), fixedClock{time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)}, fixedIDs{}, audit, true)
	p, err := svc.Create(ctx, CreateInput{TenantID: "tenant-a", CreatedBy: "alice", Name: "Project", Key: "project", SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Audit.CreatedBy != "alice" || len(audit.entries) != 1 || audit.entries[0].Action != "project.create" {
		t.Fatalf("create audit/owner: p=%+v audit=%+v", p, audit.entries)
	}
	if _, err := svc.Get(ctx, "tenant-b", "project"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant=%v, want not found", err)
	}
	list, err := svc.List(ctx, "tenant-a")
	if err != nil || len(list) != 1 {
		t.Fatalf("list=%+v err=%v", list, err)
	}
	if err := svc.Delete(ctx, "alice", "tenant-a", "project"); err != nil {
		t.Fatal(err)
	}
	if len(audit.entries) != 2 || audit.entries[1].Action != "project.delete" {
		t.Fatalf("delete audit=%+v", audit.entries)
	}
}

func TestListSummariesIncludesLatestAnalysis(t *testing.T) {
	ctx := context.Background()
	projects := memory.NewProjectRepository()
	engagements := memory.NewEngagementRepository()
	analyses := memory.NewProjectAnalysisStore()
	svc := NewService(projects, engagements, fixedClock{time.Unix(1, 0)}, fixedIDs{}, &captureAudit{}, true)
	svc.SetAnalysisStore(analyses)
	p, err := svc.Create(ctx, CreateInput{TenantID: "tenant", CreatedBy: "alice", Name: "Project", Key: "project", SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := analyses.Save(ctx, projectanalysis.Analysis{ID: "analysis-1", TenantID: "tenant", ProjectID: p.ID.String(), CreatedAt: time.Unix(2, 0)}); err != nil {
		t.Fatal(err)
	}
	summaries, err := svc.ListSummaries(ctx, "tenant")
	if err != nil || len(summaries) != 1 || summaries[0].LatestAnalysis == nil || summaries[0].LatestAnalysis.ID != "analysis-1" || summaries[0].LatestJob != nil {
		t.Fatalf("summaries=%+v err=%v", summaries, err)
	}
	if other, err := svc.ListSummaries(ctx, "other"); err != nil || len(other) != 0 {
		t.Fatalf("other=%+v err=%v", other, err)
	}
}

func TestServiceRequiresActor(t *testing.T) {
	svc := NewService(memory.NewProjectRepository(), memory.NewEngagementRepository(), fixedClock{}, fixedIDs{}, &captureAudit{}, true)
	if _, err := svc.Create(context.Background(), CreateInput{Name: "P", Key: "p", SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("got %v, want validation", err)
	}
}

func TestServiceRejectsLocalSourceOutsideDevelopment(t *testing.T) {
	svc := NewService(memory.NewProjectRepository(), memory.NewEngagementRepository(), fixedClock{}, fixedIDs{}, &captureAudit{}, false)
	_, err := svc.Create(context.Background(), CreateInput{
		TenantID: "tenant-a", CreatedBy: "alice", Name: "Project", Key: "project",
		SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"},
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("got %v, want validation", err)
	}
}

func TestServiceCreatesBuiltInGateWithoutStoredRow(t *testing.T) {
	ctx := context.Background()
	svc := NewService(memory.NewProjectRepository(), memory.NewEngagementRepository(), fixedClock{}, fixedIDs{}, &captureAudit{}, true)
	p, err := svc.Create(ctx, CreateInput{TenantID: "tenant", CreatedBy: "alice", Name: "Project", Key: "project", GateID: qualitygate.DefaultKey, SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.GateID != qualitygate.DefaultKey {
		t.Fatalf("gate=%q, want %q", p.GateID, qualitygate.DefaultKey)
	}
}

func TestServiceCreateRejectsMissingCustomGate(t *testing.T) {
	ctx := context.Background()
	projects := memory.NewProjectRepository()
	svc := NewService(projects, memory.NewEngagementRepository(), fixedClock{}, fixedIDs{}, &captureAudit{}, true)
	svc.SetQualityGateMutator(memory.NewQualityGateMutator(memory.NewQualityGateStore(), projects, &captureAudit{}))
	_, err := svc.Create(ctx, CreateInput{TenantID: "tenant", CreatedBy: "alice", Name: "Project", Key: "project", GateID: "release", SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("create with missing gate=%v, want not found", err)
	}
	if _, err := projects.GetByKey(ctx, "tenant", "project"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("project after failed create=%v, want not found", err)
	}
}

func TestServiceCreateWithCustomGateBlocksDeletion(t *testing.T) {
	ctx := context.Background()
	projects := memory.NewProjectRepository()
	gates := memory.NewQualityGateStore()
	audit := &captureAudit{}
	mutator := memory.NewQualityGateMutator(gates, projects, audit)
	gateService := qualitygatesuc.NewService(gates, audit, fixedClock{})
	gateService.SetMutator(mutator)
	if _, err := gateService.Create(ctx, "alice", "tenant", qualitygate.Gate{Key: "release", Name: "Release", Conditions: []qualitygate.Condition{{Metric: qualitygate.MetricNewHigh, Op: qualitygate.OpLE, Threshold: 0}}}); err != nil {
		t.Fatal(err)
	}
	svc := NewService(projects, memory.NewEngagementRepository(), fixedClock{}, fixedIDs{}, audit, true)
	svc.SetQualityGateMutator(mutator)
	if _, err := svc.Create(ctx, CreateInput{TenantID: "tenant", CreatedBy: "alice", Name: "Project", Key: "project", GateID: "release", SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}}); err != nil {
		t.Fatal(err)
	}
	if err := gateService.Delete(ctx, "alice", "tenant", "release"); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("delete assigned custom gate=%v, want conflict", err)
	}
}

func TestRecordProjectAnalysisUsesAssignedGate(t *testing.T) {
	ctx := context.Background()
	projects := memory.NewProjectRepository()
	engagements := memory.NewEngagementRepository()
	analyses := memory.NewProjectAnalysisStore()
	audit := &captureAudit{}
	svc := NewService(projects, engagements, fixedClock{}, fixedIDs{}, audit, true)
	svc.SetAnalysisStore(analyses)
	gates := memory.NewQualityGateStore()
	mutator := memory.NewQualityGateMutator(gates, projects, audit)
	gateService := qualitygatesuc.NewService(gates, audit, fixedClock{})
	gateService.SetMutator(mutator)
	svc.SetQualityGates(gateService)
	svc.SetQualityGateMutator(mutator)
	svc.SetRuleCatalog(projectRuleCatalog{})
	if _, err := svc.gates.Create(ctx, "alice", "tenant", qualitygate.Gate{Key: "relaxed", Name: "Relaxed", Conditions: []qualitygate.Condition{{Metric: qualitygate.MetricNewHigh, Op: qualitygate.OpLE, Threshold: 1}}}); err != nil {
		t.Fatal(err)
	}
	p, err := svc.Create(ctx, CreateInput{TenantID: "tenant", CreatedBy: "alice", Name: "Project", Key: "project", GateID: "relaxed", SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}})
	if err != nil {
		t.Fatal(err)
	}
	e, err := engagements.GetByProjectID(ctx, p.TenantID, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.RecordProjectAnalysis(ctx, e.ID, "job-1", time.Unix(1, 0), &scauc.ScanResult{Findings: []finding.Finding{{ID: "high", DedupKey: "high", Kind: finding.KindSCA, Severity: shared.SeverityHigh, Status: finding.StatusOpen}}}); err != nil {
		t.Fatal(err)
	}
	list, _, err := analyses.List(ctx, p.TenantID, p.ID, 1, time.Time{}, "")
	if err != nil || len(list) != 1 || !list[0].Gate.Passed || len(list[0].Gate.Results) != 1 {
		t.Fatalf("analysis=%+v err=%v", list, err)
	}
	if list[0].GateInfo.Key != "relaxed" || list[0].GateInfo.Name != "Relaxed" || list[0].GateInfo.Source != "managed" {
		t.Fatalf("gate info=%+v", list[0].GateInfo)
	}
}

func TestRecordProjectAnalysisUsesRepositoryGate(t *testing.T) {
	ctx := context.Background()
	projects := memory.NewProjectRepository()
	engagements := memory.NewEngagementRepository()
	analyses := memory.NewProjectAnalysisStore()
	svc := NewService(projects, engagements, fixedClock{}, fixedIDs{}, &captureAudit{}, true)
	svc.SetAnalysisStore(analyses)
	svc.SetRuleCatalog(projectRuleCatalog{})
	p, err := svc.Create(ctx, CreateInput{TenantID: "tenant", CreatedBy: "alice", Name: "Project", Key: "project", SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}})
	if err != nil {
		t.Fatal(err)
	}
	e, err := engagements.GetByProjectID(ctx, p.TenantID, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	gate := qualitygate.Gate{Key: "repo", Name: "Repository gate", Conditions: []qualitygate.Condition{{Metric: qualitygate.MetricNewHigh, Op: qualitygate.OpLE, Threshold: 0}}}
	if err := svc.RecordProjectAnalysis(ctx, e.ID, "job-1", time.Unix(1, 0), &scauc.ScanResult{Gate: gate}); err != nil {
		t.Fatal(err)
	}
	list, _, err := analyses.List(ctx, p.TenantID, p.ID, 1, time.Time{}, "")
	if err != nil || len(list) != 1 || list[0].GateInfo.Source != "repository" || list[0].GateInfo.Key != "repo" {
		t.Fatalf("analysis=%+v err=%v", list, err)
	}
}

func TestRecordProjectAnalysisPersistsLineCoverage(t *testing.T) {
	ctx := context.Background()
	projects := memory.NewProjectRepository()
	engagements := memory.NewEngagementRepository()
	analyses := memory.NewProjectAnalysisStore()
	svc := NewService(projects, engagements, fixedClock{}, fixedIDs{}, &captureAudit{}, true)
	svc.SetAnalysisStore(analyses)
	svc.SetRuleCatalog(projectRuleCatalog{})
	p, err := svc.Create(ctx, CreateInput{TenantID: "tenant", CreatedBy: "alice", Name: "Project", Key: "project", SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}})
	if err != nil {
		t.Fatal(err)
	}
	e, err := engagements.GetByProjectID(ctx, p.TenantID, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	coverage := &measure.CoverageReport{Files: []measure.FileCoverage{{File: "a.go", CoveredLines: 1, TotalLines: 2}}, CoveredLines: 1, TotalLines: 2}
	if err := svc.RecordProjectAnalysis(ctx, e.ID, "job-1", time.Unix(1, 0), &scauc.ScanResult{LineCoverage: coverage}); err != nil {
		t.Fatal(err)
	}
	list, _, err := analyses.List(ctx, p.TenantID, p.ID, 1, time.Time{}, "")
	if err != nil || len(list) != 1 || list[0].Coverage == nil || list[0].Coverage.Percent() != 50 || list[0].Measures[qualitygate.MetricCoveragePct] != 50 {
		t.Fatalf("analysis=%+v err=%v", list, err)
	}
}

func TestRecordProjectAnalysisHydratesCurrentTriageOnly(t *testing.T) {
	ctx := context.Background()
	projects := memory.NewProjectRepository()
	engagements := memory.NewEngagementRepository()
	analyses := memory.NewProjectAnalysisStore()
	findings := memory.NewFindingRepository()
	svc := NewService(projects, engagements, fixedClock{}, fixedIDs{}, &captureAudit{}, true)
	svc.SetAnalysisStore(analyses)
	svc.SetFindingRepository(findings)
	svc.SetRuleCatalog(projectRuleCatalog{})
	p, err := svc.Create(ctx, CreateInput{TenantID: "tenant-a", CreatedBy: "alice", Name: "Project", Key: "project", SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}})
	if err != nil {
		t.Fatal(err)
	}
	e, err := engagements.GetByProjectID(ctx, p.TenantID, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	persisted := []finding.Finding{
		{ID: "current-id", EngagementID: e.ID, DedupKey: "current", Status: finding.StatusFalsePos, Severity: shared.SeverityHigh, Kind: finding.KindSCA},
		{ID: "stale-id", EngagementID: e.ID, DedupKey: "stale", Status: finding.StatusRemediated, Severity: shared.SeverityCritical, Kind: finding.KindSCA},
	}
	if err := findings.Upsert(ctx, persisted); err != nil {
		t.Fatal(err)
	}
	result := &scauc.ScanResult{Findings: []finding.Finding{{ID: "new-id", EngagementID: e.ID, DedupKey: "current", Status: finding.StatusOpen, Severity: shared.SeverityHigh, Kind: finding.KindSCA, SourceLocation: &finding.SourceLocation{File: "main.go", StartLine: 7, EndLine: 7}}}}
	if err := svc.RecordProjectAnalysis(ctx, e.ID, "job-1", time.Unix(1, 0), result); err != nil {
		t.Fatal(err)
	}
	list, _, err := analyses.List(ctx, p.TenantID, p.ID, 1, time.Time{}, "")
	if err != nil || len(list) != 1 {
		t.Fatalf("list=%+v err=%v", list, err)
	}
	if got := list[0].Issues.ByStatus[string(finding.StatusFalsePos)]; got != 1 {
		t.Fatalf("false-positive count=%d, want 1", got)
	}
	if list[0].Issues.Total != 1 || len(list[0].InternalIssues) != 1 || list[0].InternalIssues[0].Key != "current" {
		t.Fatalf("stale finding leaked into snapshot: %+v", list[0])
	}
	if len(list[0].Annotations) != 1 || list[0].Annotations[0].Status != finding.StatusOpen || list[0].Annotations[0].Location.File != "main.go" {
		t.Fatalf("historical annotation=%+v", list[0].Annotations)
	}
}

func TestBuildAnnotationsMarksOnlyFindingsAbsentFromBaselineAsNew(t *testing.T) {
	baseline := &projectanalysis.Analysis{InternalIssues: []projectanalysis.Issue{{Key: "old"}}}
	annotations := buildAnnotations([]finding.Finding{
		{DedupKey: "old", Kind: finding.KindSAST, Severity: shared.SeverityHigh, Status: finding.StatusOpen, SourceLocation: &finding.SourceLocation{File: "a.go", StartLine: 1, EndLine: 1}},
		{DedupKey: "new", Kind: finding.KindSAST, Severity: shared.SeverityHigh, Status: finding.StatusOpen, SourceLocation: &finding.SourceLocation{File: "b.go", StartLine: 1, EndLine: 1}},
		{DedupKey: "sast:rule:c.go:7", Kind: finding.KindSAST, Severity: shared.SeverityHigh, Status: finding.StatusOpen},
	}, baseline)
	if len(annotations) != 3 || annotations[0].FindingKey != "new" || !annotations[0].New || annotations[1].FindingKey != "old" || annotations[1].New || annotations[2].Location.File != "c.go" || annotations[2].Location.StartLine != 7 {
		t.Fatalf("annotations=%+v", annotations)
	}
}

func TestBuildAnnotationsUsesPriorAnnotationsForHotspots(t *testing.T) {
	baseline := &projectanalysis.Analysis{Annotations: []projectanalysis.Annotation{{FindingKey: "hotspot", Kind: finding.KindSAST, Severity: shared.SeverityHigh, Status: finding.StatusOpen, Location: finding.SourceLocation{File: "main.go", StartLine: 7, EndLine: 7}}}}
	annotations := buildAnnotations([]finding.Finding{
		{DedupKey: "hotspot", Kind: finding.KindSAST, Severity: shared.SeverityHigh, Status: finding.StatusOpen, SourceLocation: &finding.SourceLocation{File: "main.go", StartLine: 7, EndLine: 7}},
		{DedupKey: "new-hotspot", Kind: finding.KindSAST, Severity: shared.SeverityHigh, Status: finding.StatusOpen, SourceLocation: &finding.SourceLocation{File: "main.go", StartLine: 9, EndLine: 9}},
	}, baseline)
	if len(annotations) != 2 || annotations[0].FindingKey != "hotspot" || annotations[0].New || annotations[1].FindingKey != "new-hotspot" || !annotations[1].New {
		t.Fatalf("annotations=%+v", annotations)
	}
}

func TestReconcileSourceCapturePreservesTruncation(t *testing.T) {
	capabilities := projectanalysis.SourceCapabilities{Source: projectanalysis.Capability{Available: true}}
	_, manifest := reconcileSourceCapture(
		measure.Snapshot{Nodes: []measure.Node{{Path: "", Kind: measure.NodeProject}, {Path: "main.go", Kind: measure.NodeFile}}},
		capabilities,
		projectanalysis.SourceManifest{Truncated: true, Files: []projectanalysis.SourceFile{{Path: "main.go", Digest: "digest", Available: true}}},
	)
	if !manifest.Truncated {
		t.Fatal("source truncation was lost during snapshot reconciliation")
	}
}

func TestRecordProjectAnalysisExcludesCatalogHotspotsFromProjectMetrics(t *testing.T) {
	ctx := context.Background()
	projects := memory.NewProjectRepository()
	engagements := memory.NewEngagementRepository()
	analyses := memory.NewProjectAnalysisStore()
	svc := NewService(projects, engagements, fixedClock{}, fixedIDs{}, &captureAudit{}, true)
	svc.SetAnalysisStore(analyses)
	svc.SetHotspotStore(analyses)
	svc.SetRuleCatalog(projectRuleCatalog{rules: map[rule.Key]rule.Rule{
		"hotspot-rule": {Key: "hotspot-rule", Type: rule.TypeSecurityHotspot, Qualities: []rule.Quality{rule.QualitySecurity}},
	}})
	p, err := svc.Create(ctx, CreateInput{TenantID: "tenant", CreatedBy: "alice", Name: "Project", Key: "project", SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}})
	if err != nil {
		t.Fatal(err)
	}
	e, err := engagements.GetByProjectID(ctx, p.TenantID, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	result := &scauc.ScanResult{Findings: []finding.Finding{
		{ID: "hotspot", DedupKey: "sast:hotspot-rule:src/main.go:7", RuleKey: "hotspot-rule", Kind: finding.KindSAST, Severity: shared.SeverityCritical, Title: "Review this", Description: "Review the security-sensitive use", Status: finding.StatusOpen},
		{ID: "normal", DedupKey: "normal", Kind: finding.KindSCA, Severity: shared.SeverityLow, Title: "Normal", Description: "Normal issue", Status: finding.StatusOpen},
	}}
	if err := svc.RecordProjectAnalysis(ctx, e.ID, "job-1", time.Unix(1, 0), result); err != nil {
		t.Fatal(err)
	}
	list, _, err := analyses.List(ctx, p.TenantID, p.ID, 1, time.Time{}, "")
	if err != nil || len(list) != 1 {
		t.Fatalf("analysis=%+v err=%v", list, err)
	}
	analysis := list[0]
	if analysis.Issues.Total != 1 || analysis.NewCode.Counts.Total != 1 {
		t.Fatalf("hotspot counted as issue: %+v", analysis)
	}
	if got := analysis.Measures[qualitygate.MetricNewVulnerability]; got != 1 {
		t.Fatalf("new vulnerability=%v, want 1 normal finding only", got)
	}
	if analysis.Rating.Security != "B" {
		t.Fatalf("security rating=%q, want B from low normal issue only", analysis.Rating.Security)
	}
	if got := analysis.Measures[qualitygate.MetricNewCritical]; got != 0 {
		t.Fatalf("new critical=%v, hotspot leaked into gate measures", got)
	}
	id := hotspot.DeterministicID(p.TenantID, p.ID, "sast:hotspot-rule:src/main.go:7")
	projected, err := analyses.GetHotspot(ctx, p.TenantID, p.ID, id)
	if err != nil || projected.Status != hotspot.StatusToReview || projected.Location != "src/main.go:7" {
		t.Fatalf("projection=%+v err=%v", projected, err)
	}

	root := analysis.Snapshot.Nodes[0]
	if root.Counters.IssuesByType["security_hotspot"] != 1 {
		t.Fatalf("snapshot root IssuesByType[security_hotspot]=%d, want 1", root.Counters.IssuesByType["security_hotspot"])
	}
	if root.Counters.RemediationEffortMinutes != 0 {
		t.Fatalf("snapshot root remediation effort=%d, want 0", root.Counters.RemediationEffortMinutes)
	}
	if root.AttributionAvailable {
		t.Fatalf("snapshot root should have AttributionAvailable=false due to un-attributed hotspots")
	}
}

func TestRecordProjectAnalysisSnapshotFiltersNonRuleFindings(t *testing.T) {
	ctx := context.Background()
	projects := memory.NewProjectRepository()
	engagements := memory.NewEngagementRepository()
	analyses := memory.NewProjectAnalysisStore()
	svc := NewService(projects, engagements, fixedClock{}, fixedIDs{}, &captureAudit{}, true)
	svc.SetAnalysisStore(analyses)
	svc.SetRuleCatalog(projectRuleCatalog{rules: map[rule.Key]rule.Rule{
		"code-smell": {Key: "code-smell", Type: rule.TypeCodeSmell, Qualities: []rule.Quality{rule.QualityMaintainability}, RemediationEffort: 5},
	}})
	p, err := svc.Create(ctx, CreateInput{TenantID: "tenant", CreatedBy: "alice", Name: "Project", Key: "project", SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}})
	if err != nil {
		t.Fatal(err)
	}
	e, err := engagements.GetByProjectID(ctx, p.TenantID, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	result := &scauc.ScanResult{Findings: []finding.Finding{
		{ID: "sca-finding", DedupKey: "sca", RuleKey: "", Kind: finding.KindSCA, Severity: shared.SeverityHigh, Status: finding.StatusOpen},
		{ID: "quality-finding", DedupKey: "quality", RuleKey: "code-smell", Kind: finding.KindQuality, Severity: shared.SeverityMedium, Status: finding.StatusOpen},
	}}
	if err := svc.RecordProjectAnalysis(ctx, e.ID, "job-2", time.Unix(2, 0), result); err != nil {
		t.Fatal(err)
	}
	list, _, err := analyses.List(ctx, p.TenantID, p.ID, 1, time.Time{}, "")
	if err != nil || len(list) != 1 {
		t.Fatalf("analysis=%+v err=%v", list, err)
	}
	analysis := list[0]
	// Assert SCA is in general issue metrics
	if analysis.Issues.Total != 2 {
		t.Fatalf("analysis.Issues.Total=%d, want 2", analysis.Issues.Total)
	}

	// Assert Snapshot root node constraints
	root := analysis.Snapshot.Nodes[0]
	if !root.IssueTypeAvailable || !root.TechDebtAvailable {
		t.Fatalf("snapshot should be fully available because SCA findings were correctly filtered, got IssueTypeAvailable=%v TechDebtAvailable=%v", root.IssueTypeAvailable, root.TechDebtAvailable)
	}
	if root.Counters.IssuesByType[string(rule.TypeCodeSmell)] != 1 {
		t.Fatalf("snapshot IssuesByType[code_smell]=%d, want 1", root.Counters.IssuesByType[string(rule.TypeCodeSmell)])
	}
	if root.Counters.RemediationEffortMinutes != 5 {
		t.Fatalf("snapshot RemediationEffortMinutes=%d, want 5", root.Counters.RemediationEffortMinutes)
	}
}
