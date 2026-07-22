package projectuc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
)

type codeArtifactStub struct {
	loaded     bool
	baseLoaded bool
	data       []byte
	baseData   []byte
	err        error
	baseErr    error
}

func (*codeArtifactStub) Capture(context.Context, shared.ID, shared.ID, string, string) (projectanalysis.SourceCapture, error) {
	return projectanalysis.SourceCapture{}, nil
}
func (s *codeArtifactStub) Load(_ context.Context, _ shared.ID, _ shared.ID, _ string, path string) ([]byte, projectanalysis.SourceFile, error) {
	s.loaded = true
	if s.err != nil {
		return nil, projectanalysis.SourceFile{}, s.err
	}
	data := s.data
	if data == nil {
		data = []byte("package main\n")
	}
	return data, projectanalysis.SourceFile{Path: path, Digest: "digest", Bytes: int64(len(data)), Lines: len(splitCodeLines(string(data))), Available: true}, nil
}
func (*codeArtifactStub) CaptureBase(context.Context, shared.ID, shared.ID, string, map[string][]byte) (projectanalysis.SourceManifest, error) {
	return projectanalysis.SourceManifest{}, nil
}
func (s *codeArtifactStub) LoadBase(_ context.Context, _ shared.ID, _ shared.ID, _ string, path string) ([]byte, projectanalysis.SourceFile, error) {
	s.baseLoaded = true
	if s.baseErr != nil {
		return nil, projectanalysis.SourceFile{}, s.baseErr
	}
	if s.baseData == nil {
		return nil, projectanalysis.SourceFile{}, projectanalysis.ErrSourceNotRetained
	}
	return s.baseData, projectanalysis.SourceFile{Path: path, Digest: "base-digest", Bytes: int64(len(s.baseData)), Lines: len(splitCodeLines(string(s.baseData))), Available: true}, nil
}
func (*codeArtifactStub) DeleteAnalysis(context.Context, shared.ID, shared.ID, string) error {
	return nil
}
func (*codeArtifactStub) DeleteProject(context.Context, shared.ID, shared.ID) error { return nil }
func (*codeArtifactStub) CleanupExpired(context.Context, time.Time) error           { return nil }

func saveCodeAnalysis(t *testing.T, analyses *memory.ProjectAnalysisStore, p *project.Project, analysis projectanalysis.Analysis) {
	t.Helper()
	analysis.ID = "analysis"
	analysis.TenantID = p.TenantID.String()
	analysis.ProjectID = p.ID.String()
	if err := analyses.Save(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
}

func newCodeService(t *testing.T, artifacts *codeArtifactStub) (*Service, *memory.ProjectAnalysisStore, *project.Project) {
	t.Helper()
	ctx := context.Background()
	projects := memory.NewProjectRepository()
	analyses := memory.NewProjectAnalysisStore()
	svc := NewService(projects, memory.NewEngagementRepository(), fixedClock{}, fixedIDs{}, &captureAudit{}, true)
	svc.SetAnalysisStore(analyses)
	svc.SetSourceArtifactStore(artifacts)
	p, err := svc.Create(ctx, CreateInput{TenantID: "tenant", CreatedBy: "alice", Name: "Project", Key: "project", SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}})
	if err != nil {
		t.Fatal(err)
	}
	return svc, analyses, p
}

func TestAnnotationsForRangeIncludesOverlappingMultilineMarkers(t *testing.T) {
	annotations := []projectanalysis.Annotation{
		{FindingKey: "before", Location: finding.SourceLocation{File: "main.go", StartLine: 1, EndLine: 2}},
		{FindingKey: "overlap", Location: finding.SourceLocation{File: "main.go", StartLine: 2, EndLine: 4}},
		{FindingKey: "other", Location: finding.SourceLocation{File: "other.go", StartLine: 2, EndLine: 2}},
	}
	got := annotationsForRange(annotations, "main.go", 3, 3)
	if len(got) != 1 || got[0].FindingKey != "overlap" {
		t.Fatalf("annotations=%+v", got)
	}
}

func TestReadCodeFileRejectsPathOutsideSnapshot(t *testing.T) {
	ctx := context.Background()
	artifacts := &codeArtifactStub{}
	svc, analyses, p := newCodeService(t, artifacts)
	saveCodeAnalysis(t, analyses, p, projectanalysis.Analysis{
		Capabilities: projectanalysis.SourceCapabilities{Source: projectanalysis.Capability{Available: true}},
		Snapshot:     measure.Snapshot{Nodes: []measure.Node{{Path: "", Kind: measure.NodeProject}, {Path: "main.go", Kind: measure.NodeFile}}},
	})
	if _, _, err := svc.ReadCodeFile(ctx, p.TenantID, p.Key, "analysis", "missing.go", 1, 1); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("error=%v, want not found", err)
	}
	if artifacts.loaded {
		t.Fatal("artifact store was called for a path outside the immutable snapshot")
	}
}

func TestListCodeFilesAppliesDocumentedFilters(t *testing.T) {
	svc, analyses, p := newCodeService(t, &codeArtifactStub{})
	saveCodeAnalysis(t, analyses, p, projectanalysis.Analysis{
		Capabilities: projectanalysis.SourceCapabilities{Source: projectanalysis.Capability{Available: true}},
		SourceManifest: projectanalysis.SourceManifest{Files: []projectanalysis.SourceFile{
			{Path: "src/changed.go", Digest: "a", Lines: 3, Available: true},
			{Path: "src/generated.go", Digest: "b", Lines: 2, Generated: true, Available: true},
			{Path: "src/unchanged.go", Digest: "c", Lines: 1, Available: true},
		}},
		FileChanges: []projectanalysis.FileChange{{Status: projectanalysis.FileStatusModified, OldPath: "src/changed.go", NewPath: "src/changed.go", Added: []projectanalysis.LineRange{{Start: 2, End: 3}}}},
		Annotations: []projectanalysis.Annotation{{FindingKey: "finding", Kind: finding.KindSAST, Severity: shared.SeverityHigh, Status: finding.StatusOpen, Location: finding.SourceLocation{File: "src/unchanged.go", StartLine: 1, EndLine: 1}}},
		Snapshot:    measure.Snapshot{Nodes: []measure.Node{{Path: "", Kind: measure.NodeProject}, {Path: "src/changed.go", Kind: measure.NodeFile}, {Path: "src/generated.go", Kind: measure.NodeFile}, {Path: "src/unchanged.go", Kind: measure.NodeFile}}},
	})
	changed := true
	files, _, err := svc.ListCodeFilesWithFilter(context.Background(), p.TenantID, p.Key, "analysis", CodeFileFilter{Changed: &changed, Prefix: "src"})
	if err != nil || len(files) != 1 || files[0].Path != "src/changed.go" || files[0].ChangedLineCount != 2 {
		t.Fatalf("changed files=%+v err=%v", files, err)
	}
	hasFindings := true
	files, _, err = svc.ListCodeFilesWithFilter(context.Background(), p.TenantID, p.Key, "analysis", CodeFileFilter{HasFindings: &hasFindings})
	if err != nil || len(files) != 1 || files[0].Path != "src/unchanged.go" {
		t.Fatalf("finding files=%+v err=%v", files, err)
	}
	files, _, err = svc.ListCodeFilesWithFilter(context.Background(), p.TenantID, p.Key, "analysis", CodeFileFilter{IncludeGenerated: true, Status: "unchanged"})
	if err != nil || len(files) != 2 || files[0].Path != "src/generated.go" || files[1].Path != "src/unchanged.go" {
		t.Fatalf("unchanged files=%+v err=%v", files, err)
	}
}

func TestReadCodeFileComposesImmutableLineState(t *testing.T) {
	artifacts := &codeArtifactStub{data: []byte("one\ntwo\nthree\n")}
	svc, analyses, p := newCodeService(t, artifacts)
	saveCodeAnalysis(t, analyses, p, projectanalysis.Analysis{
		Capabilities:   projectanalysis.SourceCapabilities{Source: projectanalysis.Capability{Available: true}},
		SourceManifest: projectanalysis.SourceManifest{Files: []projectanalysis.SourceFile{{Path: "main.go", Digest: "digest", Lines: 3, Available: true}}},
		FileChanges:    []projectanalysis.FileChange{{Status: projectanalysis.FileStatusModified, OldPath: "main.go", NewPath: "main.go", Added: []projectanalysis.LineRange{{Start: 2, End: 2}}}},
		Coverage:       &measure.CoverageReport{Lines: measure.LineCoverage{"main.go": {1: true, 2: false}}},
		Duplication:    measure.DuplicationReport{Blocks: []measure.DuplicationBlock{{Occurrences: []measure.CodeRange{{File: "main.go", StartLine: 3, EndLine: 3}}}}},
		Annotations:    []projectanalysis.Annotation{{FindingKey: "finding", Kind: finding.KindSAST, Severity: shared.SeverityHigh, Status: finding.StatusOpen, Location: finding.SourceLocation{File: "main.go", StartLine: 2, EndLine: 2}}},
		Snapshot:       measure.Snapshot{Nodes: []measure.Node{{Path: "", Kind: measure.NodeProject}, {Path: "main.go", Kind: measure.NodeFile}}},
	})
	view, _, err := svc.ReadCodeFile(context.Background(), p.TenantID, p.Key, "analysis", "main.go", 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Lines) != 3 || view.Lines[0].Change != "unchanged" || view.Lines[0].Coverage == nil || *view.Lines[0].Coverage != "covered" || view.Lines[1].Change != "addition" || view.Lines[1].Coverage == nil || *view.Lines[1].Coverage != "uncovered" || !view.Lines[2].Duplicated || len(view.Findings) != 1 {
		t.Fatalf("view=%+v", view)
	}
}

func TestReadCodeFileUsesBaseArtifactForDeletedFile(t *testing.T) {
	artifacts := &codeArtifactStub{baseData: []byte("old\n")}
	svc, analyses, p := newCodeService(t, artifacts)
	saveCodeAnalysis(t, analyses, p, projectanalysis.Analysis{
		Capabilities: projectanalysis.SourceCapabilities{Source: projectanalysis.Capability{Available: true}},
		Comparison:   projectanalysis.Comparison{Available: true, BaseCommit: "base", MergeBase: "base", BaseManifest: projectanalysis.SourceManifest{Files: []projectanalysis.SourceFile{{Path: "deleted.go", Digest: "base-digest", Lines: 1, Available: true}}}},
		FileChanges:  []projectanalysis.FileChange{{Status: projectanalysis.FileStatusDeleted, OldPath: "deleted.go"}},
		Snapshot:     measure.Snapshot{Nodes: []measure.Node{{Path: "", Kind: measure.NodeProject}}},
	})
	view, _, err := svc.ReadCodeFile(context.Background(), p.TenantID, p.Key, "analysis", "deleted.go", 1, 1)
	if err != nil || !artifacts.baseLoaded || artifacts.loaded || view.File.Status != "deleted" || len(view.Lines) != 1 || view.Lines[0].Content != "old" {
		t.Fatalf("view=%+v baseLoaded=%v loaded=%v err=%v", view, artifacts.baseLoaded, artifacts.loaded, err)
	}
}

func TestCodeFindingsConvertsMultilineColumnsToUTF16(t *testing.T) {
	start, end := 5, 5 // byte columns after one non-BMP rune on each line.
	findings := codeFindings([]projectanalysis.Annotation{{
		FindingKey: "finding",
		Location:   finding.SourceLocation{File: "main.go", StartLine: 1, EndLine: 2, StartColumn: &start, EndColumn: &end},
	}}, []string{"a😀b", "c😀d"}, nil)
	if len(findings) != 1 || findings[0].Location.StartColumn == nil || findings[0].Location.EndColumn == nil || *findings[0].Location.StartColumn != 3 || *findings[0].Location.EndColumn != 3 {
		t.Fatalf("findings=%+v", findings)
	}
}

func TestReadCodeDiffReportsTruncatedBaseAsLimit(t *testing.T) {
	artifacts := &codeArtifactStub{}
	svc, analyses, p := newCodeService(t, artifacts)
	saveCodeAnalysis(t, analyses, p, projectanalysis.Analysis{
		Capabilities: projectanalysis.SourceCapabilities{UnifiedDiff: projectanalysis.Capability{Available: true}},
		Comparison: projectanalysis.Comparison{
			Available:    true,
			BaseManifest: projectanalysis.SourceManifest{Truncated: true},
		},
		SourceManifest: projectanalysis.SourceManifest{Files: []projectanalysis.SourceFile{{Path: "main.go", Available: true}}},
		FileChanges:    []projectanalysis.FileChange{{Status: projectanalysis.FileStatusModified, OldPath: "old.go", NewPath: "main.go"}},
	})
	if _, _, err := svc.ReadCodeDiff(context.Background(), p.TenantID, p.Key, "analysis", "main.go", "unified", 3); !errors.Is(err, projectanalysis.ErrSourceLimit) {
		t.Fatalf("error=%v, want source limit", err)
	}
	if artifacts.baseLoaded || artifacts.loaded {
		t.Fatalf("artifact store read despite omitted truncated manifest: %+v", artifacts)
	}
}
