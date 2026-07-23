package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	projectuc "github.com/KKloudTarus/synapse-ce/internal/usecase/projectuc"
)

type projectCodeServiceStub struct {
	projectService
	view     projectuc.CodeFileView
	diff     projectuc.CodeDiffView
	analysis projectanalysis.Analysis
	err      error
	filter   projectuc.CodeFileFilter
}

func (s projectCodeServiceStub) ReadCodeFile(context.Context, shared.ID, string, string, string, int, int) (projectuc.CodeFileView, projectanalysis.SourceCapabilities, error) {
	return s.view, projectanalysis.SourceCapabilities{}, s.err
}
func (s projectCodeServiceStub) ReadCodeDiff(context.Context, shared.ID, string, string, string, string, int) (projectuc.CodeDiffView, projectanalysis.SourceCapabilities, error) {
	return s.diff, projectanalysis.SourceCapabilities{}, s.err
}
func (s *projectCodeServiceStub) ListCodeFilesWithFilter(_ context.Context, _ shared.ID, _ string, _ string, filter projectuc.CodeFileFilter) ([]projectuc.CodeFile, projectanalysis.SourceCapabilities, error) {
	s.filter = filter
	return nil, s.analysis.Capabilities, s.err
}
func (s projectCodeServiceStub) GetAnalysis(context.Context, shared.ID, string, string) (projectanalysis.Analysis, error) {
	return s.analysis, s.err
}

func TestGetProjectCodeFileHonorsETag(t *testing.T) {
	stub := &projectCodeServiceStub{view: projectuc.CodeFileView{AnalysisID: "a", File: projectuc.CodeFile{Path: "main.go", SourceAvailable: true}, FromLine: 1, ToLine: 1, Lines: []projectuc.CodeLine{{Number: 1, Content: "package main", Change: "unchanged"}}}}
	rt := &Router{log: discardLog(), projects: stub}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/p/analyses/a/code/file?path=main.go", nil)
	req.SetPathValue("key", "p")
	req.SetPathValue("id", "a")
	rec := httptest.NewRecorder()
	rt.getProjectCodeFile(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("ETag") == "" || rec.Header().Get("Cache-Control") != "private, max-age=300" {
		t.Fatalf("code=%d headers=%v body=%s", rec.Code, rec.Header(), rec.Body.String())
	}

	conditional := httptest.NewRequest(http.MethodGet, "/api/v1/projects/p/analyses/a/code/file?path=main.go", nil)
	conditional.Header.Set("If-None-Match", rec.Header().Get("ETag"))
	conditional.SetPathValue("key", "p")
	conditional.SetPathValue("id", "a")
	cached := httptest.NewRecorder()
	rt.getProjectCodeFile(cached, conditional)
	if cached.Code != http.StatusNotModified || cached.Body.Len() != 0 {
		t.Fatalf("code=%d body=%q", cached.Code, cached.Body.String())
	}
}

func TestListProjectCodeFilesReturnsDocumentedRevisionAndCapabilities(t *testing.T) {
	analysis := projectanalysis.Analysis{
		ID:             "a",
		SourceRef:      "head-ref",
		SourceRevision: projectanalysis.SourceRevision{Head: "head-commit"},
		SourceManifest: projectanalysis.SourceManifest{Files: []projectanalysis.SourceFile{}},
		Capabilities:   projectanalysis.SourceCapabilities{Source: projectanalysis.Capability{Available: true}},
		Coverage:       &measure.CoverageReport{},
		Comparison: projectanalysis.Comparison{
			Available: true, BaseRef: "base-ref", BaseCommit: "base-commit",
			BaseManifest: projectanalysis.SourceManifest{Files: []projectanalysis.SourceFile{}},
		},
	}
	stub := &projectCodeServiceStub{analysis: analysis}
	rt := &Router{log: discardLog(), projects: stub}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/p/analyses/a/code/files", nil)
	req.SetPathValue("key", "p")
	req.SetPathValue("id", "a")
	rec := httptest.NewRecorder()
	rt.listProjectCodeFiles(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Base         *projectuc.CodeRevision  `json:"base"`
		Head         projectuc.CodeRevision   `json:"head"`
		Capabilities codeCapabilitiesResponse `json:"capabilities"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Base == nil || response.Head.ArtifactDigest == "" || response.Base.ArtifactDigest == "" || !response.Capabilities.Source || !response.Capabilities.LineCoverage {
		t.Fatalf("response=%+v", response)
	}
}

func TestGetProjectCodeDiffHonorsETag(t *testing.T) {
	stub := &projectCodeServiceStub{diff: projectuc.CodeDiffView{Path: "main.go", View: "unified", ContextTruncated: true, Change: projectanalysis.FileChange{Status: projectanalysis.FileStatusModified, OldPath: "main.go", NewPath: "main.go"}}}
	rt := &Router{log: discardLog(), projects: stub}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/p/analyses/a/code/diff?path=main.go", nil)
	req.SetPathValue("key", "p")
	req.SetPathValue("id", "a")
	rec := httptest.NewRecorder()
	rt.getProjectCodeDiff(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("ETag") == "" || rec.Header().Get("Cache-Control") != "private, max-age=300" {
		t.Fatalf("code=%d headers=%v body=%s", rec.Code, rec.Header(), rec.Body.String())
	}
	var response codeDiffResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.Diff.ContextTruncated {
		t.Fatalf("response=%+v", response)
	}
}

func TestCodeETagIncludesFullRepresentation(t *testing.T) {
	first := codeETag("tenant", "project", "analysis", codeFileResponse{CodeFileView: projectuc.CodeFileView{AnalysisID: "analysis", File: projectuc.CodeFile{Path: "main.go", SourceAvailable: true}, Lines: []projectuc.CodeLine{{Number: 1, Content: "one", Change: "unchanged"}}}})
	second := codeETag("tenant", "project", "analysis", codeFileResponse{CodeFileView: projectuc.CodeFileView{AnalysisID: "analysis", File: projectuc.CodeFile{Path: "main.go", SourceAvailable: true}, Lines: []projectuc.CodeLine{{Number: 1, Content: "one", Change: "unchanged"}}, Findings: []projectuc.CodeFinding{{ID: "f", Kind: "issue", Severity: shared.SeverityHigh, DetectionStatus: finding.StatusOpen, Location: mustCodeLocation(t)}}}})
	if first == second {
		t.Fatal("ETag did not change with annotations")
	}
	if first == codeETag("tenant", "project", "other", codeFileResponse{}) {
		t.Fatal("ETag did not include analysis identity")
	}
}

func TestCodeFilesParamsAndHandlerAcceptDocumentedFilters(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/code/files?include_generated=true&changed=false&has_findings=true&prefix=src&status=unchanged", nil)
	filter, err := codeFilesParams(req)
	if err != nil || !filter.IncludeGenerated || filter.Changed == nil || *filter.Changed || filter.HasFindings == nil || !*filter.HasFindings || filter.Prefix != "src" || filter.Status != "unchanged" {
		t.Fatalf("filter=%+v err=%v", filter, err)
	}
	for _, raw := range []string{"?prefix=src/&status=unchanged", "?status=bogus", "?changed=perhaps", "?extra=1"} {
		if _, err := codeFilesParams(httptest.NewRequest(http.MethodGet, "/code/files"+raw, nil)); err == nil {
			t.Fatalf("%s: expected validation error", raw)
		}
	}
}

func TestWriteCodeErrorMapsArtifactAvailability(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want int
	}{
		{projectanalysis.ErrSourceIntegrity, http.StatusConflict},
		{projectanalysis.ErrSourceNotRetained, http.StatusGone},
		{projectanalysis.ErrSourceLimit, http.StatusRequestEntityTooLarge},
		{projectanalysis.ErrSourceUnsupported, http.StatusUnsupportedMediaType},
		{projectanalysis.ErrSourceTransient, http.StatusServiceUnavailable},
	} {
		t.Run(tc.err.Error(), func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeCodeError(rec, &Router{log: discardLog()}, tc.err)
			if rec.Code != tc.want {
				t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func mustCodeLocation(t *testing.T) finding.SourceLocation {
	t.Helper()
	return finding.SourceLocation{File: "main.go", StartLine: 1, EndLine: 1}
}

func TestCodeFileAndDiffParamsRejectInvalidValues(t *testing.T) {
	for _, raw := range []string{"?path=main.go&extra=1", "?path=main.go&from_line=0", "?path=main.go&to_line=no"} {
		req := httptest.NewRequest(http.MethodGet, "/code/file"+raw, nil)
		if _, _, _, err := codeFileParams(req); err == nil {
			t.Fatalf("%s: expected validation error", raw)
		}
	}
	for _, raw := range []string{"?path=main.go&view=bad", "?path=main.go&context=101", "?path=main.go&extra=1"} {
		req := httptest.NewRequest(http.MethodGet, "/code/diff"+raw, nil)
		if _, _, _, err := codeDiffParams(req); err == nil {
			t.Fatalf("%s: expected validation error", raw)
		}
	}
}
