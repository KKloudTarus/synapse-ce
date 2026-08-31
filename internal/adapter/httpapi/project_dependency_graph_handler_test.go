package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	projectuc "github.com/KKloudTarus/synapse-ce/internal/usecase/projectuc"
)

type dependencyGraphServiceStub struct {
	projectService
	graph           projectuc.DependencyGraph
	graphErr        error
	export          []byte
	exportName      string
	exportErr       error
	tenant          shared.ID
	key, exportRoot string
}

func (s *dependencyGraphServiceStub) ProjectDependencyGraph(_ context.Context, tenant shared.ID, key string) (projectuc.DependencyGraph, error) {
	s.tenant, s.key = tenant, key
	return s.graph, s.graphErr
}

func (s *dependencyGraphServiceStub) ExportProjectDependencySubtree(_ context.Context, tenant shared.ID, key, root string) ([]byte, string, error) {
	s.tenant, s.key, s.exportRoot = tenant, key, root
	return s.export, s.exportName, s.exportErr
}

func TestProjectDependencyGraphHandler(t *testing.T) {
	stub := &dependencyGraphServiceStub{graph: projectuc.DependencyGraph{
		AnalysisID: "analysis-1", Roots: []string{"pkg:generic/root@1"},
		Summary: projectuc.DependencyGraphSummary{Components: 1, Direct: 1},
	}}
	rt := &Router{log: discardLog(), projects: stub}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/payments/dependency-graph", nil)
	req.SetPathValue("key", "payments")
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "alice", TenantID: "tenant-a"}))
	rec := httptest.NewRecorder()

	rt.projectDependencyGraph(rec, req)

	if rec.Code != http.StatusOK || stub.tenant != "tenant-a" || stub.key != "payments" {
		t.Fatalf("code=%d tenant=%q key=%q body=%s", rec.Code, stub.tenant, stub.key, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"analysis_id":"analysis-1"`) || !strings.Contains(rec.Body.String(), `"components":1`) {
		t.Fatalf("body=%s", rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "private, no-cache" {
		t.Fatalf("cache-control=%q", got)
	}
}

func TestExportProjectDependencySubtreeHandler(t *testing.T) {
	stub := &dependencyGraphServiceStub{export: []byte(`{"bomFormat":"CycloneDX"}`), exportName: "payments-dependencies-subtree.cdx.json"}
	rt := &Router{log: discardLog(), projects: stub}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/payments/dependency-graph/export?root=pkg%3Anpm%2Flog4j%401", nil)
	req.SetPathValue("key", "payments")
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "alice", TenantID: "tenant-a"}))
	rec := httptest.NewRecorder()

	rt.exportProjectDependencySubtree(rec, req)

	if rec.Code != http.StatusOK || stub.exportRoot != "pkg:npm/log4j@1" {
		t.Fatalf("code=%d root=%q body=%s", rec.Code, stub.exportRoot, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/vnd.cyclonedx+json" {
		t.Fatalf("content-type=%q", got)
	}
	if got := rec.Header().Get("Content-Disposition"); got != `attachment; filename="payments-dependencies-subtree.cdx.json"` {
		t.Fatalf("content-disposition=%q", got)
	}
}

func TestExportProjectDependencySubtreeRejectsHostileRoot(t *testing.T) {
	stub := &dependencyGraphServiceStub{}
	rt := &Router{log: discardLog(), projects: stub}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/p/dependency-graph/export?root=bad%0Aheader", nil)
	req.SetPathValue("key", "p")
	rec := httptest.NewRecorder()

	rt.exportProjectDependencySubtree(rec, req)

	if rec.Code != http.StatusBadRequest || stub.exportRoot != "" {
		t.Fatalf("code=%d root=%q body=%s", rec.Code, stub.exportRoot, rec.Body.String())
	}
}
