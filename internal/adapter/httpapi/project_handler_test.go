package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	projectuc "github.com/KKloudTarus/synapse-ce/internal/usecase/projectuc"
)

type projectAnalysisServiceStub struct {
	projectService
	data []byte
	err  error
}

func (s projectAnalysisServiceStub) LatestAnalysis(context.Context, shared.ID, string) ([]byte, error) {
	return s.data, s.err
}

func TestProjectAnalysisJobHidesInternalEngagement(t *testing.T) {
	data, err := json.Marshal(projectAnalysisJob(ports.ScanJob{ID: "job-1", EngagementID: "hidden-engagement"}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "engagement") {
		t.Fatalf("Project analysis response leaked hidden engagement: %s", data)
	}
}

func TestLatestProjectAnalysisHidesInternalEngagement(t *testing.T) {
	const topLevelID = "hidden-top-level-engagement"
	const codeQualityID = "hidden-code-quality-engagement"
	data := []byte(`{
		"future_root":"keep-root",
		"findings":[{"Title":"top-level finding","EngagementID":"hidden-top-level-engagement","future_finding":"keep-top"}],
		"code_quality":{"future_report":"keep-report","findings":[{"Title":"quality finding","engagement_id":"hidden-code-quality-engagement","future_finding":"keep-quality"}]}
	}`)
	rt := &Router{log: discardLog(), projects: projectAnalysisServiceStub{data: data}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/project/analysis", nil)
	req.SetPathValue("key", "project")
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "alice", TenantID: "tenant-a"}))
	rec := httptest.NewRecorder()

	rt.latestProjectAnalysis(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, secret := range []string{topLevelID, codeQualityID, "EngagementID", "engagement_id", "engagementId"} {
		if strings.Contains(body, secret) {
			t.Fatalf("project analysis leaked %q: %s", secret, body)
		}
	}
	for _, kept := range []string{"keep-root", "keep-top", "keep-report", "keep-quality", "top-level finding", "quality finding"} {
		if !strings.Contains(body, kept) {
			t.Fatalf("project analysis dropped %q: %s", kept, body)
		}
	}
}

func TestLatestProjectAnalysisRejectsMalformedCache(t *testing.T) {
	rt := &Router{log: discardLog(), projects: projectAnalysisServiceStub{data: []byte(`{"findings":"not-an-array","secret":"must-not-leak"}`)}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/project/analysis", nil)
	req.SetPathValue("key", "project")
	rec := httptest.NewRecorder()

	rt.latestProjectAnalysis(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "must-not-leak") {
		t.Fatalf("malformed cache leaked payload: %s", rec.Body.String())
	}
}

func TestProjectHandlers(t *testing.T) {
	svc := projectuc.NewService(memory.NewProjectRepository(), memory.NewEngagementRepository(), fixedClock{t: time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)}, engIDs{}, &fakeAudit{}, true)
	rt := &Router{log: discardLog(), projects: svc}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/projects", strings.NewReader(`{"name":"Synapse","key":"synapse","source_binding":{"Kind":"local","Value":"/repo"}}`))
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "alice", TenantID: "tenant-a"}))
	rec := httptest.NewRecorder()
	rt.createProject(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: code=%d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/projects/synapse", nil)
	req.SetPathValue("key", "synapse")
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "alice", TenantID: "tenant-a"}))
	rec = httptest.NewRecorder()
	rt.getProject(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: code=%d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["Key"] != "synapse" {
		t.Fatalf("body=%v err=%v", body, err)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/projects/synapse", nil)
	req.SetPathValue("key", "synapse")
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "bob", TenantID: "tenant-b"}))
	rec = httptest.NewRecorder()
	rt.getProject(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant: got %d, want 404", rec.Code)
	}
}
