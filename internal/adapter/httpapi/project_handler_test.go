package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	projectuc "github.com/KKloudTarus/synapse-ce/internal/usecase/projectuc"
)

type projectAnalysisServiceStub struct {
	projectService
	latest projectuc.LatestAnalysis
	err    error
}

func (s projectAnalysisServiceStub) LatestAnalysis(context.Context, shared.ID, string) (projectuc.LatestAnalysis, error) {
	return s.latest, s.err
}

type dummyRulesStub struct {
	rulesService
}

func (s dummyRulesStub) Get(context.Context, rule.Key) (rule.Rule, error) {
	return rule.Rule{}, shared.ErrNotFound
}

type coverageStartStub struct {
	projectService
	received *measure.CoverageReport
}

func (s *coverageStartStub) StartAnalysis(_ context.Context, _ string, _ shared.ID, _ string, coverage *measure.CoverageReport) (ports.ScanJob, error) {
	s.received = coverage
	return ports.ScanJob{ID: "job-1"}, nil
}

func TestParseCoverageUpload(t *testing.T) {
	for _, data := range []string{
		"SF:a.go\nDA:1,1\nend_of_record\n",
		`<coverage><packages><package><classes><class filename="a.go"><lines><line number="1" hits="1"/></lines></class></classes></package></packages></coverage>`,
		`<report><package name="pkg"><sourcefile name="A.java"><line nr="1" mi="0" ci="1"/></sourcefile></package></report>`,
	} {
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		part, err := writer.CreateFormFile("coverage", "coverage")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/", &body)
		req.Header.Set("Content-Type", writer.FormDataContentType())
		report, err := parseCoverageUpload(httptest.NewRecorder(), req)
		if err != nil || report == nil || report.TotalLines != 1 {
			t.Fatalf("report=%+v err=%v", report, err)
		}
	}
}

func TestStartProjectAnalysisRejectsInvalidCoverage(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("coverage", "coverage")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("not a report"))
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	stub := &coverageStartStub{}
	rt := &Router{log: discardLog(), projects: stub}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/projects/project/analyses", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.SetPathValue("key", "project")
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "alice", TenantID: "tenant"}))
	rec := httptest.NewRecorder()
	rt.startProjectAnalysis(rec, req)
	if rec.Code != http.StatusBadRequest || stub.received != nil {
		t.Fatalf("code=%d coverage=%+v body=%s", rec.Code, stub.received, rec.Body.String())
	}
}

func TestStartProjectAnalysisKeepsEmptyPostCompatible(t *testing.T) {
	stub := &coverageStartStub{}
	rt := &Router{log: discardLog(), projects: stub}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/projects/project/analyses", nil)
	req.SetPathValue("key", "project")
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "alice", TenantID: "tenant"}))
	rec := httptest.NewRecorder()
	rt.startProjectAnalysis(rec, req)
	if rec.Code != http.StatusAccepted || stub.received != nil {
		t.Fatalf("code=%d coverage=%+v body=%s", rec.Code, stub.received, rec.Body.String())
	}
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
	rt := &Router{log: discardLog(), projects: projectAnalysisServiceStub{latest: projectuc.LatestAnalysis{Analysis: projectanalysis.Analysis{ID: "job-1"}, Result: data}}, rules: dummyRulesStub{}}
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
	rt := &Router{log: discardLog(), projects: projectAnalysisServiceStub{latest: projectuc.LatestAnalysis{Analysis: projectanalysis.Analysis{ID: "job-1"}, Result: []byte(`{"findings":"not-an-array","secret":"must-not-leak"}`)}}, rules: dummyRulesStub{}}
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

func TestProjectAnalysisPageParams(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/p/analyses?limit=10&before_created_at=2026-07-17T00:00:00Z&before_id=a1", nil)
	limit, before, id, err := projectAnalysisPageParams(req)
	if err != nil || limit != 10 || before.IsZero() || id != "a1" {
		t.Fatalf("limit=%d before=%v id=%q err=%v", limit, before, id, err)
	}
	for _, query := range []string{"?limit=0", "?limit=101", "?limit=nope", "?before_id=a1", "?before_created_at=nope&before_id=a1"} {
		req = httptest.NewRequest(http.MethodGet, "/api/v1/projects/p/analyses"+query, nil)
		if _, _, _, err := projectAnalysisPageParams(req); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("query %q error=%v, want validation", query, err)
		}
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
