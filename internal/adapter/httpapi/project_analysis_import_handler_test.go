package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/aup"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	projectuc "github.com/KKloudTarus/synapse-ce/internal/usecase/projectuc"
)

func newImportRouter(t *testing.T) *Router {
	t.Helper()
	svc := projectuc.NewService(memory.NewProjectRepository(), memory.NewEngagementRepository(), fixedClock{t: time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)}, engIDs{}, &fakeAudit{}, true)
	svc.SetAnalysisStore(memory.NewProjectAnalysisStore())
	svc.SetScanJobs(memory.NewScanJobStore())
	svc.SetRuleCatalog(importRuleCatalog{})
	aupStore := newFakeAUPStore()
	aupStore.accepted["1.0"] = aup.Acceptance{Version: "1.0"}
	rt := &Router{
		log:      discardLog(),
		projects: svc,
		auth: NewAuthenticator(func(_ context.Context, token string) (Principal, bool) {
			if token == "ci" {
				return Principal{ID: "ci-bot", Role: "admin", TenantID: "tenant-a"}, true
			}
			return Principal{}, false
		}),
		aup: newTestAUP(aupStore, &fakeAudit{}),
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/projects", strings.NewReader(`{"name":"App","key":"app","source_binding":{"Kind":"local","Value":"/repo"}}`))
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "ci-bot", TenantID: "tenant-a"}))
	rec := httptest.NewRecorder()
	rt.createProject(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create project: %d %s", rec.Code, rec.Body.String())
	}
	return rt
}

// importRuleCatalog is the two-method catalogue the recorder needs to classify a quality finding. A
// fake sidesteps the real catalogue's field validation, which is not what this test is about.
type importRuleCatalog struct{}

func (importRuleCatalog) List(context.Context) ([]rule.Rule, error) { return nil, nil }
func (importRuleCatalog) Get(_ context.Context, key rule.Key) (rule.Rule, error) {
	if key == "code-smell" {
		return rule.Rule{Key: "code-smell", Name: "smell", Language: "go", Type: rule.TypeCodeSmell, Qualities: []rule.Quality{rule.QualityMaintainability}, RemediationEffort: 5}, nil
	}
	return rule.Rule{}, shared.ErrNotFound
}

const importBody = `{"ci":{"provider":"github-actions","run_url":"https://github.com/acme/app/actions/runs/7","run_id":"7","branch":"main","actor":"octocat"},
"result":{"target":"/work/app","source_commit":"abcdef0123456789abcdef0123456789abcdef01","scan_mode":"full","languages":[],"sbom":null,"vulnerabilities":[],"licenses":[],"component_licenses":[],
"findings":[{"ID":"v1","DedupKey":"vuln:CVE-2024-1:lodash:4.17.15","Kind":"sca","Severity":"high","Status":"open","Title":"lodash"}],
"min_severity":"info","vulns_below_threshold":0,"unfixed_suppressed":0,"tool_versions":{"synapse":"test"}}}`

// TestImportProjectAnalysisRoute drives the real chain: authentication, the AUP gate, the route
// pattern, the body ceiling and the handler. A pipeline's result comes back as a recorded analysis
// marked with its origin, and the project's status and history reflect it.
func TestImportProjectAnalysisRoute(t *testing.T) {
	rt := newImportRouter(t)
	handler := rt.Handler()

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/projects/app/analyses/import", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer ci")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	rec := post(importBody)
	if rec.Code != http.StatusCreated {
		t.Fatalf("import: %d %s", rec.Code, rec.Body.String())
	}
	var analysis map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &analysis); err != nil {
		t.Fatal(err)
	}
	if analysis["origin"] != "ci" {
		t.Errorf("origin = %v, want ci", analysis["origin"])
	}
	ci, _ := analysis["ci"].(map[string]any)
	if ci["provider"] != "github-actions" || ci["run_url"] != "https://github.com/acme/app/actions/runs/7" {
		t.Errorf("ci context not returned: %v", analysis["ci"])
	}
	if analysis["source_commit"] != "abcdef0123456789abcdef0123456789abcdef01" {
		t.Errorf("source_commit = %v", analysis["source_commit"])
	}

	// The history lists it, and the status endpoint reports the succeeded run.
	get := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer ci")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	if rec := get("/api/v1/projects/app/analyses"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"origin":"ci"`) {
		t.Errorf("history: %d %s", rec.Code, rec.Body.String())
	}
	if rec := get("/api/v1/projects/app/analysis-status"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"succeeded"`) || !strings.Contains(rec.Body.String(), `"kind":"ci-import"`) {
		t.Errorf("status: %d %s", rec.Code, rec.Body.String())
	}

	// Refusals.
	if rec := post(`{"result":null}`); rec.Code != http.StatusBadRequest {
		t.Errorf("nil result: %d %s", rec.Code, rec.Body.String())
	}
	if rec := post(`{"result":{},"unexpected":1}`); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown field: %d %s", rec.Code, rec.Body.String())
	}
	if rec := post(`not json`); rec.Code != http.StatusBadRequest {
		t.Errorf("garbage: %d", rec.Code)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/projects/nope/analyses/import", strings.NewReader(importBody))
	req.Header.Set("Authorization", "Bearer ci")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown project: %d %s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodPost, "/api/v1/projects/app/analyses/import", strings.NewReader(importBody))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: %d", rec.Code)
	}
}

// TestImportProjectAnalysisCarriesTheImportCeiling proves the route accepts a result larger than the
// JSON default. A full scan result with its SBOM is a document produced elsewhere, in the same class
// as a SARIF import; capped at 1 MiB it would reject every real pipeline result.
func TestImportProjectAnalysisCarriesTheImportCeiling(t *testing.T) {
	rt := newImportRouter(t)
	handler := rt.Handler()

	// A well-formed body padded past the 1 MiB default with a long, valid string field.
	padding := strings.Repeat("a", int(defaultBodyLimit)+(512<<10))
	body := strings.Replace(importBody, `"actor":"octocat"`, `"actor":"octocat","run_id":"`+padding+`"`, 1)
	body = strings.Replace(body, `"run_id":"7",`, ``, 1)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/projects/app/analyses/import", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer ci")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	// The over-long run_id is refused by validation, which is the point: the body got THROUGH the
	// transport ceiling and reached the handler, rather than dying at 1 MiB.
	if rec.Code == http.StatusRequestEntityTooLarge {
		t.Fatalf("a 1.5 MiB pipeline result was rejected at the transport ceiling: %s", rec.Body.String())
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected the over-long ci field to be refused by validation, got %d %s", rec.Code, rec.Body.String())
	}
}
