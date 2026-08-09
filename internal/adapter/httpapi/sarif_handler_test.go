package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/importedfinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/sarifingest"
)

// recordingSARIF captures the request the handler builds, so the tests can assert on what the usecase
// actually receives rather than on what the handler appears to pass.
type recordingSARIF struct {
	got    sarifingest.IngestRequest
	result sarifingest.IngestResult
}

func (r *recordingSARIF) Ingest(_ context.Context, req sarifingest.IngestRequest) (sarifingest.IngestResult, error) {
	r.got = req
	return r.result, nil
}

func sarifRequest(t *testing.T, principal Principal, body string) (*Router, *recordingSARIF, *httptest.ResponseRecorder) {
	t.Helper()
	rt := &Router{}
	rec := &recordingSARIF{}
	rt.SetSARIFIngest(rec)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/engagements/eng-1/sarif", strings.NewReader(body))
	req.SetPathValue("id", "eng-1")
	req = req.WithContext(context.WithValue(req.Context(), principalKey, principal))
	w := httptest.NewRecorder()
	rt.importSARIF(w, req)
	return rt, rec, w
}

// TestSARIFImportWorksInSingleTenantMode is the regression for the route being dead in the DEFAULT
// deployment: TenantFrom is empty in single-tenant mode (and for the bootstrap admin), and the usecase
// rejects a zero tenant, so every ingest returned 400 until the handler normalized it.
func TestSARIFImportWorksInSingleTenantMode(t *testing.T) {
	t.Parallel()

	_, rec, w := sarifRequest(t, Principal{ID: "alice", Role: "consultant", TenantID: ""}, `{"version":"2.1.0","runs":[]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("single-tenant ingest = %d, want 200", w.Code)
	}
	if rec.got.TenantID != shared.DefaultTenant {
		t.Fatalf("tenant = %q, want the normalized default tenant %q", rec.got.TenantID, shared.DefaultTenant)
	}
	if rec.got.Actor != "alice" {
		t.Fatalf("actor = %q, want the authenticated principal", rec.got.Actor)
	}
	if rec.got.EngagementID != "eng-1" {
		t.Fatalf("engagement = %q, want the path segment", rec.got.EngagementID)
	}
}

// An explicit tenant is passed through untouched — normalizing must not collapse tenants.
func TestSARIFImportKeepsAnExplicitTenant(t *testing.T) {
	t.Parallel()

	_, rec, _ := sarifRequest(t, Principal{ID: "bob", Role: "consultant", TenantID: "tenantA"}, `{"version":"2.1.0","runs":[]}`)
	if rec.got.TenantID != "tenantA" {
		t.Fatalf("tenant = %q, want tenantA", rec.got.TenantID)
	}
}

// TestSARIFResponseSurfacesCoverage locks that what the ingest could NOT represent reaches the caller: a
// lossy ingest must not be indistinguishable from a complete one.
func TestSARIFResponseSurfacesCoverage(t *testing.T) {
	t.Parallel()

	rt := &Router{}
	rec := &recordingSARIF{result: sarifingest.IngestResult{
		Accepted: 1,
		Coverage: []importedfinding.CoverageIssue{{Detail: "3 results carried a severity this ingester cannot map"}},
		Refused: []importedfinding.RefusalReason{
			{RunIndex: 0, ResultIndex: 2, Code: importedfinding.RefusalPathTraversal, Detail: "artifact location is not a safe repository-relative path"},
		},
	}}
	rt.SetSARIFIngest(rec)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/engagements/eng-1/sarif", strings.NewReader(`{"version":"2.1.0","runs":[]}`))
	req.SetPathValue("id", "eng-1")
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "alice", Role: "consultant"}))
	w := httptest.NewRecorder()
	rt.importSARIF(w, req)

	var payload struct {
		Accepted int      `json:"accepted"`
		Coverage []string `json:"coverage"`
		Refused  []struct {
			Code string `json:"code"`
		} `json:"refused"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(payload.Coverage) != 1 {
		t.Fatalf("coverage must reach the caller, got %+v", payload.Coverage)
	}
	// Refusals stay a LIST, not a count.
	if len(payload.Refused) != 1 || payload.Refused[0].Code != string(importedfinding.RefusalPathTraversal) {
		t.Fatalf("refused = %+v, want the typed refusal listed individually", payload.Refused)
	}
}
