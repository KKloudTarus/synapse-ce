package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/importedfinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/sarifingest"
)

// fakeImportedFindings is the read side under test.
type fakeImportedFindings struct {
	tenant shared.ID
	list   []importedfinding.ImportedFinding
}

func (f *fakeImportedFindings) ListByEngagement(_ context.Context, tenantID, _ shared.ID) ([]importedfinding.ImportedFinding, error) {
	f.tenant = tenantID
	return f.list, nil
}

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

// TestSARIFImportPassesTheRawTenant locks the tenancy contract: the handler forwards the principal's
// tenant UNCHANGED, and the use case resolves the engagement inside it and takes the row tenant from the
// engagement. Normalizing here instead is what let an empty-tenant principal pass a wildcard engagement
// gate for another tenant and then stamp the rows `default` — two different answers to "which tenant".
func TestSARIFImportPassesTheRawTenant(t *testing.T) {
	t.Parallel()

	tests := []struct{ name, tenant string }{
		{"single-tenant principal", ""},
		{"explicit tenant", "tenantA"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, rec, w := sarifRequest(t, Principal{ID: "alice", Role: "consultant", TenantID: test.tenant},
				`{"version":"2.1.0","runs":[]}`)
			if w.Code != http.StatusOK {
				t.Fatalf("ingest = %d, want 200", w.Code)
			}
			if string(rec.got.TenantID) != test.tenant {
				t.Fatalf("tenant = %q, want the principal's own %q, unmodified", rec.got.TenantID, test.tenant)
			}
			if rec.got.Actor != "alice" {
				t.Fatalf("actor = %q, want the authenticated principal", rec.got.Actor)
			}
			if rec.got.EngagementID != "eng-1" {
				t.Fatalf("engagement = %q, want the path segment", rec.got.EngagementID)
			}
		})
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

// TestImportedFindingsReadStatesTheGovernancePosition locks that the read surface makes an imported
// finding's status explicit rather than leaving it to be inferred: every row says it is external and
// that it cannot promote itself, and carries the provenance it was refused without.
func TestImportedFindingsReadStatesTheGovernancePosition(t *testing.T) {
	t.Parallel()

	reader := &fakeImportedFindings{list: []importedfinding.ImportedFinding{{
		ID: "if-1", TenantID: shared.DefaultTenant, EngagementID: "eng-1", Severity: shared.SeverityUnknown,
		Title: "Injection", Location: importedfinding.Location{Path: "src/app.go", StartLine: 42},
		Provenance: importedfinding.Provenance{
			ToolName: "semgrep", ToolVersion: "1.2.3", RuleID: "rule.a", SourceDigest: "abc",
			IngestedBy: "human:alice", IngestedAt: time.Unix(1700000000, 0).UTC(),
		},
	}}}
	rt := &Router{}
	rt.SetImportedFindings(reader)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/engagements/eng-1/imported-findings", nil)
	req.SetPathValue("id", "eng-1")
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "alice", Role: "readonly"}))
	w := httptest.NewRecorder()
	rt.listImportedFindings(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("read = %d, want 200", w.Code)
	}
	var payload []struct {
		External       bool   `json:"external"`
		CanSelfPromote bool   `json:"can_self_promote"`
		Severity       string `json:"severity"`
		Tool           string `json:"tool"`
		SourceDigest   string `json:"source_digest"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(payload) != 1 {
		t.Fatalf("expected one finding, got %d", len(payload))
	}
	if !payload[0].External || payload[0].CanSelfPromote {
		t.Fatalf("an imported finding must render as external and unable to self-promote, got %+v", payload[0])
	}
	if payload[0].Severity != "unknown" {
		t.Fatalf("severity = %q: an unmapped severity must stay unknown on the wire", payload[0].Severity)
	}
	if payload[0].Tool == "" || payload[0].SourceDigest == "" {
		t.Fatalf("provenance must reach the reader, got %+v", payload[0])
	}
	// The store partition uses a non-empty tenant, so the empty single-tenant principal is normalized
	// HERE — after the engagement gate has already authorized the read.
	if reader.tenant != shared.DefaultTenant {
		t.Fatalf("store tenant = %q, want the normalized default", reader.tenant)
	}
}
