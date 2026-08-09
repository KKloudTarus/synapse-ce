package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/attackpath"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/importedfinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type fakeAttackPaths struct {
	tenant shared.ID
	query  attackpath.Query
	calls  int
	result attackpath.Result
}

func (f *fakeAttackPaths) Query(_ context.Context, tenant shared.ID, query attackpath.Query) (attackpath.Result, error) {
	f.tenant = tenant
	f.query = query
	f.calls++
	return f.result, nil
}

func TestRouterAttackPathRoute(t *testing.T) {
	rt := &Router{log: discardLog()}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/attack-paths", nil)
	rec := httptest.NewRecorder()
	rt.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("before SetAttackPaths = %d, want 404", rec.Code)
	}
	fake := &fakeAttackPaths{result: attackpath.Result{Paths: []attackpath.Path{}, Bounds: attackpath.BoundReport{MaxLength: 12, MaxPaths: 100}}}
	rt.SetAttackPaths(fake)
	req = httptest.NewRequest(http.MethodGet, "/api/v1/attack-paths?target=a&entrypoint=e&finding=f", nil).WithContext(context.WithValue(context.Background(), principalKey, Principal{ID: "p", Role: "readonly", TenantID: "tenantA"}))
	rec = httptest.NewRecorder()
	rt.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || fake.tenant != "tenantA" || fake.query.Finding != "f" || fake.query.FindingTarget != nil {
		t.Fatalf("route = %d tenant=%q query=%#v body=%s", rec.Code, fake.tenant, fake.query, rec.Body.String())
	}
	var body struct {
		Bounds struct {
			MaxLength int `json:"maxLength"`
		} `json:"bounds"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Bounds.MaxLength != 12 {
		t.Fatalf("public shape = %s, %v", rec.Body.String(), err)
	}
}

func TestRouterAttackPathFindingKindQuery(t *testing.T) {
	rt := &Router{log: discardLog()}
	fake := &fakeAttackPaths{result: attackpath.Result{Paths: []attackpath.Path{}}}
	rt.SetAttackPaths(fake)
	principal := context.WithValue(context.Background(), principalKey, Principal{ID: "p", Role: "readonly", TenantID: "tenantA"})
	for _, tc := range []struct {
		name   string
		path   string
		status int
		calls  int
		kind   attackpath.TargetKind
	}{
		{name: "canonical", path: "/api/v1/attack-paths?finding=same&finding_kind=canonical", status: http.StatusOK, calls: 1, kind: attackpath.TargetCanonical},
		{name: "imported", path: "/api/v1/attack-paths?finding=same&finding_kind=imported", status: http.StatusOK, calls: 2, kind: attackpath.TargetImported},
		{name: "kind without finding", path: "/api/v1/attack-paths?finding_kind=canonical", status: http.StatusBadRequest, calls: 2},
		{name: "invalid kind", path: "/api/v1/attack-paths?finding=same&finding_kind=other", status: http.StatusBadRequest, calls: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			rt.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil).WithContext(principal))
			if rec.Code != tc.status || fake.calls != tc.calls {
				t.Fatalf("status=%d calls=%d body=%s", rec.Code, fake.calls, rec.Body.String())
			}
			if tc.kind != "" && (fake.query.FindingTarget == nil || fake.query.FindingTarget.ID != "same" || fake.query.FindingTarget.Kind != tc.kind) {
				t.Fatalf("typed query = %#v", fake.query)
			}
		})
	}
}

func TestRouterAttackPathImportedFindingJSON(t *testing.T) {
	input := attackpath.FindingInput{
		Target:   attackpath.FindingTarget{ID: "imported", Kind: attackpath.TargetImported},
		Finding:  finding.Finding{ID: "imported", EngagementID: "eng", Title: "external", Severity: shared.SeverityHigh},
		External: true,
		ImportedProvenance: &importedfinding.Provenance{
			ToolName: "semgrep", ToolVersion: "1.2.3", RuleID: "rule", SourceDigest: "sha256:source", IngestedBy: "human:alice", IngestedAt: time.Unix(1, 0).UTC(),
		},
	}
	result := attackpath.Result{Paths: []attackpath.Path{{ID: "path", Nodes: []attackpath.Node{{Finding: &attackpath.FindingNode{Input: input}}}, Steps: []attackpath.Step{{Kind: "affected_by", ToFinding: true, Evidence: []attackpath.EdgeEvidence{{Producer: "scanner", Provenance: "immutable", Confidence: "observed"}}}}}}}
	rt := &Router{log: discardLog()}
	rt.SetAttackPaths(&fakeAttackPaths{result: result})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/attack-paths", nil).WithContext(context.WithValue(context.Background(), principalKey, Principal{ID: "p", Role: "readonly", TenantID: "tenantA"}))
	rec := httptest.NewRecorder()
	rt.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	encoded := body["paths"].([]any)[0].(map[string]any)["nodes"].([]any)[0].(map[string]any)["finding"].(map[string]any)["input"].(map[string]any)
	provenance := encoded["importedProvenance"].(map[string]any)
	step := body["paths"].([]any)[0].(map[string]any)["steps"].([]any)[0].(map[string]any)
	evidence := step["evidence"].([]any)[0].(map[string]any)
	if encoded["external"] != true || encoded["target"].(map[string]any)["Kind"] != "imported" || provenance["ToolName"] != "semgrep" || provenance["ToolVersion"] != "1.2.3" || provenance["RuleID"] != "rule" || provenance["SourceDigest"] != "sha256:source" || evidence["producer"] != "scanner" || evidence["provenance"] != "immutable" {
		t.Fatalf("imported API payload = %s", rec.Body.String())
	}
}
