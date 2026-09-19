package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	businessassetuc "github.com/KKloudTarus/synapse-ce/internal/usecase/businessassetuc"
)

func newBusinessAssetRouter(t *testing.T) *Router {
	t.Helper()
	assets := memory.NewAssetStore()
	service, err := businessassetuc.NewService(assets, memory.NewFindingRepository(), memory.NewImportedFindingStore(), memory.NewJudgmentStore(), memory.NewRetestRepository(), &fakeAudit{}, fixedClock{}, engIDs{})
	if err != nil {
		t.Fatal(err)
	}
	return &Router{log: discardLog(), businessAssets: service}
}

func TestBusinessAssetRoutesRBACIsolationAndConflicts(t *testing.T) {
	routes := newBusinessAssetRouter(t).routes()
	call := func(role, tenant, method, path string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "alice", Role: role, TenantID: tenant}))
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, req)
		return rec
	}

	body := []byte(`{"key":"mobile","name":"Mobile Banking","description":"Customer app","type":"application","criticality":"critical","owner":"mobile-team"}`)
	if rec := call("readonly", "tenant-a", http.MethodPost, "/api/v1/appsec/assets", body); rec.Code != http.StatusForbidden {
		t.Fatalf("readonly create status=%d", rec.Code)
	}
	created := call("consultant", "tenant-a", http.MethodPost, "/api/v1/appsec/assets", body)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	var asset struct {
		ID      string
		Version int
	}
	if err := json.Unmarshal(created.Body.Bytes(), &asset); err != nil {
		t.Fatal(err)
	}
	if asset.ID == "" || asset.Version != 1 {
		t.Fatalf("created asset=%+v", asset)
	}

	findings := call("readonly", "tenant-a", http.MethodGet, "/api/v1/appsec/assets/"+asset.ID+"/findings", nil)
	if findings.Code != http.StatusOK {
		t.Fatalf("findings status=%d body=%s", findings.Code, findings.Body.String())
	}
	if vary := strings.Join(findings.Header().Values("Vary"), ","); !strings.Contains(vary, clientCapabilitiesHeader) {
		t.Fatalf("findings Vary=%q, want %s", vary, clientCapabilitiesHeader)
	}

	if rec := call("consultant", "tenant-a", http.MethodPost, "/api/v1/appsec/assets", body); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate key status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := call("readonly", "tenant-a", http.MethodGet, "/api/v1/appsec/assets?limit=0", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid pagination status=%d", rec.Code)
	}
	if rec := call("readonly", "tenant-b", http.MethodGet, "/api/v1/appsec/assets/"+asset.ID, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant known-id status=%d body=%s", rec.Code, rec.Body.String())
	}

	stale := []byte(`{"name":"Mobile Banking","description":"Customer app","type":"application","criticality":"critical","lifecycle":"active","owner":"mobile-team","version":99}`)
	if rec := call("consultant", "tenant-a", http.MethodPatch, "/api/v1/appsec/assets/"+asset.ID, stale); rec.Code != http.StatusConflict {
		t.Fatalf("stale update status=%d body=%s", rec.Code, rec.Body.String())
	}
	valid := []byte(`{"name":"Mobile Banking","description":"Customer app","type":"application","criticality":"critical","lifecycle":"active","owner":"mobile-team","version":1}`)
	if rec := call("consultant", "tenant-a", http.MethodPatch, "/api/v1/appsec/assets/"+asset.ID, valid); rec.Code != http.StatusOK {
		t.Fatalf("valid update status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestBusinessAssetHasSingleWritePath(t *testing.T) {
	rt := newBusinessAssetRouter(t)
	rt.SetAssets(fakeAssetService{})
	routes := rt.routes()
	call := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader([]byte(`{"key":"mobile","name":"Mobile","type":"application","criticality":"high","owner":"team"}`)))
		req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "alice", Role: "consultant", TenantID: "tenant-a"}))
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, req)
		return rec
	}
	if rec := call("/api/v1/assets/services"); rec.Code != http.StatusNotFound {
		t.Fatalf("legacy Business Asset write path status=%d, want 404", rec.Code)
	}
	if rec := call("/api/v1/appsec/assets"); rec.Code != http.StatusCreated {
		t.Fatalf("canonical Business Asset write path status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestExternalFindingKindRequiresClientCapability(t *testing.T) {
	rows := []businessassetuc.AggregatedFinding{
		{Finding: finding.Finding{Kind: finding.KindExternal}, External: true},
		{Finding: finding.Finding{Kind: finding.KindSCA}},
		// Compatibility is keyed by the enum itself, not the redundant External metadata.
		{Finding: finding.Finding{Kind: finding.KindExternal}, External: false},
	}

	legacy := findingRowsForClient(rows, false)
	if legacy[0].Finding.Kind != "" {
		t.Fatalf("legacy client received new external enum: %q", legacy[0].Finding.Kind)
	}
	if legacy[1].Finding.Kind != finding.KindSCA {
		t.Fatalf("legacy projection changed existing kind: %q", legacy[1].Finding.Kind)
	}
	if legacy[2].Finding.Kind != "" {
		t.Fatalf("legacy client leaked external enum when metadata disagreed: %q", legacy[2].Finding.Kind)
	}
	if rows[0].Finding.Kind != finding.KindExternal {
		t.Fatal("compatibility projection mutated the service result")
	}

	capable := findingRowsForClient(rows, true)
	if capable[0].Finding.Kind != finding.KindExternal {
		t.Fatalf("capable client kind=%q, want external", capable[0].Finding.Kind)
	}
	legacyJSON, err := json.Marshal(legacy[0])
	if err != nil {
		t.Fatal(err)
	}
	capableJSON, err := json.Marshal(capable[0])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(legacyJSON, []byte(`"Kind":"external"`)) {
		t.Fatalf("legacy serialization leaked external enum: %s", legacyJSON)
	}
	if !bytes.Contains(capableJSON, []byte(`"Kind":"external"`)) {
		t.Fatalf("capable serialization omitted external enum: %s", capableJSON)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/appsec/assets/a/findings", nil)
	req.Header.Set(clientCapabilitiesHeader, "another-v1, "+externalFindingKindCapability)
	if !hasClientCapability(req, externalFindingKindCapability) {
		t.Fatal("comma-separated external finding capability was not recognized")
	}
}
