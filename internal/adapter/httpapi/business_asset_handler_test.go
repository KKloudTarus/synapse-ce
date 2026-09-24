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

// The shared engIDs fake answers one constant id. That is fine for a single-row test and wrong
// for anything that counts or pages: every create would reuse the id and overwrite the last row.
// seqIDs (user_handler_test.go) mints distinct ones.
func newBusinessAssetRouterSeq(t *testing.T) *Router {
	t.Helper()
	assets := memory.NewAssetStore()
	service, err := businessassetuc.NewService(assets, memory.NewFindingRepository(), memory.NewImportedFindingStore(), memory.NewJudgmentStore(), memory.NewRetestRepository(), &fakeAudit{}, fixedClock{}, &seqIDs{})
	if err != nil {
		t.Fatal(err)
	}
	return &Router{log: discardLog(), businessAssets: service}
}

// The inventory's estate-wide "Critical" figure comes from this route, so a tenant reading
// another tenant's histogram would be a cross-tenant leak of how much critical infrastructure
// they run. The route carries no path parameter, so the hostile harness's tenant sweep does not
// select it (harness_test.go picks GET routes containing /engagements/{, /projects/{ or /assets/{)
// and this is the only place that scoping is asserted above the repository.
func TestBusinessAssetCountsRBACIsolationAndShape(t *testing.T) {
	routes := newBusinessAssetRouterSeq(t).routes()
	call := func(role, tenant, method, path string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "alice", Role: role, TenantID: tenant}))
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, req)
		return rec
	}
	create := func(tenant, key, criticality string) {
		t.Helper()
		body := []byte(`{"key":"` + key + `","name":"` + key + `","description":"d","type":"application","criticality":"` + criticality + `","owner":"team"}`)
		if rec := call("consultant", tenant, http.MethodPost, "/api/v1/appsec/assets", body); rec.Code != http.StatusCreated {
			t.Fatalf("create %s/%s status=%d body=%s", tenant, key, rec.Code, rec.Body.String())
		}
	}

	create("tenant-a", "pay", "critical")
	create("tenant-a", "ledger", "critical")
	create("tenant-a", "wiki", "low")
	create("tenant-b", "other", "critical")

	counts := func(role, tenant string) (map[string]int, int, int) {
		t.Helper()
		rec := call(role, tenant, http.MethodGet, "/api/v1/appsec/asset-counts", nil)
		var out struct {
			ByCriticality map[string]int `json:"by_criticality"`
			Total         int            `json:"total"`
		}
		if rec.Code == http.StatusOK {
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
				t.Fatalf("decode counts: %v body=%s", err, rec.Body.String())
			}
		}
		return out.ByCriticality, out.Total, rec.Code
	}

	// View is the lowest role that may read the inventory, so readonly must be allowed here: a
	// 403 would leave the summary strip permanently "unavailable" for every read-only operator.
	byCriticality, total, code := counts("readonly", "tenant-a")
	if code != http.StatusOK {
		t.Fatalf("readonly counts status=%d", code)
	}
	if byCriticality["critical"] != 2 || byCriticality["low"] != 1 || total != 3 {
		t.Fatalf("tenant-a counts=%v total=%d, want 2 critical, 1 low, 3 total", byCriticality, total)
	}

	// The histogram is the tenant's own estate. Tenant B has one critical asset of its own and
	// must never see tenant A's two.
	byCriticality, total, code = counts("readonly", "tenant-b")
	if code != http.StatusOK {
		t.Fatalf("tenant-b counts status=%d", code)
	}
	if byCriticality["critical"] != 1 || total != 1 {
		t.Fatalf("tenant-b counts=%v total=%d, want only its own row", byCriticality, total)
	}

	// A tenant with nothing gets zeroes, not another tenant's figures.
	byCriticality, total, code = counts("readonly", "tenant-empty")
	if code != http.StatusOK {
		t.Fatalf("empty tenant counts status=%d", code)
	}
	if total != 0 || len(byCriticality) != 0 {
		t.Fatalf("empty tenant counts=%v total=%d, want empty", byCriticality, total)
	}
}

// The list's `total` is the count of every row matching the filter, which is what the pager
// divides to get its page count. Answering with len(items) would make the last page the only
// page, and no existing assertion could tell the difference because every case fetched fewer
// rows than the limit.
func TestBusinessAssetListTotalCountsBeyondThePage(t *testing.T) {
	routes := newBusinessAssetRouterSeq(t).routes()
	call := func(method, path string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "alice", Role: "consultant", TenantID: "tenant-a"}))
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, req)
		return rec
	}
	for _, key := range []string{"alpha", "bravo", "charlie", "delta", "echo"} {
		body := []byte(`{"key":"` + key + `","name":"` + key + `","description":"d","type":"application","criticality":"low","owner":"team"}`)
		if rec := call(http.MethodPost, "/api/v1/appsec/assets", body); rec.Code != http.StatusCreated {
			t.Fatalf("create %s status=%d body=%s", key, rec.Code, rec.Body.String())
		}
	}

	page := func(path string) (int, int, int) {
		t.Helper()
		rec := call(http.MethodGet, path, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("list %s status=%d body=%s", path, rec.Code, rec.Body.String())
		}
		var out struct {
			Items  []json.RawMessage `json:"items"`
			Total  int               `json:"total"`
			Offset int               `json:"offset"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode list: %v", err)
		}
		return len(out.Items), out.Total, out.Offset
	}

	if items, total, _ := page("/api/v1/appsec/assets?limit=2"); items != 2 || total != 5 {
		t.Fatalf("first page items=%d total=%d, want 2 of 5", items, total)
	}
	if items, total, offset := page("/api/v1/appsec/assets?limit=2&offset=4"); items != 1 || total != 5 || offset != 4 {
		t.Fatalf("last page items=%d total=%d offset=%d, want 1 of 5 at offset 4", items, total, offset)
	}
	// Past the end still reports the estate so the pager can correct itself, and the echoed
	// offset is clamped to the total rather than repeating what the caller asked for.
	if items, total, offset := page("/api/v1/appsec/assets?limit=2&offset=50"); items != 0 || total != 5 || offset != 5 {
		t.Fatalf("past the end items=%d total=%d offset=%d, want 0 of 5 clamped to 5", items, total, offset)
	}
}
