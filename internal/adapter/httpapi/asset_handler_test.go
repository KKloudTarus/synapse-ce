package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/assetuc"
)

type fakeAssetService struct{}

func (fakeAssetService) UpsertAsset(context.Context, string, assetuc.UpsertAssetInput) (*asset.Asset, error) {
	return &asset.Asset{}, nil
}
func (fakeAssetService) ListAssets(context.Context, shared.ID) ([]*asset.Asset, error) {
	return nil, nil
}
func (fakeAssetService) UpsertEdge(context.Context, string, assetuc.EdgeInput) error { return nil }
func (fakeAssetService) ListEdges(context.Context, shared.ID) ([]*asset.Edge, error) { return nil, nil }
func (fakeAssetService) Workloads(context.Context, shared.ID) ([]assetuc.WorkloadOrigin, error) {
	return nil, nil
}

func TestRouter_AssetRoutePresence(t *testing.T) {
	rt := &Router{log: discardLog()}

	call := func(method, path string) int {
		req := httptest.NewRequest(method, path, nil)
		w := httptest.NewRecorder()
		rt.routes().ServeHTTP(w, req)
		return w.Code
	}

	paths := []struct {
		method, path string
	}{
		{http.MethodGet, "/api/v1/assets"},
		{http.MethodGet, "/api/v1/assets/edges"},
	}

	// Not registered before SetAssets.
	for _, p := range paths {
		if code := call(p.method, p.path); code != http.StatusNotFound {
			t.Errorf("%s %s: expected 404 before SetAssets, got %d", p.method, p.path, code)
		}
	}

	rt.SetAssets(fakeAssetService{})

	// Present after SetAssets.
	for _, p := range paths {
		if code := call(p.method, p.path); code == http.StatusNotFound {
			t.Errorf("%s %s: expected route present after SetAssets, got 404", p.method, p.path)
		}
	}
	if code := call(http.MethodPost, "/api/v1/assets/services"); code != http.StatusNotFound {
		t.Fatalf("retired Business Asset write path returned %d, want 404", code)
	}
}

// A successful edge upsert answers 204 (no body), not a bodyless 201, so a JSON client does not
// fail parsing an empty response.
func TestRouter_CreateAssetEdge_NoContent(t *testing.T) {
	rt := &Router{log: discardLog()}
	rt.SetAssets(fakeAssetService{})

	body := strings.NewReader(`{"from":"asset-a","to":"asset-b","kind":"depends_on","provenance":"obs-1","confidence":"observed"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/assets/edges", body)
	w := httptest.NewRecorder()
	rt.createAssetEdge(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("POST /assets/edges: got %d, want 204", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Fatalf("expected an empty body, got %q", w.Body.String())
	}
}
