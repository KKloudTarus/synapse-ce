package httpapi

import (
	"context"
	"net/http"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetdesired"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	desireduc "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/desired"
)

type fakeDesired struct {
	setIn   desireduc.SetInput
	clearIn desireduc.ClearInput
}

func (f *fakeDesired) SetDesiredCapabilities(_ context.Context, in desireduc.SetInput) (*fleetdesired.State, error) {
	f.setIn = in
	return &fleetdesired.State{TenantID: in.TenantID, AssetID: in.AssetID, Capabilities: in.Capabilities}, nil
}
func (f *fakeDesired) Get(_ context.Context, tenantID, assetID shared.ID) (*fleetdesired.State, error) {
	return &fleetdesired.State{TenantID: tenantID, AssetID: assetID}, nil
}
func (f *fakeDesired) ClearDesiredCapabilities(_ context.Context, in desireduc.ClearInput) error {
	f.clearIn = in
	return nil
}
func (f *fakeDesired) Gaps(_ context.Context, _ shared.ID) ([]desireduc.ReconciliationRow, error) {
	return []desireduc.ReconciliationRow{{AssetID: "asset-1", Capability: "edr", Covered: false}}, nil
}

func newDesiredRouter(f *fakeDesired) *http.ServeMux {
	rt := &Router{log: discardLog(), incidents: &fakeIncidentStore{}, desiredCapabilities: f}
	return rt.routes()
}

func TestDesiredCapabilitiesRBACAndServerSideScoping(t *testing.T) {
	f := &fakeDesired{}
	mux := newDesiredRouter(f)

	// readonly cannot set (writes desired state → PermOperate).
	if rec := incidentReq(mux, "readonly", http.MethodPut, "/api/v1/fleet/assets/asset-7/desired-capabilities", `{"capabilities":["edr"]}`); rec.Code != http.StatusForbidden {
		t.Fatalf("readonly set must be forbidden, got %d", rec.Code)
	}
	// consultant can set; tenant + asset + actor come from ctx/path/principal, not the body.
	if rec := incidentReq(mux, "consultant", http.MethodPut, "/api/v1/fleet/assets/asset-7/desired-capabilities", `{"capabilities":["edr"]}`); rec.Code != http.StatusOK {
		t.Fatalf("consultant set: got %d (%s)", rec.Code, rec.Body.String())
	}
	if f.setIn.AssetID != "asset-7" || f.setIn.TenantID != "tenant-a" || f.setIn.Actor != "analyst-1" || len(f.setIn.Capabilities) != 1 {
		t.Fatalf("set input not scoped server-side: %+v", f.setIn)
	}
	// readonly CAN read gaps + get (PermView).
	if rec := incidentReq(mux, "readonly", http.MethodGet, "/api/v1/fleet/desired-capabilities/gaps", ""); rec.Code != http.StatusOK {
		t.Fatalf("readonly gaps: got %d", rec.Code)
	}
	if rec := incidentReq(mux, "readonly", http.MethodGet, "/api/v1/fleet/assets/asset-7/desired-capabilities", ""); rec.Code != http.StatusOK {
		t.Fatalf("readonly get: got %d", rec.Code)
	}
}

func TestDesiredRoutesAbsentWhenUnwired(t *testing.T) {
	rt := &Router{log: discardLog(), incidents: &fakeIncidentStore{}} // no desired service
	if rec := incidentReq(rt.routes(), "consultant", http.MethodGet, "/api/v1/fleet/desired-capabilities/gaps", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("unwired desired route must 404, got %d", rec.Code)
	}
}
