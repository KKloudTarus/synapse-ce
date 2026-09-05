package httpapi

import (
	"context"
	"net/http"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeProcessStore struct {
	saved []ports.ProcessSnapshot
}

func (f *fakeProcessStore) SaveProcesses(_ context.Context, s []ports.ProcessSnapshot) error {
	f.saved = append(f.saved, s...)
	return nil
}

func (f *fakeProcessStore) ListRunningByAsset(_ context.Context, assetID shared.ID) ([]ports.ProcessSnapshot, error) {
	var out []ports.ProcessSnapshot
	for _, p := range f.saved {
		if p.AssetID == assetID && p.Running {
			out = append(out, p)
		}
	}
	return out, nil
}

func newProcessRouter(f *fakeProcessStore) *http.ServeMux {
	rt := &Router{log: discardLog(), incidents: &fakeIncidentStore{}, endpointProcesses: f}
	return rt.routes()
}

func TestReportProcessesRBACAndServerSideScoping(t *testing.T) {
	f := &fakeProcessStore{}
	mux := newProcessRouter(f)
	body := `{"processes":[{"entity_id":"e1","pid":42,"comm":"nginx","path":"/usr/sbin/nginx","running":true}]}`

	// readonly cannot report (writes the projection → PermOperate).
	if rec := incidentReq(mux, "readonly", http.MethodPost, "/api/v1/fleet/assets/asset-9/processes", body); rec.Code != http.StatusForbidden {
		t.Fatalf("readonly report must be forbidden, got %d", rec.Code)
	}
	// consultant can report; tenant + asset come from ctx/path, not the body.
	if rec := incidentReq(mux, "consultant", http.MethodPost, "/api/v1/fleet/assets/asset-9/processes", body); rec.Code != http.StatusOK {
		t.Fatalf("consultant report: got %d (%s)", rec.Code, rec.Body.String())
	}
	if len(f.saved) != 1 || f.saved[0].AssetID != "asset-9" || f.saved[0].TenantID != "tenant-a" || f.saved[0].Comm != "nginx" {
		t.Fatalf("snapshot not scoped server-side or not persisted: %+v", f.saved)
	}
}

func TestListProcessesReadPerm(t *testing.T) {
	f := &fakeProcessStore{saved: []ports.ProcessSnapshot{{AssetID: "asset-9", EntityID: "e1", Running: true}}}
	mux := newProcessRouter(f)
	rec := incidentReq(mux, "readonly", http.MethodGet, "/api/v1/fleet/assets/asset-9/processes", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("readonly list: got %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestProcessRoutesAbsentWhenUnwired(t *testing.T) {
	rt := &Router{log: discardLog(), incidents: &fakeIncidentStore{}} // no process store
	if rec := incidentReq(rt.routes(), "consultant", http.MethodPost, "/api/v1/fleet/assets/a1/processes", "{}"); rec.Code != http.StatusNotFound {
		t.Fatalf("unwired process route must 404, got %d", rec.Code)
	}
}

type fakeRebaseliner struct {
	asset shared.ID
	actor string
	calls int
	err   error
}

func (f *fakeRebaseliner) Rebaseline(_ context.Context, actor string, assetID shared.ID) error {
	f.calls++
	f.actor, f.asset = actor, assetID
	return f.err
}

func TestRebaselineBehaviorRBACAndWiring(t *testing.T) {
	reb := &fakeRebaseliner{}
	rt := &Router{log: discardLog(), incidents: &fakeIncidentStore{}, behaviorRebaseliner: reb}
	mux := rt.routes()

	// readonly cannot re-baseline (it mutates security state → PermOperate).
	if rec := incidentReq(mux, "readonly", http.MethodPost, "/api/v1/fleet/assets/asset-9/behavior-baseline/rebaseline", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("readonly re-baseline must be forbidden, got %d", rec.Code)
	}
	// consultant can; the asset id comes from the path, the actor from the principal.
	if rec := incidentReq(mux, "consultant", http.MethodPost, "/api/v1/fleet/assets/asset-9/behavior-baseline/rebaseline", ""); rec.Code != http.StatusOK {
		t.Fatalf("consultant re-baseline: got %d (%s)", rec.Code, rec.Body.String())
	}
	if reb.calls != 1 || reb.asset != "asset-9" || reb.actor == "" {
		t.Fatalf("rebaseliner not called with the path asset + principal: %+v", reb)
	}
}

func TestRebaselineRouteAbsentWhenUnwired(t *testing.T) {
	rt := &Router{log: discardLog(), incidents: &fakeIncidentStore{}} // no rebaseliner
	if rec := incidentReq(rt.routes(), "consultant", http.MethodPost, "/api/v1/fleet/assets/a1/behavior-baseline/rebaseline", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("unwired re-baseline route must 404, got %d", rec.Code)
	}
}
