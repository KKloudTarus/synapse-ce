package httpapi

import (
	"context"
	"net/http"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/endpoint"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/retrohunt"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeTimeline struct{ gotQ ports.EndpointTimelineQuery }

func (f *fakeTimeline) Query(_ context.Context, q ports.EndpointTimelineQuery) ([]endpoint.TimelineEntry, error) {
	f.gotQ = q
	return nil, nil
}

type fakeHunter struct{ gotReq retrohunt.Request }

func (f *fakeHunter) Hunt(_ context.Context, req retrohunt.Request) (retrohunt.Result, error) {
	f.gotReq = req
	return retrohunt.Result{AssetID: req.AssetID}, nil
}

func TestTimelineAndRetroHuntPermViewAndScoping(t *testing.T) {
	tl := &fakeTimeline{}
	h := &fakeHunter{}
	rt := &Router{log: discardLog(), incidents: &fakeIncidentStore{}, endpointTimeline: tl, retroHunter: h}
	mux := rt.routes()

	// readonly can read the timeline (PermView) + asset from path.
	if rec := incidentReq(mux, "readonly", http.MethodGet, "/api/v1/fleet/assets/asset-3/timeline?limit=10", ""); rec.Code != http.StatusOK {
		t.Fatalf("readonly timeline: got %d (%s)", rec.Code, rec.Body.String())
	}
	if tl.gotQ.AssetID != "asset-3" || tl.gotQ.Limit != 10 {
		t.Fatalf("timeline query not scoped from path/params: %+v", tl.gotQ)
	}
	// readonly can retro-hunt (PermView, read-only analysis).
	if rec := incidentReq(mux, "readonly", http.MethodPost, "/api/v1/fleet/assets/asset-3/retro-hunt", `{"before_seconds":60,"after_seconds":60}`); rec.Code != http.StatusOK {
		t.Fatalf("readonly retro-hunt: got %d (%s)", rec.Code, rec.Body.String())
	}
	if h.gotReq.AssetID != "asset-3" {
		t.Fatalf("retro-hunt asset not from path: %+v", h.gotReq)
	}
}

func TestTimelineRoutesAbsentWhenUnwired(t *testing.T) {
	rt := &Router{log: discardLog(), incidents: &fakeIncidentStore{}}
	if rec := incidentReq(rt.routes(), "readonly", http.MethodGet, "/api/v1/fleet/assets/a1/timeline", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("unwired timeline route must 404, got %d", rec.Code)
	}
}
