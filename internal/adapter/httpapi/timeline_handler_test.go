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

func TestTimelinePermViewAndScoping(t *testing.T) {
	tl := &fakeTimeline{}
	rt := &Router{log: discardLog(), incidents: &fakeIncidentStore{}, endpointTimeline: tl, retroHunter: &fakeHunter{}}
	mux := rt.routes()

	// readonly can read the timeline (PermView) + asset from path.
	if rec := incidentReq(mux, "readonly", http.MethodGet, "/api/v1/fleet/assets/asset-3/timeline?limit=10", ""); rec.Code != http.StatusOK {
		t.Fatalf("readonly timeline: got %d (%s)", rec.Code, rec.Body.String())
	}
	if tl.gotQ.AssetID != "asset-3" || tl.gotQ.Limit != 10 {
		t.Fatalf("timeline query not scoped from path/params: %+v", tl.gotQ)
	}
}

// A retro-hunt runs a timeline query over a caller-chosen window, so starting one spends compute the way
// its PermOperate siblings (process report, behavior re-baseline) do. A role that may not write anything
// must not be able to start one; reading the stored timeline stays PermView.
func TestRetroHuntRequiresPermOperate(t *testing.T) {
	const path = "/api/v1/fleet/assets/asset-3/retro-hunt"
	const body = `{"before_seconds":60,"after_seconds":60}`
	tests := []struct {
		role string
		want int
	}{
		{"readonly", http.StatusForbidden},
		{"integration_admin", http.StatusForbidden},
		{"reviewer", http.StatusForbidden},
		{"consultant", http.StatusOK},
		{"member", http.StatusOK},
		{"admin", http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.role, func(t *testing.T) {
			h := &fakeHunter{}
			rt := &Router{log: discardLog(), incidents: &fakeIncidentStore{}, endpointTimeline: &fakeTimeline{}, retroHunter: h}
			rec := incidentReq(rt.routes(), tt.role, http.MethodPost, path, body)
			if rec.Code != tt.want {
				t.Fatalf("%s retro-hunt: got %d, want %d (%s)", tt.role, rec.Code, tt.want, rec.Body.String())
			}
			if tt.want != http.StatusOK {
				if h.gotReq.AssetID != "" {
					t.Fatalf("%s was refused but the hunt still ran: %+v", tt.role, h.gotReq)
				}
				return
			}
			if h.gotReq.AssetID != "asset-3" {
				t.Fatalf("retro-hunt asset not from path: %+v", h.gotReq)
			}
		})
	}
}

func TestTimelineRoutesAbsentWhenUnwired(t *testing.T) {
	rt := &Router{log: discardLog(), incidents: &fakeIncidentStore{}}
	if rec := incidentReq(rt.routes(), "readonly", http.MethodGet, "/api/v1/fleet/assets/a1/timeline", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("unwired timeline route must 404, got %d", rec.Code)
	}
}
