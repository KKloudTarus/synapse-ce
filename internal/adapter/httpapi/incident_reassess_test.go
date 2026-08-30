package httpapi

import (
	"context"
	"net/http"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/correlationuc"
)

// fakeReassessor records the actor + id it was called with and returns a fixed incident.
type fakeReassessor struct {
	gotActor string
	gotID    shared.ID
	calls    int
}

func (f *fakeReassessor) Reassess(_ context.Context, actor string, id shared.ID) (incident.Incident, error) {
	f.calls++
	f.gotActor = actor
	f.gotID = id
	return incident.Incident{ID: id, State: incident.StateOpen}, nil
}

func newReassessRouter(f *fakeReassessor) *http.ServeMux {
	rt := &Router{log: discardLog(), incidents: &fakeIncidentStore{}, incidentRiskReassessor: f}
	return rt.routes()
}

func TestReassessIncidentRiskRBAC(t *testing.T) {
	cases := []struct {
		role string
		want int
	}{
		{"readonly", http.StatusForbidden}, // reassess writes the incident → needs PermOperate
		{"consultant", http.StatusOK},
		{"admin", http.StatusOK},
	}
	for _, c := range cases {
		t.Run(c.role, func(t *testing.T) {
			f := &fakeReassessor{}
			rec := incidentReq(newReassessRouter(f), c.role, http.MethodPost, "/api/v1/fleet/incidents/inc-1/risk/reassess", "")
			if rec.Code != c.want {
				t.Fatalf("as %s: got %d, want %d (%s)", c.role, rec.Code, c.want, rec.Body.String())
			}
		})
	}
}

// TestReassessIncidentRiskActorIsPrincipal proves the reassessment actor is the authenticated principal
// (never a body field) and the path id is threaded through — the attributability property.
func TestReassessIncidentRiskActorIsPrincipal(t *testing.T) {
	f := &fakeReassessor{}
	rec := incidentReq(newReassessRouter(f), "consultant", http.MethodPost, "/api/v1/fleet/incidents/inc-42/risk/reassess", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("reassess: got %d (%s)", rec.Code, rec.Body.String())
	}
	if f.calls != 1 || f.gotActor != "analyst-1" || f.gotID != "inc-42" {
		t.Fatalf("actor/id not threaded from principal + path: calls=%d actor=%q id=%q", f.calls, f.gotActor, f.gotID)
	}
}

// TestReassessRouteAbsentWhenUnwired: the route is registered only when a reassessor is set (nil ⇒ 404).
func TestReassessRouteAbsentWhenUnwired(t *testing.T) {
	rt := &Router{log: discardLog(), incidents: &fakeIncidentStore{}} // no reassessor
	rec := incidentReq(rt.routes(), "consultant", http.MethodPost, "/api/v1/fleet/incidents/inc-1/risk/reassess", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unwired reassess route must 404, got %d", rec.Code)
	}
}

// fakeCorrelator records the actor + engagement id and returns a fixed result.
type fakeCorrelator struct {
	gotActor string
	gotEng   shared.ID
	calls    int
}

func (f *fakeCorrelator) CorrelateEngagement(_ context.Context, actor string, eng shared.ID) (correlationuc.Result, error) {
	f.calls++
	f.gotActor = actor
	f.gotEng = eng
	return correlationuc.Result{Created: []incident.Incident{{ID: "inc-new"}}, Reassessed: 1}, nil
}

func TestCorrelateEngagementRBACAndActor(t *testing.T) {
	// readonly is forbidden (creates incidents → PermOperate); consultant is allowed + actor is the principal.
	f := &fakeCorrelator{}
	rt := &Router{log: discardLog(), incidents: &fakeIncidentStore{}, incidentCorrelator: f}
	mux := rt.routes()

	if rec := incidentReq(mux, "readonly", http.MethodPost, "/api/v1/fleet/engagements/eng-1/correlate", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("readonly must be forbidden, got %d", rec.Code)
	}
	rec := incidentReq(mux, "consultant", http.MethodPost, "/api/v1/fleet/engagements/eng-7/correlate", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("consultant correlate: got %d (%s)", rec.Code, rec.Body.String())
	}
	if f.calls != 1 || f.gotActor != "analyst-1" || f.gotEng != "eng-7" {
		t.Fatalf("actor/engagement not threaded: calls=%d actor=%q eng=%q", f.calls, f.gotActor, f.gotEng)
	}
}

func TestCorrelateRouteAbsentWhenUnwired(t *testing.T) {
	rt := &Router{log: discardLog(), incidents: &fakeIncidentStore{}} // no correlator
	if rec := incidentReq(rt.routes(), "consultant", http.MethodPost, "/api/v1/fleet/engagements/eng-1/correlate", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("unwired correlate route must 404, got %d", rec.Code)
	}
}
