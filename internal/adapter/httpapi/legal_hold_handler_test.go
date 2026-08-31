package httpapi

import (
	"context"
	"net/http"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/legalhold"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type fakeLegalHolds struct {
	placedEng    shared.ID
	placedBy     string
	placedReason string
	released     shared.ID
}

func (f *fakeLegalHolds) Place(_ context.Context, actor string, eng shared.ID, reason string) (legalhold.Hold, error) {
	f.placedEng, f.placedBy, f.placedReason = eng, actor, reason
	return legalhold.Hold{EngagementID: eng, PlacedBy: actor, Reason: reason}, nil
}
func (f *fakeLegalHolds) Release(_ context.Context, _ string, eng shared.ID) error {
	f.released = eng
	return nil
}
func (f *fakeLegalHolds) ListActive(context.Context) ([]legalhold.Hold, error) {
	return []legalhold.Hold{{EngagementID: "eng-1"}}, nil
}

func newLegalHoldRouter(f *fakeLegalHolds) *http.ServeMux {
	rt := &Router{log: discardLog(), incidents: &fakeIncidentStore{}, legalHolds: f}
	return rt.routes()
}

func TestLegalHoldRBACAndServerSideScoping(t *testing.T) {
	f := &fakeLegalHolds{}
	mux := newLegalHoldRouter(f)

	// consultant CANNOT place/release (a governance decision → PermReview).
	if rec := incidentReq(mux, "consultant", http.MethodPut, "/api/v1/fleet/engagements/eng-7/legal-hold", `{"reason":"litigation"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("consultant place must be forbidden (needs review), got %d", rec.Code)
	}
	// reviewer can place; actor + engagement from principal/path, reason from body.
	if rec := incidentReq(mux, "reviewer", http.MethodPut, "/api/v1/fleet/engagements/eng-7/legal-hold", `{"reason":"litigation JIRA-1"}`); rec.Code != http.StatusOK {
		t.Fatalf("reviewer place: got %d (%s)", rec.Code, rec.Body.String())
	}
	if f.placedEng != "eng-7" || f.placedBy != "analyst-1" || f.placedReason != "litigation JIRA-1" {
		t.Fatalf("place not scoped server-side: %+v", f)
	}
	// reviewer can release.
	if rec := incidentReq(mux, "reviewer", http.MethodDelete, "/api/v1/fleet/engagements/eng-7/legal-hold", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("reviewer release: got %d", rec.Code)
	}
	if f.released != "eng-7" {
		t.Fatalf("release not scoped to path: %q", f.released)
	}
	// readonly can list (PermView).
	if rec := incidentReq(mux, "readonly", http.MethodGet, "/api/v1/fleet/legal-holds", ""); rec.Code != http.StatusOK {
		t.Fatalf("readonly list: got %d", rec.Code)
	}
}

func TestLegalHoldRoutesAbsentWhenUnwired(t *testing.T) {
	rt := &Router{log: discardLog(), incidents: &fakeIncidentStore{}}
	if rec := incidentReq(rt.routes(), "reviewer", http.MethodGet, "/api/v1/fleet/legal-holds", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("unwired legal-hold route must 404, got %d", rec.Code)
	}
}
