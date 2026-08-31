package httpapi

import (
	"context"
	"net/http"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type fakePurger struct {
	gotActor  string
	gotEng    shared.ID
	gotReason string
}

func (f *fakePurger) Purge(_ context.Context, eng shared.ID, actor, reason string) (int, error) {
	f.gotActor, f.gotEng, f.gotReason = actor, eng, reason
	return 2, nil
}

func TestDataPurgeRBACAndScoping(t *testing.T) {
	f := &fakePurger{}
	rt := &Router{log: discardLog(), incidents: &fakeIncidentStore{}, dataPurge: f}
	mux := rt.routes()

	// consultant cannot purge (destructive governance decision → PermReview).
	if rec := incidentReq(mux, "consultant", http.MethodDelete, "/api/v1/fleet/engagements/eng-9/detection-data", `{"reason":"erasure"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("consultant purge must be forbidden, got %d", rec.Code)
	}
	rec := incidentReq(mux, "reviewer", http.MethodDelete, "/api/v1/fleet/engagements/eng-9/detection-data", `{"reason":"subject erasure"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("reviewer purge: got %d (%s)", rec.Code, rec.Body.String())
	}
	if f.gotActor != "analyst-1" || f.gotEng != "eng-9" || f.gotReason != "subject erasure" {
		t.Fatalf("actor/engagement/reason not threaded: actor=%q eng=%q reason=%q", f.gotActor, f.gotEng, f.gotReason)
	}
}

func TestDataPurgeAbsentWhenUnwired(t *testing.T) {
	rt := &Router{log: discardLog(), incidents: &fakeIncidentStore{}}
	if rec := incidentReq(rt.routes(), "reviewer", http.MethodDelete, "/api/v1/fleet/engagements/e1/detection-data", `{"reason":"x"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("unwired purge route must 404, got %d", rec.Code)
	}
}
