package httpapi

import (
	"context"
	"net/http"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/privacyexport"
)

type fakeExporter struct {
	gotActor string
	gotEng   shared.ID
}

func (f *fakeExporter) Export(_ context.Context, actor string, eng shared.ID) (privacyexport.Bundle, error) {
	f.gotActor, f.gotEng = actor, eng
	return privacyexport.Bundle{EngagementID: eng, Count: 3}, nil
}

func TestPrivacyExportRBACAndScoping(t *testing.T) {
	f := &fakeExporter{}
	rt := &Router{log: discardLog(), incidents: &fakeIncidentStore{}, privacyExport: f}
	mux := rt.routes()

	// consultant cannot export (governance read → PermReview).
	if rec := incidentReq(mux, "consultant", http.MethodGet, "/api/v1/fleet/engagements/eng-9/privacy-export", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("consultant export must be forbidden, got %d", rec.Code)
	}
	if rec := incidentReq(mux, "reviewer", http.MethodGet, "/api/v1/fleet/engagements/eng-9/privacy-export", ""); rec.Code != http.StatusOK {
		t.Fatalf("reviewer export: got %d (%s)", rec.Code, rec.Body.String())
	}
	if f.gotActor != "analyst-1" || f.gotEng != "eng-9" {
		t.Fatalf("actor/engagement not threaded: actor=%q eng=%q", f.gotActor, f.gotEng)
	}
}

func TestPrivacyExportAbsentWhenUnwired(t *testing.T) {
	rt := &Router{log: discardLog(), incidents: &fakeIncidentStore{}}
	if rec := incidentReq(rt.routes(), "reviewer", http.MethodGet, "/api/v1/fleet/engagements/e1/privacy-export", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("unwired export route must 404, got %d", rec.Code)
	}
}
