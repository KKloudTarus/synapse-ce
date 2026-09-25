package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/legalholduc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/privacyexport"
)

// The legal-hold, subject-access-export and erasure surfaces each had a handler, a route, a store and a
// dashboard tab, and no composition root ever built them: the Data Governance tab could only report the
// feature switched off. The three consumers below are what the composition root now hands one
// legalholduc.Service to, so this pins that one service really does satisfy all three.
// holdChecker mirrors detectledger's unexported legal-hold guard, the third consumer.
type holdChecker interface {
	IsHeld(ctx context.Context, engagementID shared.ID) (bool, error)
}

var (
	_ legalHoldService         = (*legalholduc.Service)(nil)
	_ privacyexport.HoldReader = (*legalholduc.Service)(nil)
	_ holdChecker              = (*legalholduc.Service)(nil)
)

// TestLegalHoldRoundTripsThroughTheRealService drives place, list and release over the HTTP surface with
// the concrete service and its store rather than a fake, which is the combination the composition root
// now ships and the one nothing exercised before.
func TestLegalHoldRoundTripsThroughTheRealService(t *testing.T) {
	svc, err := legalholduc.NewService(memory.NewLegalHoldStore(), &fakeAudit{}, func() time.Time { return time.Unix(1700000000, 0).UTC() })
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	rt := &Router{log: discardLog(), incidents: &fakeIncidentStore{}, legalHolds: svc}
	mux := rt.routes()

	if rec := incidentReq(mux, "reviewer", http.MethodPut, "/api/v1/fleet/engagements/eng-7/legal-hold", `{"reason":"litigation JIRA-1"}`); rec.Code != http.StatusOK {
		t.Fatalf("place: got %d (%s)", rec.Code, rec.Body.String())
	}

	rec := incidentReq(mux, "reviewer", http.MethodGet, "/api/v1/fleet/legal-holds", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: got %d (%s)", rec.Code, rec.Body.String())
	}
	var listed struct {
		Holds []struct {
			EngagementID string
			Reason       string
			PlacedBy     string
		}
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listed.Holds) != 1 {
		t.Fatalf("active holds = %d, want the one just placed: %s", len(listed.Holds), rec.Body.String())
	}
	if listed.Holds[0].EngagementID != "eng-7" || listed.Holds[0].Reason != "litigation JIRA-1" || listed.Holds[0].PlacedBy != "analyst-1" {
		t.Fatalf("hold not scoped server-side: %+v", listed.Holds[0])
	}

	if rec := incidentReq(mux, "reviewer", http.MethodDelete, "/api/v1/fleet/engagements/eng-7/legal-hold", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("release: got %d (%s)", rec.Code, rec.Body.String())
	}
	rec = incidentReq(mux, "reviewer", http.MethodGet, "/api/v1/fleet/legal-holds", "")
	listed.Holds = nil
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode list after release: %v", err)
	}
	if len(listed.Holds) != 0 {
		t.Fatalf("a released hold must not stay active, got %+v", listed.Holds)
	}
}
