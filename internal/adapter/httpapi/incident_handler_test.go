package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type incidentHTTPFake struct {
	lastAction      string
	lastID          shared.ID
	lastActor       string
	lastValue       string
	lastAsset       shared.ID
	lastLimit       int
	mutationInvoked bool
}

func (f *incidentHTTPFake) item() incident.Incident {
	return incident.Incident{
		ID: "inc-1", AssetID: "asset-1", Title: "Suspicious process", Severity: shared.SeverityHigh,
		State: incident.StateNew, Disposition: incident.DispositionUnknown, Revision: 2,
		CreatedAt: time.Unix(100, 0).UTC(), UpdatedAt: time.Unix(101, 0).UTC(),
	}
}

func (f *incidentHTTPFake) Get(_ context.Context, id shared.ID) (incident.Incident, error) {
	f.lastID = id
	return f.item(), nil
}

func (f *incidentHTTPFake) ListByAsset(_ context.Context, asset shared.ID, limit int) ([]incident.Incident, error) {
	f.lastAsset, f.lastLimit = asset, limit
	return []incident.Incident{f.item()}, nil
}

func (f *incidentHTTPFake) History(_ context.Context, id shared.ID) ([]incident.IncidentEvent, error) {
	f.lastID = id
	return []incident.IncidentEvent{{IncidentID: id, Kind: incident.EventCreated, At: time.Unix(100, 0).UTC(), Actor: "correlator", AssetID: "asset-1"}}, nil
}

func (f *incidentHTTPFake) mutated(action string, id shared.ID, actor, value string) (incident.Incident, error) {
	f.lastAction, f.lastID, f.lastActor, f.lastValue = action, id, actor, value
	f.mutationInvoked = true
	item := f.item()
	item.Revision++
	return item, nil
}

func (f *incidentHTTPFake) AssignOwner(_ context.Context, actor string, id shared.ID, owner string) (incident.Incident, error) {
	return f.mutated("owner", id, actor, owner)
}

func (f *incidentHTTPFake) Comment(_ context.Context, actor string, id shared.ID, comment string) (incident.Incident, error) {
	return f.mutated("comment", id, actor, comment)
}

func (f *incidentHTTPFake) ChangeStatus(_ context.Context, actor string, id shared.ID, state incident.State) (incident.Incident, error) {
	return f.mutated("state", id, actor, string(state))
}

func (f *incidentHTTPFake) SetDisposition(_ context.Context, actor string, id shared.ID, disposition incident.Disposition) (incident.Incident, error) {
	return f.mutated("disposition", id, actor, string(disposition))
}

func TestIncidentReadHandlers(t *testing.T) {
	fake := &incidentHTTPFake{}
	rt := &Router{log: discardLog(), incidents: fake}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents?asset_id=asset-1&limit=25", nil)
	rec := httptest.NewRecorder()
	rt.listIncidents(rec, req)
	if rec.Code != http.StatusOK || fake.lastAsset != "asset-1" || fake.lastLimit != 25 {
		t.Fatalf("list: status=%d asset=%s limit=%d body=%s", rec.Code, fake.lastAsset, fake.lastLimit, rec.Body.String())
	}
	var listed struct {
		Incidents []incidentResponse `json:"incidents"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil || len(listed.Incidents) != 1 || listed.Incidents[0].ID != "inc-1" {
		t.Fatalf("list response: %+v err=%v", listed, err)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/incidents/inc-1/events", nil)
	req.SetPathValue("id", "inc-1")
	rec = httptest.NewRecorder()
	rt.incidentHistory(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"revision":1`) || !strings.Contains(rec.Body.String(), `"kind":"created"`) {
		t.Fatalf("history: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestIncidentMutationHandlersMapAuthenticatedActor(t *testing.T) {
	cases := []struct {
		name, method, path, body, action, value string
		handler                                 func(*Router, http.ResponseWriter, *http.Request)
	}{
		{"owner", http.MethodPut, "/api/v1/incidents/inc-1/owner", `{"owner":"bob","expected_revision":2}`, "owner", "bob", (*Router).changeIncidentOwner},
		{"comment", http.MethodPost, "/api/v1/incidents/inc-1/comments", `{"comment":"investigating","expected_revision":2}`, "comment", "investigating", (*Router).addIncidentComment},
		{"state", http.MethodPost, "/api/v1/incidents/inc-1/state", `{"state":"investigating","expected_revision":2}`, "state", "investigating", (*Router).changeIncidentState},
		{"disposition", http.MethodPost, "/api/v1/incidents/inc-1/disposition", `{"disposition":"true_positive","expected_revision":2}`, "disposition", "true_positive", (*Router).setIncidentDisposition},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &incidentHTTPFake{}
			rt := &Router{log: discardLog(), incidents: fake, incidentTriage: fake}
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.SetPathValue("id", "inc-1")
			req = withPrincipal(req, "analyst-1", "reviewer")
			rec := httptest.NewRecorder()
			tc.handler(rt, rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			if fake.lastAction != tc.action || fake.lastID != "inc-1" || fake.lastActor != "analyst-1" || fake.lastValue != tc.value {
				t.Fatalf("mapped mutation: %+v", fake)
			}
		})
	}
}

func TestIncidentMutationRejectsUnknownBodyField(t *testing.T) {
	fake := &incidentHTTPFake{}
	rt := &Router{log: discardLog(), incidents: fake, incidentTriage: fake}
	req := httptest.NewRequest(http.MethodPut, "/api/v1/incidents/inc-1/owner", strings.NewReader(`{"owner":"bob","expected_revision":2,"event_kind":"response_verified"}`))
	req.SetPathValue("id", "inc-1")
	rec := httptest.NewRecorder()
	rt.changeIncidentOwner(rec, req)
	if rec.Code != http.StatusBadRequest || fake.mutationInvoked {
		t.Fatalf("smuggled event field: status=%d invoked=%v body=%s", rec.Code, fake.mutationInvoked, rec.Body.String())
	}
}

func TestIncidentRoutesEnforceReviewPermission(t *testing.T) {
	fake := &incidentHTTPFake{}
	rt := &Router{log: discardLog()}
	rt.SetIncidents(fake, fake)
	mux := rt.routes()

	send := func(role, method, path, body string) int {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req = withPrincipal(req, role+"-user", role)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := send("readonly", http.MethodGet, "/api/v1/incidents", ""); code != http.StatusOK {
		t.Fatalf("readonly list status=%d, want 200", code)
	}
	for _, role := range []string{"readonly", "consultant", "agent", "mcp"} {
		fake.mutationInvoked = false
		if code := send(role, http.MethodPost, "/api/v1/incidents/inc-1/disposition", `{"disposition":"true_positive","expected_revision":2}`); code != http.StatusForbidden {
			t.Fatalf("role %s mutation status=%d, want 403", role, code)
		}
		if fake.mutationInvoked {
			t.Fatalf("role %s reached incident mutation", role)
		}
	}
	if code := send("reviewer", http.MethodPost, "/api/v1/incidents/inc-1/disposition", `{"disposition":"true_positive","expected_revision":2}`); code != http.StatusOK {
		t.Fatalf("reviewer mutation status=%d, want 200", code)
	}
}

func TestIncidentMutationRejectsStaleRevision(t *testing.T) {
	fake := &incidentHTTPFake{}
	rt := &Router{log: discardLog(), incidents: fake, incidentTriage: fake}
	req := httptest.NewRequest(http.MethodPut, "/api/v1/incidents/inc-1/owner", strings.NewReader(`{"owner":"bob","expected_revision":1}`))
	req.SetPathValue("id", "inc-1")
	rec := httptest.NewRecorder()
	rt.changeIncidentOwner(rec, req)
	if rec.Code != http.StatusConflict || fake.mutationInvoked {
		t.Fatalf("stale mutation: status=%d invoked=%v body=%s", rec.Code, fake.mutationInvoked, rec.Body.String())
	}
}

func TestIncidentListRejectsUnboundedOrUnknownQueries(t *testing.T) {
	for _, target := range []string{"/api/v1/incidents?limit=101", "/api/v1/incidents?limit=nope", "/api/v1/incidents?tenant=other"} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		if _, _, err := incidentListParams(req); err == nil {
			t.Fatalf("query %s must fail", target)
		}
	}
}
