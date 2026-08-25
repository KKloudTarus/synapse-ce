package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// fakeIncidentStore is an in-test double satisfying BOTH incidentReader and incidentTriager, so the
// incident handler tests stay free of infrastructure/usecase imports. It records the last call so a
// test can assert the actor came from the authenticated principal (not the body) and that the honest
// limit+1 truncation probe reached the store.
type fakeIncidentStore struct {
	get    map[shared.ID]incident.Incident
	list   []incident.Incident
	getErr error
	triErr error

	lastAsset shared.ID
	lastLimit int
	lastActor string
	lastOwner string
	lastState incident.State
	lastDisp  incident.Disposition
}

func (f *fakeIncidentStore) Get(_ context.Context, id shared.ID) (incident.Incident, error) {
	if f.getErr != nil {
		return incident.Incident{}, f.getErr
	}
	inc, ok := f.get[id]
	if !ok {
		return incident.Incident{}, shared.ErrNotFound
	}
	return inc, nil
}

func (f *fakeIncidentStore) ListByAsset(_ context.Context, assetID shared.ID, limit int) ([]incident.Incident, error) {
	f.lastAsset = assetID
	f.lastLimit = limit
	// Emulate a real store capping at the requested limit.
	if limit < len(f.list) {
		return append([]incident.Incident(nil), f.list[:limit]...), nil
	}
	return append([]incident.Incident(nil), f.list...), nil
}

func (f *fakeIncidentStore) AssignOwner(_ context.Context, actor string, id shared.ID, owner string) (incident.Incident, error) {
	f.lastActor, f.lastOwner = actor, owner
	if f.triErr != nil {
		return incident.Incident{}, f.triErr
	}
	return incident.Incident{ID: id, OwnerID: owner}, nil
}

func (f *fakeIncidentStore) Comment(_ context.Context, actor string, id shared.ID, _ string) (incident.Incident, error) {
	f.lastActor = actor
	if f.triErr != nil {
		return incident.Incident{}, f.triErr
	}
	return incident.Incident{ID: id}, nil
}

func (f *fakeIncidentStore) ChangeStatus(_ context.Context, actor string, id shared.ID, to incident.State) (incident.Incident, error) {
	f.lastActor, f.lastState = actor, to
	if f.triErr != nil {
		return incident.Incident{}, f.triErr
	}
	return incident.Incident{ID: id, State: to}, nil
}

func (f *fakeIncidentStore) SetDisposition(_ context.Context, actor string, id shared.ID, d incident.Disposition) (incident.Incident, error) {
	f.lastActor, f.lastDisp = actor, d
	if f.triErr != nil {
		return incident.Incident{}, f.triErr
	}
	return incident.Incident{ID: id, Disposition: d}, nil
}

func newIncidentRouter(f *fakeIncidentStore) *http.ServeMux {
	rt := &Router{log: discardLog(), incidents: f, incidentTriage: f}
	return rt.routes()
}

// incidentReq drives the real route → authz → handler chain with an injected principal (role +
// tenant), exactly like the hostile harness, so the RBAC gates are the production ones.
func incidentReq(mux *http.ServeMux, role, method, path, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	r = r.WithContext(context.WithValue(r.Context(), principalKey, Principal{ID: "analyst-1", Role: role, TenantID: "tenant-a"}))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	return rec
}

func TestIncidentRoutesRBAC(t *testing.T) {
	f := &fakeIncidentStore{get: map[shared.ID]incident.Incident{"inc-1": {ID: "inc-1", State: incident.StateOpen}}}
	mux := newIncidentRouter(f)

	cases := []struct {
		name, role, method, path, body string
		want                           int
	}{
		{"readonly can read list", "readonly", http.MethodGet, "/api/v1/fleet/incidents", "", http.StatusOK},
		{"readonly can read one", "readonly", http.MethodGet, "/api/v1/fleet/incidents/inc-1", "", http.StatusOK},
		{"readonly cannot assign owner (needs triage)", "readonly", http.MethodPost, "/api/v1/fleet/incidents/inc-1/owner", `{"owner":"a"}`, http.StatusForbidden},
		{"readonly cannot set disposition (needs review)", "readonly", http.MethodPost, "/api/v1/fleet/incidents/inc-1/disposition", `{"disposition":"true_positive"}`, http.StatusForbidden},
		{"consultant can assign owner", "consultant", http.MethodPost, "/api/v1/fleet/incidents/inc-1/owner", `{"owner":"a"}`, http.StatusOK},
		{"consultant can change status", "consultant", http.MethodPost, "/api/v1/fleet/incidents/inc-1/status", `{"to":"triaged"}`, http.StatusOK},
		{"consultant CANNOT set disposition (no review)", "consultant", http.MethodPost, "/api/v1/fleet/incidents/inc-1/disposition", `{"disposition":"true_positive"}`, http.StatusForbidden},
		{"reviewer can set disposition", "reviewer", http.MethodPost, "/api/v1/fleet/incidents/inc-1/disposition", `{"disposition":"true_positive"}`, http.StatusOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := incidentReq(mux, c.role, c.method, c.path, c.body)
			if rec.Code != c.want {
				t.Fatalf("%s %s as %s: got %d, want %d (%s)", c.method, c.path, c.role, rec.Code, c.want, rec.Body.String())
			}
		})
	}
}

// TestIncidentTriageActorIsPrincipal proves the actor is the authenticated principal, never a body
// field — the security-critical property of an attributable triage mutation.
func TestIncidentTriageActorIsPrincipal(t *testing.T) {
	f := &fakeIncidentStore{}
	mux := newIncidentRouter(f)
	// The body tries to spoof a different actor; it must be ignored.
	rec := incidentReq(mux, "consultant", http.MethodPost, "/api/v1/fleet/incidents/inc-9/owner", `{"owner":"bob","actor":"attacker"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("assign owner: got %d (%s)", rec.Code, rec.Body.String())
	}
	if f.lastActor != "analyst-1" {
		t.Fatalf("actor must be the authenticated principal, got %q", f.lastActor)
	}
	if f.lastOwner != "bob" {
		t.Fatalf("owner must come from the body, got %q", f.lastOwner)
	}
}

// TestIncidentListTruncationIsHonest checks the limit+1 probe: a full page reports Truncated so a
// client (and any state filter run over it) knows more incidents exist beyond the page.
func TestIncidentListTruncationIsHonest(t *testing.T) {
	f := &fakeIncidentStore{list: []incident.Incident{
		{ID: "a", State: incident.StateOpen},
		{ID: "b", State: incident.StateOpen},
		{ID: "c", State: incident.StateTriaged},
	}}
	mux := newIncidentRouter(f)
	rec := incidentReq(mux, "readonly", http.MethodGet, "/api/v1/fleet/incidents?limit=2", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: got %d (%s)", rec.Code, rec.Body.String())
	}
	if f.lastLimit != 3 {
		t.Fatalf("handler must probe limit+1 for honest truncation, store saw limit=%d", f.lastLimit)
	}
	var resp incidentListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Incidents) != 2 {
		t.Fatalf("page must be trimmed to the limit, got %d", len(resp.Incidents))
	}
	if !resp.Truncated {
		t.Fatal("a full page must report Truncated=true")
	}
}

func TestIncidentListStateFilter(t *testing.T) {
	f := &fakeIncidentStore{list: []incident.Incident{
		{ID: "a", State: incident.StateOpen},
		{ID: "b", State: incident.StateTriaged},
		{ID: "c", State: incident.StateOpen},
	}}
	mux := newIncidentRouter(f)
	rec := incidentReq(mux, "readonly", http.MethodGet, "/api/v1/fleet/incidents?state=open", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: got %d (%s)", rec.Code, rec.Body.String())
	}
	var resp incidentListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Incidents) != 2 {
		t.Fatalf("state=open must filter to the two open incidents, got %d", len(resp.Incidents))
	}
	// An unknown state is rejected, not silently ignored.
	if bad := incidentReq(mux, "readonly", http.MethodGet, "/api/v1/fleet/incidents?state=bogus", ""); bad.Code != http.StatusBadRequest {
		t.Fatalf("unknown state must be 400, got %d", bad.Code)
	}
}

func TestIncidentReadAndTriageErrorMapping(t *testing.T) {
	// Missing incident → 404.
	f := &fakeIncidentStore{getErr: shared.ErrNotFound}
	mux := newIncidentRouter(f)
	if rec := incidentReq(mux, "readonly", http.MethodGet, "/api/v1/fleet/incidents/nope", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("missing incident must be 404, got %d", rec.Code)
	}
	// Invalid limit → 400.
	if rec := incidentReq(mux, "readonly", http.MethodGet, "/api/v1/fleet/incidents?limit=-1", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid limit must be 400, got %d", rec.Code)
	}
	// Bad body → 400.
	if rec := incidentReq(mux, "consultant", http.MethodPost, "/api/v1/fleet/incidents/inc-1/owner", `{`); rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed body must be 400, got %d", rec.Code)
	}
	// A usecase validation error (e.g. an illegal transition) maps to 400.
	f2 := &fakeIncidentStore{triErr: shared.ErrValidation}
	mux2 := newIncidentRouter(f2)
	if rec := incidentReq(mux2, "consultant", http.MethodPost, "/api/v1/fleet/incidents/inc-1/status", `{"to":"resolved"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("usecase validation error must be 400, got %d", rec.Code)
	}
	// A conflict (optimistic-concurrency) maps to 409.
	f3 := &fakeIncidentStore{triErr: shared.ErrConflict}
	mux3 := newIncidentRouter(f3)
	if rec := incidentReq(mux3, "consultant", http.MethodPost, "/api/v1/fleet/incidents/inc-1/status", `{"to":"triaged"}`); rec.Code != http.StatusConflict {
		t.Fatalf("optimistic-concurrency conflict must be 409, got %d", rec.Code)
	}
}
