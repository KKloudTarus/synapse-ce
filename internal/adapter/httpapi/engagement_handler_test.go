package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	enguc "github.com/KKloudTarus/synapse-ce/internal/usecase/engagement"
)

// engRepoFake is an in-test engagement repository – adapter tests stay free of
// infrastructure imports (see the note in aup_test.go).
type engRepoFake struct {
	data map[shared.ID]*engdom.Engagement
}

func newEngRepoFake() *engRepoFake { return &engRepoFake{data: map[shared.ID]*engdom.Engagement{}} }

func (r *engRepoFake) Create(_ context.Context, e *engdom.Engagement) error {
	r.data[e.ID] = e
	return nil
}
func (r *engRepoFake) Update(_ context.Context, e *engdom.Engagement) error {
	if _, ok := r.data[e.ID]; !ok {
		return shared.ErrNotFound
	}
	r.data[e.ID] = e
	return nil
}
func (r *engRepoFake) Delete(_ context.Context, id shared.ID) error {
	delete(r.data, id)
	return nil
}
func (r *engRepoFake) GetByID(_ context.Context, id shared.ID) (*engdom.Engagement, error) {
	e, ok := r.data[id]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return e, nil
}
func (r *engRepoFake) GetByIDInTenant(_ context.Context, tenantID, id shared.ID) (*engdom.Engagement, error) {
	e, ok := r.data[id]
	if !ok {
		return nil, shared.ErrNotFound
	}
	if !tenantID.IsZero() && e.TenantID != tenantID {
		return nil, shared.ErrNotFound // cross-tenant – do not reveal existence
	}
	return e, nil
}
func (r *engRepoFake) List(context.Context, shared.ID) ([]*engdom.Engagement, error) { return nil, nil }

type engIDs struct{}

func (engIDs) NewID() shared.ID { return shared.ID("eng-1") }

// newEngRouter wires a Router with only the engagement service (the E1 handlers
// touch rt.eng + rt.log), seeded with one in-scope engagement "eng-1".
func newEngRouter(t *testing.T) (*Router, *engRepoFake, *fakeAudit) {
	t.Helper()
	repo := newEngRepoFake()
	audit := &fakeAudit{}
	svc := enguc.NewService(repo, fixedClock{t: time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)}, engIDs{}, audit)
	if _, err := svc.Create(context.Background(), enguc.CreateInput{
		Name:    "Acme",
		Client:  "Acme",
		InScope: []engdom.Target{{Kind: engdom.TargetDomain, Value: "app.acme.io"}},
	}); err != nil {
		t.Fatalf("seed engagement: %v", err)
	}
	return &Router{log: discardLog(), eng: svc}, repo, audit
}

// engCall invokes a handler against engagement "eng-1" with a JSON body.
func engCall(h http.HandlerFunc, method, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/api/v1/engagements/eng-1", strings.NewReader(body))
	req.SetPathValue("id", "eng-1")
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func auditHas(a *fakeAudit, action string) bool {
	for _, e := range a.entries {
		if e.Action == action {
			return true
		}
	}
	return false
}

// TestWithEngTenantIsolatesChildRoutes proves the single chokepoint that tenant-isolates every
// /engagements/{id}/… child route (PR5c): a cross-tenant caller gets 404 and the wrapped child
// handler NEVER runs (so no child resource – findings, evidence, recon, agent data – is read or
// written cross-tenant, and existence is not revealed); same-tenant and zero-tenant callers pass
// through. This is what makes the "every child read/mutation is tenant-scoped" claim hold without
// trusting each of ~30 handlers to remember the check.
func TestWithEngTenantIsolatesChildRoutes(t *testing.T) {
	repo := newEngRepoFake()
	svc := enguc.NewService(repo, fixedClock{t: time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)}, engIDs{}, &fakeAudit{})
	if _, err := svc.Create(context.Background(), enguc.CreateInput{TenantID: "tenant-A", Name: "Acme", Client: "Acme"}); err != nil {
		t.Fatalf("seed engagement: %v", err)
	}
	rt := &Router{log: discardLog(), eng: svc}

	called := false
	stub := func(w http.ResponseWriter, _ *http.Request) { called = true; w.WriteHeader(299) }
	wrapped := rt.withEngTenant(stub)

	call := func(id, tenant string) (int, bool) {
		called = false
		req := httptest.NewRequest(http.MethodGet, "/api/v1/engagements/"+id+"/findings", nil)
		req.SetPathValue("id", id)
		req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "u", TenantID: tenant}))
		rec := httptest.NewRecorder()
		wrapped(rec, req)
		return rec.Code, called
	}

	// Cross-tenant: 404, and the child handler must NOT run.
	if code, ran := call("eng-1", "tenant-B"); code != http.StatusNotFound || ran {
		t.Errorf("cross-tenant: want 404 + child NOT called, got code=%d called=%v", code, ran)
	}
	// Same tenant: pass through to the child handler.
	if code, ran := call("eng-1", "tenant-A"); code != 299 || !ran {
		t.Errorf("same-tenant: want passthrough (299) + child called, got code=%d called=%v", code, ran)
	}
	// Zero tenant (single-tenant / default-tenant admin): sees any engagement.
	if code, ran := call("eng-1", ""); code != 299 || !ran {
		t.Errorf("zero-tenant: want passthrough (299) + child called, got code=%d called=%v", code, ran)
	}
	// Unknown engagement: 404, child never runs.
	if code, ran := call("nope", "tenant-A"); code != http.StatusNotFound || ran {
		t.Errorf("unknown engagement: want 404 + child NOT called, got code=%d called=%v", code, ran)
	}
}

func TestGetEngagementHandler(t *testing.T) {
	rt, _, _ := newEngRouter(t)
	rec := engCall(rt.getEngagement, http.MethodGet, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get: code=%d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["ID"] != "eng-1" {
		t.Errorf("id = %v, want eng-1", body["ID"])
	}

	// Unknown id -> 404.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/engagements/nope", nil)
	req.SetPathValue("id", "nope")
	rec = httptest.NewRecorder()
	rt.getEngagement(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown id: want 404, got %d", rec.Code)
	}
}

func TestUpdateScopeHandler(t *testing.T) {
	rt, repo, audit := newEngRouter(t)
	rec := engCall(rt.updateScope, http.MethodPut, `{"in_scope":[{"kind":"cidr","value":"10.0.0.0/24"}],"out_of_scope":[]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("scope: code=%d body=%s", rec.Code, rec.Body.String())
	}
	got, _ := repo.GetByID(context.Background(), shared.ID("eng-1"))
	if len(got.Scope.InScope) != 1 || got.Scope.InScope[0].Kind != engdom.TargetCIDR {
		t.Errorf("scope not persisted: %+v", got.Scope)
	}
	if !auditHas(audit, "engagement.scope.update") {
		t.Error("scope update not audited")
	}

	if rec := engCall(rt.updateScope, http.MethodPut, `{"in_scope":[{"kind":"bogus","value":"x"}]}`); rec.Code != http.StatusBadRequest {
		t.Errorf("invalid kind: want 400, got %d", rec.Code)
	}
	if rec := engCall(rt.updateScope, http.MethodPut, `{`); rec.Code != http.StatusBadRequest {
		t.Errorf("invalid json: want 400, got %d", rec.Code)
	}
}

func TestTransitionHandler(t *testing.T) {
	rt, _, audit := newEngRouter(t)
	if rec := engCall(rt.transitionEngagement, http.MethodPatch, `{"status":"active"}`); rec.Code != http.StatusOK {
		t.Fatalf("activate: code=%d body=%s", rec.Code, rec.Body.String())
	}
	if !auditHas(audit, "engagement.transition") {
		t.Error("transition not audited")
	}
	// active -> draft is not a legal transition.
	if rec := engCall(rt.transitionEngagement, http.MethodPatch, `{"status":"draft"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("illegal transition: want 400, got %d", rec.Code)
	}
}

func TestSetWindowHandler(t *testing.T) {
	rt, _, _ := newEngRouter(t)
	if rec := engCall(rt.setAuthorizationWindow, http.MethodPut, `{"authorized_from":"2026-06-22T00:00:00Z","authorized_to":"2026-06-21T00:00:00Z"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("from after to: want 400, got %d", rec.Code)
	}
	if rec := engCall(rt.setAuthorizationWindow, http.MethodPut, `{"authorized_from":"not-a-time"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("bad timestamp: want 400, got %d", rec.Code)
	}
	if rec := engCall(rt.setAuthorizationWindow, http.MethodPut, `{"authorized_from":"2026-06-21T00:00:00Z","authorized_to":"2026-06-22T00:00:00Z","timezone":"UTC"}`); rec.Code != http.StatusOK {
		t.Errorf("valid window: want 200, got %d", rec.Code)
	}
}

func TestSetRoEHandler(t *testing.T) {
	rt, repo, audit := newEngRouter(t)
	rec := engCall(rt.setRoE, http.MethodPut, `{"allowed_tool_classes":["sca"],"blackouts":[{"from":"2026-06-21T00:00:00Z","to":"2026-06-21T06:00:00Z"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("roe: code=%d body=%s", rec.Code, rec.Body.String())
	}
	got, _ := repo.GetByID(context.Background(), shared.ID("eng-1"))
	if len(got.RoE.AllowedToolClasses) != 1 || len(got.RoE.Blackouts) != 1 {
		t.Errorf("roe not persisted: %+v", got.RoE)
	}
	if !auditHas(audit, "engagement.roe.update") {
		t.Error("roe update not audited")
	}
	if rec := engCall(rt.setRoE, http.MethodPut, `{"blackouts":[{"from":"nope","to":"nope"}]}`); rec.Code != http.StatusBadRequest {
		t.Errorf("bad blackout timestamp: want 400, got %d", rec.Code)
	}
}
