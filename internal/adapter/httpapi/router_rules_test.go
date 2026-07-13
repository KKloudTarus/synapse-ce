package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/aup"
)

func TestRouter_RulesAPI_FullMiddleware(t *testing.T) {
	// 1. Setup Auth
	auth := NewAuthenticator(func(_ context.Context, token string) (Principal, bool) {
		if token == "secret" {
			return Principal{ID: "u1", Name: "Tester", Role: "readonly", TenantID: "tenantA"}, true
		}
		if token == "agent-secret" {
			return Principal{ID: "m1", Name: "Machine", Role: "agent", TenantID: "tenantA"}, true
		}
		return Principal{}, false
	})

	// 2. Setup AUP
	aupStore := newFakeAUPStore()
	aupSvc := newTestAUP(aupStore, &fakeAudit{})

	// 3. Setup Router
	rt := &Router{
		log:  discardLog(),
		auth: auth,
		aup:  aupSvc,
	}
	rt.SetRules(&fakeRulesService{})
	h := rt.Handler()

	callList := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	callGet := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rules/some-key", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	// a. unauthenticated request -> 401
	if w := callList(""); w.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated list: expected 401, got %d", w.Code)
	}
	if w := callGet(""); w.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated get: expected 401, got %d", w.Code)
	}

	// b. authenticated viewer, AUP not accepted -> 403
	if w := callList("secret"); w.Code != http.StatusForbidden {
		t.Errorf("unaccepted AUP list: expected 403, got %d", w.Code)
	}

	// c. authenticated viewer, AUP accepted -> 200
	aupStore.accepted["1.0"] = aup.Acceptance{Version: "1.0"}
	if w := callList("secret"); w.Code != http.StatusOK {
		t.Errorf("accepted AUP list: expected 200, got %d", w.Code)
	}
	if w := callGet("secret"); w.Code != http.StatusOK {
		t.Errorf("accepted AUP get: expected 200, got %d", w.Code)
	}

	// d. authenticated machine role (agent) -> 403 (PermView denied by authz)
	if w := callList("agent-secret"); w.Code != http.StatusForbidden {
		t.Errorf("agent list: expected 403, got %d", w.Code)
	}
	if w := callGet("agent-secret"); w.Code != http.StatusForbidden {
		t.Errorf("agent get: expected 403, got %d", w.Code)
	}
}

func TestRouter_RulesRoutePresence(t *testing.T) {
	rt := &Router{log: discardLog()}
	// SetRules NOT called

	callList := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil)
		w := httptest.NewRecorder()
		rt.routes().ServeHTTP(w, req)
		return w
	}

	callGet := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rules/some-key", nil)
		w := httptest.NewRecorder()
		rt.routes().ServeHTTP(w, req)
		return w
	}

	if callList().Code != http.StatusNotFound {
		t.Errorf("expected 404 when rules not set, got %d", callList().Code)
	}
	if callGet().Code != http.StatusNotFound {
		t.Errorf("expected 404 when rules not set, got %d", callGet().Code)
	}

	// SetRules called
	rt.SetRules(&fakeRulesService{})

	if callList().Code == http.StatusNotFound {
		t.Errorf("expected route to be present")
	}
	if callGet().Code == http.StatusNotFound {
		t.Errorf("expected route to be present")
	}
}
