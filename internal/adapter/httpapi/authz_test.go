package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
)

// TestAuthzDecorator verifies the single RBAC chokepoint: a principal whose role lacks the
// required permission gets 403 and the wrapped handler NEVER runs; a principal with the permission
// passes through; a machine role and an unauthenticated request are both denied (fail-closed).
func TestAuthzDecorator(t *testing.T) {
	rt := &Router{log: discardLog()}
	called := false
	h := rt.authz(userdom.PermOperate, func(w http.ResponseWriter, _ *http.Request) { called = true; w.WriteHeader(299) })

	call := func(role string, authed bool) (int, bool) {
		called = false
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		if authed {
			req = req.WithContext(ctxAs(role))
		}
		rec := httptest.NewRecorder()
		h(rec, req)
		return rec.Code, called
	}

	if code, ran := call("consultant", true); code != 299 || !ran {
		t.Errorf("consultant+operate: want passthrough(299) + handler run, got code=%d ran=%v", code, ran)
	}
	if code, ran := call("readonly", true); code != http.StatusForbidden || ran {
		t.Errorf("readonly+operate: want 403 + handler NOT run, got code=%d ran=%v", code, ran)
	}
	if code, ran := call("agent", true); code != http.StatusForbidden || ran {
		t.Errorf("machine(agent)+operate: want 403 + handler NOT run, got code=%d ran=%v", code, ran)
	}
	if code, ran := call("", false); code != http.StatusUnauthorized || ran {
		t.Errorf("unauthenticated: want 401 + handler NOT run, got code=%d ran=%v", code, ran)
	}
}
