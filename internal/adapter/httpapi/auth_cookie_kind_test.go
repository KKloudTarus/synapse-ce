package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
)

type cookiePrincipalResolver struct{ kind authz.CredentialKind }

func (s cookiePrincipalResolver) Authenticate(context.Context, string, string, bool) (Principal, error) {
	return Principal{ID: "recovery-actor", Role: "admin", TenantID: "tenant-a", Credential: s.kind}, nil
}

func TestCookieAuthenticationPreservesRecoveryRestriction(t *testing.T) {
	for _, tc := range []struct {
		name        string
		kind        authz.CredentialKind
		wantKind    authz.CredentialKind
		wantAllowed bool
	}{
		{"legacy session", "", authz.KindBrowserSession, true},
		{"explicit ordinary session", authz.KindBrowserSession, authz.KindBrowserSession, true},
		{"recovery session", authz.KindBreakGlass, authz.KindBreakGlass, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := NewAuthenticator(nil)
			a.SetSessionResolver(cookiePrincipalResolver{kind: tc.kind})
			called := false
			h := a.Middleware(nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				p, ok := principalObj(r.Context())
				if !ok || p.Credential != tc.wantKind {
					t.Errorf("credential kind = %q, want %q", p.Credential, tc.wantKind)
				}
				for _, permission := range []user.Permission{user.PermAdminister, user.PermManageIntegrations} {
					if d := decideRequest(r, authz.Action{Permission: permission}); d.Allowed != tc.wantAllowed {
						t.Errorf("permission %s allowed = %v, want %v", permission, d.Allowed, tc.wantAllowed)
					}
				}
				if d := decideRequest(r, authz.Action{Recovery: authz.RecoveryLogout}); !d.Allowed {
					t.Error("own logout denied")
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			r := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
			r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "test-only-opaque-cookie"})
			h.ServeHTTP(httptest.NewRecorder(), r)
			if !called {
				t.Fatal("session resolver did not reach handler")
			}
		})
	}
}

func TestCookieAuthenticationRejectsNonSessionKinds(t *testing.T) {
	for _, kind := range []authz.CredentialKind{authz.KindBootstrap, authz.KindAPIKey, "future-kind"} {
		t.Run(string(kind), func(t *testing.T) {
			a := NewAuthenticator(nil)
			a.SetSessionResolver(cookiePrincipalResolver{kind: kind})
			h := a.Middleware(nil, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("invalid cookie kind authenticated") }))
			r := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
			r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "test-only-opaque-cookie"})
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", w.Code)
			}
		})
	}
}
