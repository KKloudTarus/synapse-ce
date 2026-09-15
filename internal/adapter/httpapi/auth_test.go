package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestTenantPropagatesThroughContext covers the tenant foundation: the tenant the resolver
// puts on the HumanPrincipal flows through the auth middleware into the request context, readable via
// TenantFrom – the plumbing that lets writes stamp + reads scope by tenant.
func TestTenantPropagatesThroughContext(t *testing.T) {
	auth := NewAuthenticator(func(_ context.Context, _ string) (HumanPrincipal, bool) {
		return HumanPrincipal{ID: "u1", Name: "T", Role: "member", TenantID: "acme"}, true
	})
	var gotTenant, gotActor string
	var gotPrincipal HumanPrincipal
	var gotPrincipalOK bool
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotTenant = TenantFrom(r.Context())
		gotActor = PrincipalFrom(r.Context())
		gotPrincipal, gotPrincipalOK = HumanPrincipalFrom(r.Context())
	})
	h := auth.Middleware(map[string]bool{}, next)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/engagements", nil)
	req.Header.Set("Authorization", "Bearer x")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if gotTenant != "acme" {
		t.Errorf("TenantFrom = %q, want acme", gotTenant)
	}
	if gotActor != "u1" {
		t.Errorf("PrincipalFrom = %q, want u1", gotActor)
	}
	if !gotPrincipalOK || gotPrincipal.ID != "u1" || gotPrincipal.TenantID != "acme" {
		t.Fatalf("HumanPrincipalFrom = %+v, %v; want authenticated u1/acme", gotPrincipal, gotPrincipalOK)
	}
}

func TestMissingPrincipalDoesNotImplyBootstrapOperator(t *testing.T) {
	ctx := context.Background()
	if p, ok := HumanPrincipalFrom(ctx); ok || p.ID != "" {
		t.Fatalf("HumanPrincipalFrom without authentication = %+v, %v; want zero,false", p, ok)
	}
	if actor := PrincipalFrom(ctx); actor != "" {
		t.Errorf("missing principal actor = %q, want empty; absence must not become %q", actor, PrincipalOperator)
	}
	if tid := TenantFrom(ctx); tid != "" {
		t.Errorf("missing principal tenant = %q, want empty", tid)
	}
	if IsPlatformAdmin(ctx) {
		t.Fatal("missing principal must never authorize as the platform operator")
	}
}

func TestBootstrapPrincipalIsExplicitlyAuthenticated(t *testing.T) {
	auth := NewAuthenticator(func(_ context.Context, token string) (HumanPrincipal, bool) {
		if token != "bootstrap-secret" {
			return HumanPrincipal{}, false
		}
		return HumanPrincipal{ID: PrincipalOperator, Name: "Operator", Role: "admin"}, true
	})
	var got HumanPrincipal
	var gotOK, gotPlatformAdmin bool
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, gotOK = HumanPrincipalFrom(r.Context())
		gotPlatformAdmin = IsPlatformAdmin(r.Context())
	})
	h := auth.Middleware(map[string]bool{}, next)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/engagements", nil)
	req.Header.Set("Authorization", "Bearer bootstrap-secret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("bootstrap authentication status = %d, want 200", rec.Code)
	}
	if !gotOK || got.ID != PrincipalOperator {
		t.Fatalf("bootstrap principal = %+v, %v; want explicit operator", got, gotOK)
	}
	if !gotPlatformAdmin {
		t.Fatal("explicit authenticated bootstrap principal must retain platform-admin authority")
	}
}

func TestAuthenticatorRejectsEmptyResolvedPrincipal(t *testing.T) {
	auth := NewAuthenticator(func(_ context.Context, _ string) (HumanPrincipal, bool) {
		// A buggy resolver must not be able to claim success without binding an identity.
		return HumanPrincipal{}, true
	})
	called := false
	h := auth.Middleware(map[string]bool{}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/engagements", nil)
	req.Header.Set("Authorization", "Bearer malformed")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if called {
		t.Fatal("middleware called protected handler with an empty resolved principal")
	}
}

func TestTenantFromDefaultsEmpty(t *testing.T) {
	if tid := TenantFrom(context.Background()); tid != "" {
		t.Errorf("no principal → tenant must be '', got %q", tid)
	}
}

func TestAuthenticatorMiddleware(t *testing.T) {
	// Resolver accepts only "secret", mapping it to a member principal.
	auth := NewAuthenticator(func(_ context.Context, token string) (HumanPrincipal, bool) {
		if token == "secret" {
			return HumanPrincipal{ID: "u1", Name: "Tester", Role: "member"}, true
		}
		return HumanPrincipal{}, false
	})
	public := map[string]bool{"/healthz": true, "/readyz": true}

	var nextCalled bool
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})
	h := auth.Middleware(public, next)

	tests := []struct {
		name     string
		path     string
		header   string
		wantCode int
		wantNext bool
	}{
		{"public needs no token", "/healthz", "", http.StatusOK, true},
		{"readiness needs no token", "/readyz", "", http.StatusOK, true},
		{"protected missing token", "/api/v1/engagements", "", http.StatusUnauthorized, false},
		{"protected wrong token", "/api/v1/engagements", "Bearer nope", http.StatusUnauthorized, false},
		{"protected wrong scheme", "/api/v1/engagements", "Basic secret", http.StatusUnauthorized, false},
		{"protected correct token", "/api/v1/engagements", "Bearer secret", http.StatusOK, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			nextCalled = false
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.wantCode {
				t.Errorf("code = %d, want %d", rec.Code, tc.wantCode)
			}
			if nextCalled != tc.wantNext {
				t.Errorf("nextCalled = %v, want %v", nextCalled, tc.wantNext)
			}
		})
	}
}
