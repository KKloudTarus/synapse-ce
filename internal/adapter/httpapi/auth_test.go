package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestTenantPropagatesThroughContext covers the tenant foundation: the tenant the resolver
// puts on the Principal flows through the auth middleware into the request context, readable via
// TenantFrom – the plumbing that lets writes stamp + reads scope by tenant.
func TestTenantPropagatesThroughContext(t *testing.T) {
	auth := NewAuthenticator(func(_ context.Context, _ string) (Principal, bool) {
		return Principal{ID: "u1", Name: "T", Role: "member", TenantID: "acme"}, true
	})
	var gotTenant, gotActor string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotTenant = TenantFrom(r.Context())
		gotActor = PrincipalFrom(r.Context())
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
}

func TestTenantFromDefaultsEmpty(t *testing.T) {
	if tid := TenantFrom(context.Background()); tid != "" {
		t.Errorf("no principal → tenant must be '' (default tenant), got %q", tid)
	}
}

func TestAuthenticatorMiddleware(t *testing.T) {
	// Resolver accepts only "secret", mapping it to a member principal.
	auth := NewAuthenticator(func(_ context.Context, token string) (Principal, bool) {
		if token == "secret" {
			return Principal{ID: "u1", Name: "Tester", Role: "member"}, true
		}
		return Principal{}, false
	})
	public := map[string]bool{"/healthz": true}

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
