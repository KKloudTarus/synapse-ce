package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type cookieSessionResolver struct{ principal Principal }

func (s cookieSessionResolver) Authenticate(_ context.Context, token, csrf string, unsafe bool) (Principal, error) {
	if token != "opaque" || unsafe && csrf != "csrf" {
		return Principal{}, errors.New("denied")
	}
	return s.principal, nil
}

func TestNewOIDCServiceRejectsNilOperations(t *testing.T) {
	validBegin := func(context.Context) (OIDCAuthorization, error) { return OIDCAuthorization{}, nil }
	validComplete := func(context.Context, string, string, string) (OIDCSession, error) { return OIDCSession{}, nil }
	validDiscover := func(context.Context, string) (OIDCSession, error) { return OIDCSession{}, nil }
	validAuthenticate := func(context.Context, string, string, bool) (OIDCPrincipal, error) { return OIDCPrincipal{}, nil }
	validLogout := func(context.Context, string) error { return nil }
	if service, err := NewOIDCService(validBegin, validComplete, validDiscover, validAuthenticate, validLogout); err != nil || service == nil {
		t.Fatalf("valid service = %v, %v", service, err)
	}
	if _, err := NewOIDCService(nil, validComplete, validDiscover, validAuthenticate, validLogout); err == nil {
		t.Fatal("nil operation was accepted")
	}
}

func TestOIDCCookieFlags(t *testing.T) {
	rec := httptest.NewRecorder()
	setSessionCookie(rec, "opaque")
	cookie := rec.Result().Cookies()[0]
	if cookie.Name != sessionCookieName || !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.SameSite != http.SameSiteLaxMode || strings.Contains(rec.Header().Get("Set-Cookie"), "Domain=") {
		t.Fatalf("unsafe session cookie: %q", rec.Header().Get("Set-Cookie"))
	}

	rec = httptest.NewRecorder()
	setNonceCookie(rec, "nonce")
	nonce := rec.Result().Cookies()[0]
	if nonce.Name != nonceCookieName || nonce.Path != "/" || !nonce.Secure || !nonce.HttpOnly || nonce.SameSite != http.SameSiteLaxMode || strings.Contains(rec.Header().Get("Set-Cookie"), "Domain=") {
		t.Fatalf("unsafe nonce cookie: %q", rec.Header().Get("Set-Cookie"))
	}
}

type oidcTestService struct {
	discover func(context.Context, string) (OIDCSession, error)
	complete func(context.Context, string, string, string) (OIDCSession, error)
}

func (s oidcTestService) Begin(context.Context) (OIDCAuthorization, error) {
	return OIDCAuthorization{}, errors.New("not implemented")
}
func (s oidcTestService) Complete(ctx context.Context, state, code, nonce string) (OIDCSession, error) {
	return s.complete(ctx, state, code, nonce)
}
func (s oidcTestService) Discover(ctx context.Context, token string) (OIDCSession, error) {
	return s.discover(ctx, token)
}
func (s oidcTestService) Authenticate(context.Context, string, string, bool) (OIDCPrincipal, error) {
	return OIDCPrincipal{}, errors.New("not implemented")
}
func (s oidcTestService) Logout(context.Context, string) error { return nil }

func TestOIDCSessionDiscoveryDoesNotExposeOpaqueToken(t *testing.T) {
	rt := &Router{oidc: oidcTestService{discover: func(_ context.Context, token string) (OIDCSession, error) {
		if token != "old-token" {
			t.Fatalf("token = %q", token)
		}
		return OIDCSession{Token: "new-token", CSRFToken: "csrf", Principal: OIDCPrincipal{ID: "u1", Name: "User", Role: "admin", TenantID: "tenant"}}, nil
	}}}
	req := httptest.NewRequest(http.MethodGet, "/api/auth/session", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "old-token"})
	rec := httptest.NewRecorder()
	rt.oidcSession(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "\"authenticated\":true") || !strings.Contains(body, "\"csrf_token\":\"csrf\"") || strings.Contains(body, "old-token") || strings.Contains(body, "new-token") {
		t.Fatalf("unexpected session response: %s", body)
	}
	if cookie := rec.Result().Cookies()[0]; cookie.Value != "new-token" || !cookie.HttpOnly {
		t.Fatalf("session cookie = %#v", cookie)
	}
}

func TestOIDCCallbackRedirectsToConfiguredFrontendOnly(t *testing.T) {
	rt := &Router{oidcFrontendURL: "https://synapse.example/", oidc: oidcTestService{complete: func(_ context.Context, state, code, nonce string) (OIDCSession, error) {
		if state != "state" || code != "code" || nonce != "nonce" {
			t.Fatalf("unexpected callback values")
		}
		return OIDCSession{Token: "opaque"}, nil
	}}}
	req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/callback?state=state&code=code&next=https://attacker.example", nil)
	req.AddCookie(&http.Cookie{Name: nonceCookieName, Value: "nonce"})
	rec := httptest.NewRecorder()
	rt.oidcCallback(rec, req)

	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "https://synapse.example/" {
		t.Fatalf("callback redirect = %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestCookieCSRFAndBearerUnchanged(t *testing.T) {
	resolver := cookieSessionResolver{principal: Principal{ID: "u1", Role: "admin", TenantID: "tenant"}}
	auth := NewAuthenticator(func(_ context.Context, token string) (Principal, bool) {
		return Principal{ID: "bearer", Role: "admin"}, token == "api"
	})
	auth.SetSessionResolver(resolver)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	h := auth.Middleware(map[string]bool{}, next)
	for _, tc := range []struct {
		name, method, authz, cookie, csrf string
		want                              int
	}{
		{"unsafe cookie lacks csrf", http.MethodPost, "", "opaque", "", http.StatusUnauthorized},
		{"unsafe cookie csrf", http.MethodPost, "", "opaque", "csrf", http.StatusNoContent},
		{"bearer ignores csrf", http.MethodPost, "Bearer api", "opaque", "", http.StatusNoContent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/api/v1/x", nil)
			if tc.authz != "" {
				req.Header.Set("Authorization", tc.authz)
			}
			if tc.cookie != "" {
				req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: tc.cookie})
			}
			req.Header.Set("X-CSRF-Token", tc.csrf)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
		})
	}
}
