package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	identitydom "github.com/KKloudTarus/synapse-ce/internal/domain/identity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func identityContext(requestID string) context.Context {
	return context.WithValue(context.Background(), requestIDKey{}, requestID)
}

func decodeIdentityError(t *testing.T, rec *httptest.ResponseRecorder) identityErrorBody {
	t.Helper()
	var body identityErrorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode identity error: %v (%s)", err, rec.Body.String())
	}
	return body
}

func TestIdentityErrorContract(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		wantCode  IdentityErrorCode
		wantHTTP  int
		retryable bool
	}{
		{name: "invalid credential", err: identitydom.ErrAuthenticationInvalid, wantCode: IdentityErrorAuthenticationInvalid, wantHTTP: http.StatusUnauthorized},
		{name: "access denied", err: identitydom.ErrAccessDenied, wantCode: IdentityErrorAccessDenied, wantHTTP: http.StatusForbidden},
		{name: "legacy forbidden", err: shared.ErrForbidden, wantCode: IdentityErrorAccessDenied, wantHTTP: http.StatusForbidden},
		{name: "conflict", err: shared.ErrConflict, wantCode: IdentityErrorConflict, wantHTTP: http.StatusConflict},
		{name: "capacity", err: shared.ErrSaturated, wantCode: IdentityErrorCapacityLimited, wantHTTP: http.StatusServiceUnavailable, retryable: true},
		{name: "dependency", err: errors.New("postgres unavailable: secret detail"), wantCode: IdentityErrorDependencyUnavailable, wantHTTP: http.StatusServiceUnavailable, retryable: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			ctx := identityContext("req-123")
			writeIdentityFailure(ctx, rec, tc.err)
			if rec.Code != tc.wantHTTP {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantHTTP)
			}
			body := decodeIdentityError(t, rec)
			if body.Code != tc.wantCode || body.RequestID != "req-123" || body.Retryable != tc.retryable {
				t.Fatalf("body = %+v, want code=%q request=req-123 retryable=%v", body, tc.wantCode, tc.retryable)
			}
			if strings.Contains(body.Error, "secret detail") || strings.Contains(rec.Body.String(), "postgres") {
				t.Fatalf("public identity error leaked dependency detail: %s", rec.Body.String())
			}
			if tc.retryable && rec.Header().Get("Retry-After") == "" {
				t.Error("retryable identity error must include Retry-After")
			}
		})
	}
}

type sessionResolverFunc func(context.Context, string, string, bool) (HumanPrincipal, error)

func (f sessionResolverFunc) Authenticate(ctx context.Context, token, csrf string, unsafe bool) (HumanPrincipal, error) {
	return f(ctx, token, csrf, unsafe)
}

func TestSessionMiddlewarePreservesCookieOnDependencyFailure(t *testing.T) {
	auth := NewAuthenticator(func(context.Context, string) (HumanPrincipal, bool) { return HumanPrincipal{}, false })
	auth.SetSessionResolver(sessionResolverFunc(func(context.Context, string, string, bool) (HumanPrincipal, error) {
		return HumanPrincipal{}, errors.New("database unavailable")
	}))
	h := auth.Middleware(map[string]bool{}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler must not run when identity dependency fails")
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil).WithContext(identityContext("req-dep"))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "opaque"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body := decodeIdentityError(t, rec)
	if rec.Code != http.StatusServiceUnavailable || body.Code != IdentityErrorDependencyUnavailable || !body.Retryable {
		t.Fatalf("dependency response = status %d body %+v", rec.Code, body)
	}
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == sessionCookieName && cookie.MaxAge < 0 {
			t.Fatal("dependency failure cleared a browser credential")
		}
	}
}

func TestBearerMiddlewarePreservesDependencyFailure(t *testing.T) {
	auth := NewAuthenticatorWithErrorResolver(func(context.Context, string) (HumanPrincipal, error) {
		return HumanPrincipal{}, errors.New("database unavailable")
	})
	h := auth.Middleware(map[string]bool{}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler must not run when bearer resolution fails")
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil).WithContext(identityContext("req-bearer-dep"))
	req.Header.Set("Authorization", "Bearer still-valid")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body := decodeIdentityError(t, rec)
	if rec.Code != http.StatusServiceUnavailable || body.Code != IdentityErrorDependencyUnavailable || !body.Retryable {
		t.Fatalf("dependency response = status %d body %+v", rec.Code, body)
	}
}

func TestSessionMiddlewareClearsOnlyInvalidCredential(t *testing.T) {
	auth := NewAuthenticator(func(context.Context, string) (HumanPrincipal, bool) { return HumanPrincipal{}, false })
	auth.SetSessionResolver(sessionResolverFunc(func(context.Context, string, string, bool) (HumanPrincipal, error) {
		return HumanPrincipal{}, identitydom.ErrAuthenticationInvalid
	}))
	h := auth.Middleware(map[string]bool{}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler must not run for invalid session")
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil).WithContext(identityContext("req-invalid"))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "expired"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body := decodeIdentityError(t, rec)
	if rec.Code != http.StatusUnauthorized || body.Code != IdentityErrorAuthenticationInvalid || body.Retryable {
		t.Fatalf("invalid response = status %d body %+v", rec.Code, body)
	}
	cleared := false
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == sessionCookieName && cookie.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("invalid browser credential was not cleared")
	}
}

func TestSessionMiddlewareDoesNotClearOnAccessDenied(t *testing.T) {
	auth := NewAuthenticator(func(context.Context, string) (HumanPrincipal, bool) { return HumanPrincipal{}, false })
	auth.SetSessionResolver(sessionResolverFunc(func(context.Context, string, string, bool) (HumanPrincipal, error) {
		return HumanPrincipal{}, identitydom.ErrAccessDenied
	}))
	h := auth.Middleware(map[string]bool{}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler must not run when CSRF/access proof is denied")
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", nil).WithContext(identityContext("req-denied"))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "still-valid"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	body := decodeIdentityError(t, rec)
	if rec.Code != http.StatusForbidden || body.Code != IdentityErrorAccessDenied {
		t.Fatalf("access-denied response = status %d body %+v", rec.Code, body)
	}
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == sessionCookieName && cookie.MaxAge < 0 {
			t.Fatal("access denial cleared a still-valid browser session")
		}
	}
}
