package httpapi

import (
	"strings"
	"testing"
)

// TestHumanPlaneExceptionAuthenticationPosture extends the parser-backed route inventory with the
// D1 distinction that matters before role authorization: some routes deliberately skip RBAC but
// still require an authenticated HumanPrincipal. Only the pre-authentication/browser bootstrap
// routes below may bypass the authenticator entirely.
func TestHumanPlaneExceptionAuthenticationPosture(t *testing.T) {
	public := publicPaths()
	wantPublic := map[string]bool{
		"/healthz":                 true,
		"/readyz":                  true,
		"/api/auth/oidc/login":     true,
		"/api/auth/oidc/callback":  true,
		"/api/auth/session":        true,
		"/api/v1/aup":              false,
		"/api/v1/aup/accept":       false,
		"/api/v1/me":               false,
		"/api/auth/logout":         false,
	}

	seen := map[string]bool{}
	for _, route := range registeredRoutes(t) {
		if _, exempt := publicRoutePatterns[route.Pattern]; !exempt {
			continue
		}
		_, path, ok := strings.Cut(route.Pattern, " ")
		if !ok {
			t.Fatalf("invalid registered route pattern %q", route.Pattern)
		}
		want, known := wantPublic[path]
		if !known {
			t.Fatalf("authz-exempt human route %q has no explicit D1 authentication posture", route.Pattern)
		}
		seen[path] = true
		if got := public[path]; got != want {
			t.Errorf("%s public=%v, want %v; RBAC exemption must not silently become authentication exemption", route.Pattern, got, want)
		}
	}

	for path, want := range wantPublic {
		if !seen[path] {
			t.Errorf("authentication-posture entry %q does not match a parser-inventoried route", path)
		}
		if got := public[path]; got != want {
			t.Errorf("publicPaths[%q]=%v, want %v", path, got, want)
		}
	}
}
