package httpapi

import "testing"

// A public path skips authentication but NOT the AUP gate. An unauthenticated visitor has no
// principal that could have accepted the policy, so a public path missing from the AUP exemption
// set answers 403 forever – which silently makes browser login unreachable.
func TestPublicPathsAreAUPExempt(t *testing.T) {
	exempt := aupExemptPaths()
	for path := range publicPaths() {
		if !exempt[path] {
			t.Errorf("public path %q is not AUP-exempt; it would always answer 403", path)
		}
	}
}

func TestBrowserLoginPathsAreReachableUnauthenticated(t *testing.T) {
	public, exempt := publicPaths(), aupExemptPaths()
	// The login redirect, the provider callback, and session discovery are all reached before a
	// session exists. Logout requires a session, so it is authenticated but still AUP-exempt.
	for _, path := range []string{"/api/auth/oidc/login", "/api/auth/oidc/callback", "/api/auth/session"} {
		if !public[path] {
			t.Errorf("%q must be public: the browser reaches it before any session exists", path)
		}
		if !exempt[path] {
			t.Errorf("%q must be AUP-exempt", path)
		}
	}
	if public["/api/auth/logout"] {
		t.Error("/api/auth/logout must require authentication")
	}
	if !exempt["/api/auth/logout"] {
		t.Error("/api/auth/logout must be AUP-exempt so an operator can always sign out")
	}
}
