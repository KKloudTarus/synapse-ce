package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

// routerSource reads router.go so a test can assert on how routes are registered rather than on
// runtime behaviour that would need every optional service wired.
func routerSource(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatalf("read router.go: %v", err)
	}
	return string(b)
}

// harnessSource reads the hostile-harness test table so an inventory test can measure coverage.
func harnessSource(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("harness_test.go")
	if err != nil {
		t.Fatalf("read harness_test.go: %v", err)
	}
	return string(b)
}

// TestIsPlatformAdminFailsClosed pins the one property that makes this check usable as
// authorization: with no authenticated principal bound it must answer no. PrincipalFrom
// deliberately falls back to the operator id for attribution, so a check built on it would
// grant platform authority to any request that reached a handler without the authenticator.
func TestIsPlatformAdminFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		ctx  context.Context
		want bool
	}{
		{"no principal bound", context.Background(), false},
		{"empty principal", context.WithValue(context.Background(), principalKey, Principal{}), false},
		{"tenant admin", context.WithValue(context.Background(), principalKey, Principal{ID: "u1", Role: "admin", TenantID: "tenant-a"}), false},
		{"tenant member", context.WithValue(context.Background(), principalKey, Principal{ID: "u2", Role: "member", TenantID: "tenant-a"}), false},
		{"platform operator", context.WithValue(context.Background(), principalKey, Principal{ID: PrincipalOperator, Role: "admin"}), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsPlatformAdmin(tc.ctx); got != tc.want {
				t.Errorf("IsPlatformAdmin() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestRequirePlatformAdminRejectsTenantAdmin proves the middleware stops a tenant admin before
// the handler runs, and lets the platform operator through.
func TestRequirePlatformAdminRejectsTenantAdmin(t *testing.T) {
	rt := &Router{}
	var reached bool
	h := rt.requirePlatformAdmin(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})

	t.Run("tenant admin is refused", func(t *testing.T) {
		reached = false
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/vulnerability/sources", nil)
		req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "u1", Role: "admin", TenantID: "tenant-a"}))
		h(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
		}
		if reached {
			t.Error("handler ran for a tenant admin")
		}
	})

	t.Run("platform operator is allowed", func(t *testing.T) {
		reached = false
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/vulnerability/sources", nil)
		req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: PrincipalOperator, Role: "admin"}))
		h(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
		}
		if !reached {
			t.Error("handler did not run for the platform operator")
		}
	})
}

// TestGlobalResourceMutationsRequirePlatformAdmin is an inventory guard: every mutation of a
// resource that has no tenant_id column, and is therefore shared by every tenant, must carry the
// platform-operator check. Without it one tenant's admin decides what advisories every other
// tenant sees, and can point the control plane's HTTP client at a host of their choosing.
func TestGlobalResourceMutationsRequirePlatformAdmin(t *testing.T) {
	source := routerSource(t)
	// Mutating verbs on the global vulnerability-source registry.
	pattern := regexp.MustCompile(`mux\.HandleFunc\("(POST|PUT|PATCH|DELETE) (/api/v1/vulnerability/sources[^"]*)",\s*([^\n]+)`)
	matches := pattern.FindAllStringSubmatch(source, -1)
	if len(matches) == 0 {
		t.Fatal("found no vulnerability-source mutation routes; the guard is no longer looking at the right file")
	}
	for _, m := range matches {
		method, path, registration := m[1], m[2], m[3]
		// The sync route starts a fetch for an existing source and is deliberately a tenant
		// operator action, not a change to the shared registry.
		if strings.HasSuffix(path, "/sync") {
			continue
		}
		if !strings.Contains(registration, "requirePlatformAdmin") {
			t.Errorf("%s %s mutates the global source registry without requirePlatformAdmin", method, path)
		}
	}
}
