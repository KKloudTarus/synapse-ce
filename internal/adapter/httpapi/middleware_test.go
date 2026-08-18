package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestNormalizePathRejectsNonCanonical covers the auth/AUP bypass surface: the
// gate must reject any path that the ServeMux would clean, so authz decisions
// run on the same path the router uses.
func TestNormalizePathRejectsNonCanonical(t *testing.T) {
	var called bool
	h := normalizePath(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	bad := []string{
		"/healthz/",
		"/api/v1//engagements",
		"/./healthz",
		"/api/v1/sca/scans/..",
		"//healthz",
		"/api/v1/aup/",
	}
	for _, p := range bad {
		called = false
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://x"+p, nil))
		if rec.Code != http.StatusBadRequest || called {
			t.Errorf("%q: want 400 and no next, got code=%d next=%v", p, rec.Code, called)
		}
	}

	good := []string{"/healthz", "/readyz", "/api/v1/engagements", "/api/v1/aup", "/api/v1/aup/accept", "/"}
	for _, p := range good {
		called = false
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://x"+p, nil))
		if rec.Code != http.StatusOK || !called {
			t.Errorf("%q: want pass-through, got code=%d next=%v", p, rec.Code, called)
		}
	}
}
