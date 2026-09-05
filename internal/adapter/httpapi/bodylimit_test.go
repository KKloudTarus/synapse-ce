package httpapi

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestBodyLimitFor pins the ceiling every route family gets, so a new route is bounded by
// the default the moment it is registered rather than inheriting an unbounded body.
func TestBodyLimitFor(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		want    int64
	}{
		{"unknown route falls back to the default", "POST /api/v1/engagements", defaultBodyLimit},
		{"empty pattern falls back to the default", "", defaultBodyLimit},
		{"source publish keeps the archive ceiling", "POST /api/v1/projects/{key}/analyses/{id}/source", sourceUploadBodyLimit},
		{"bundle import", "POST /api/v1/engagements/import", importBodyLimit},
		{"sarif import", "POST /api/v1/engagements/{id}/sarif", importBodyLimit},
		{"sbom import", "POST /api/v1/engagements/{id}/sbom", importBodyLimit},
		{"evidence capture", "POST /api/v1/engagements/{id}/evidence", importBodyLimit},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := bodyLimitFor(tc.pattern); got != tc.want {
				t.Errorf("bodyLimitFor(%q) = %d, want %d", tc.pattern, got, tc.want)
			}
		})
	}
}

// TestLimitRequestBodyRejectsOversizedBody proves the middleware bounds what a handler can
// read: without it a handler that decodes eagerly reads whatever an authenticated client
// sends, so one request can exhaust server memory.
func TestLimitRequestBodyRejectsOversizedBody(t *testing.T) {
	var read int64
	var readErr error
	handler := limitRequestBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		read, readErr = n, err
		w.WriteHeader(http.StatusOK)
	}))

	body := bytes.Repeat([]byte("a"), int(defaultBodyLimit)+4096)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/engagements", bytes.NewReader(body))
	req.Pattern = "POST /api/v1/engagements"
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if readErr == nil {
		t.Fatalf("handler read %d bytes with no error; the body was not bounded", read)
	}
	if read > defaultBodyLimit {
		t.Errorf("handler read %d bytes, want at most %d", read, defaultBodyLimit)
	}
	if !strings.Contains(readErr.Error(), "too large") {
		t.Errorf("error = %v, want the http.MaxBytesReader limit error", readErr)
	}
}

// TestLimitRequestBodyAllowsBodyUnderLimit keeps the guard from breaking ordinary requests.
func TestLimitRequestBodyAllowsBodyUnderLimit(t *testing.T) {
	var read int64
	var readErr error
	handler := limitRequestBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		read, readErr = io.Copy(io.Discard, r.Body)
	}))

	body := bytes.Repeat([]byte("a"), 512<<10)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/engagements", bytes.NewReader(body))
	req.Pattern = "POST /api/v1/engagements"
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if readErr != nil {
		t.Fatalf("read error = %v, want nil", readErr)
	}
	if read != int64(len(body)) {
		t.Errorf("read %d bytes, want %d", read, len(body))
	}
}

// TestLimitRequestBodyHonoursRouteOverride proves an import route keeps its larger ceiling
// while the default still applies elsewhere.
func TestLimitRequestBodyHonoursRouteOverride(t *testing.T) {
	var read int64
	var readErr error
	handler := limitRequestBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		read, readErr = io.Copy(io.Discard, r.Body)
	}))

	size := int(defaultBodyLimit) + (256 << 10)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/engagements/e1/sarif", bytes.NewReader(bytes.Repeat([]byte("a"), size)))
	req.Pattern = "POST /api/v1/engagements/{id}/sarif"
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if readErr != nil {
		t.Fatalf("read error = %v, want nil for an import route", readErr)
	}
	if read != int64(size) {
		t.Errorf("read %d bytes, want %d", read, size)
	}
}

// TestLimitRequestBodyPassesThroughBodylessMethods keeps GET and DELETE untouched.
func TestLimitRequestBodyPassesThroughBodylessMethods(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodDelete, http.MethodOptions} {
		t.Run(method, func(t *testing.T) {
			var seen io.ReadCloser
			handler := limitRequestBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen = r.Body
			}))
			req := httptest.NewRequest(method, "/api/v1/engagements", nil)
			original := req.Body
			handler.ServeHTTP(httptest.NewRecorder(), req)
			if seen != original {
				t.Errorf("%s body was replaced; bodyless methods must pass through untouched", method)
			}
		})
	}
}
