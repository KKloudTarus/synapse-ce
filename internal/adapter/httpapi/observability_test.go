package httpapi

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type recordedObservation struct {
	method, route, statusClass string
	duration                   time.Duration
}

type fakeHTTPObserver struct {
	mu    sync.Mutex
	calls []recordedObservation
}

func (f *fakeHTTPObserver) ObserveHTTPRequest(method, route, statusClass string, duration time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, recordedObservation{method: method, route: route, statusClass: statusClass, duration: duration})
}

func (f *fakeHTTPObserver) snapshot() []recordedObservation {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedObservation(nil), f.calls...)
}

// TestInstrumentGeneratesRequestID covers request-ID correlation: Instrument must mint
// one ID, expose it via X-Request-ID and RequestIDFrom, and every request gets exactly one.
func TestInstrumentGeneratesRequestID(t *testing.T) {
	var gotID string
	var ok bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotID, ok = RequestIDFrom(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	h := Instrument(next, discardLog(), false, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

	if !ok || gotID == "" {
		t.Fatal("request ID must be set in the request context")
	}
	if rec.Header().Get("X-Request-ID") != gotID {
		t.Errorf("X-Request-ID header = %q, want %q", rec.Header().Get("X-Request-ID"), gotID)
	}
}

// TestInstrumentDefaultStatusIsOK covers a handler that never calls WriteHeader: the
// default response status recorded and observed must be 200, matching net/http semantics.
func TestInstrumentDefaultStatusIsOK(t *testing.T) {
	observer := &fakeHTTPObserver{}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok")) // no explicit WriteHeader
	})
	h := Instrument(next, discardLog(), false, observer)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	h.ServeHTTP(rec, req)

	if len(observer.snapshot()) != 1 {
		t.Fatalf("want exactly 1 observation, got %d", len(observer.snapshot()))
	}
	if observer.snapshot()[0].statusClass != "2xx" {
		t.Errorf("statusClass = %q, want 2xx (default status 200)", observer.snapshot()[0].statusClass)
	}
}

// TestInstrumentExplicitStatus covers an explicit WriteHeader call, and that the
// route label falls back to "unmatched" when r.Pattern is unset (no ServeMux match).
func TestInstrumentExplicitStatus(t *testing.T) {
	observer := &fakeHTTPObserver{}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	h := Instrument(next, discardLog(), false, observer)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/missing", nil))

	if len(observer.snapshot()) != 1 {
		t.Fatalf("want exactly 1 observation, got %d", len(observer.snapshot()))
	}
	got := observer.snapshot()[0]
	if got.statusClass != "4xx" {
		t.Errorf("statusClass = %q, want 4xx", got.statusClass)
	}
	if got.route != unmatchedRoute {
		t.Errorf("route = %q, want %q for a request with no matched ServeMux pattern", got.route, unmatchedRoute)
	}
}

// TestInstrumentRoutePatternCardinality covers bounded route labels: the matched
// ServeMux pattern (a fixed template, never the raw path) is used for the route label,
// so distinct path VALUES on the same route collapse to one bounded label.
func TestInstrumentRoutePatternCardinality(t *testing.T) {
	observer := &fakeHTTPObserver{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/engagements/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := Instrument(mux, discardLog(), false, observer)

	for _, id := range []string{"e1", "e2", "e3"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/engagements/"+id, nil))
	}
	if len(observer.snapshot()) != 3 {
		t.Fatalf("want 3 observations, got %d", len(observer.snapshot()))
	}
	for _, c := range observer.snapshot() {
		if c.route != "GET /api/v1/engagements/{id}" {
			t.Errorf("route = %q, want the matched pattern (not the raw path)", c.route)
		}
	}
}

// TestInstrumentAccessLogEmitsExactlyOnceWhenEnabled covers the single-access-event
// contract: enabled → exactly one Info "http access" record per request with the
// documented safe fields; disabled → zero.
func TestInstrumentAccessLogEmitsExactlyOnceWhenEnabled(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	var buf strings.Builder
	log := newCapturingLogger(&buf)
	h := Instrument(next, log, true, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/engagements", nil))

	out := buf.String()
	if strings.Count(out, "http access") != 1 {
		t.Fatalf("want exactly 1 access-log event, got log: %s", out)
	}
	for _, field := range []string{"request_id=", "method=GET", "status=200"} {
		if !strings.Contains(out, field) {
			t.Errorf("access log missing field %q: %s", field, out)
		}
	}
}

func TestInstrumentAccessLogDisabledEmitsNothing(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	var buf strings.Builder
	log := newCapturingLogger(&buf)
	h := Instrument(next, log, false, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/engagements", nil))
	if buf.Len() != 0 {
		t.Errorf("access logging disabled must emit nothing, got: %s", buf.String())
	}
}

// TestInstrumentSensitiveFieldsAbsent covers the privacy contract: the access-log
// event must never contain the raw path, query string, or a value the handler wrote
// to the response body, even though the request carried them.
func TestInstrumentSensitiveFieldsAbsent(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("super-secret-body-content"))
	})
	var buf strings.Builder
	log := newCapturingLogger(&buf)
	h := Instrument(next, log, true, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/engagements?token=super-secret-query&tenant=acme", nil)
	req.Header.Set("Authorization", "Bearer super-secret-bearer-token")
	req.Header.Set("User-Agent", "sensitive-agent-string")
	h.ServeHTTP(rec, req)

	out := buf.String()
	for _, secret := range []string{"super-secret-query", "super-secret-bearer-token", "sensitive-agent-string", "super-secret-body-content", "?token="} {
		if strings.Contains(out, secret) {
			t.Errorf("access log leaked sensitive content %q: %s", secret, out)
		}
	}
}

// TestInstrumentPrincipalPropagation covers principal attribution: setPrincipal (as
// called by the real auth middleware) must surface in the access log only when the
// principal actually resolves; an unauthenticated request logs no principal_id field.
func TestInstrumentPrincipalPropagation(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if observation := requestObservationFrom(r.Context()); observation != nil {
			observation.setPrincipal("user-123")
		}
		w.WriteHeader(http.StatusOK)
	})
	var buf strings.Builder
	log := newCapturingLogger(&buf)
	h := Instrument(next, log, true, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

	if !strings.Contains(buf.String(), "principal_id=user-123") {
		t.Errorf("access log missing resolved principal_id: %s", buf.String())
	}

	buf.Reset()
	anon := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
	h2 := Instrument(anon, log, true, nil)
	rec2 := httptest.NewRecorder()
	h2.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/x", nil))
	if strings.Contains(buf.String(), "principal_id") {
		t.Errorf("unauthenticated request must not log principal_id: %s", buf.String())
	}
}

// flushRecorder is a ResponseWriter double implementing http.Flusher, so the test can
// confirm Instrument's wrapper preserves streaming instead of buffering.
type flushRecorder struct {
	*httptest.ResponseRecorder
	flushed int
}

func (f *flushRecorder) Flush() { f.flushed++ }

// TestInstrumentPreservesFlusher covers streaming preservation: the wrapper must
// expose http.Flusher (via Unwrap for http.ResponseController, and directly) so a
// streaming handler's Flush() calls still reach the underlying writer.
func TestInstrumentPreservesFlusher(t *testing.T) {
	under := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
	var sawFlusher bool
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		rc := http.NewResponseController(w)
		if err := rc.Flush(); err == nil {
			sawFlusher = true
		}
	})
	h := Instrument(next, discardLog(), false, nil)
	h.ServeHTTP(under, httptest.NewRequest(http.MethodGet, "/stream", nil))

	if !sawFlusher {
		t.Error("http.ResponseController(w).Flush() must succeed through the observability wrapper")
	}
	if under.flushed == 0 {
		t.Error("Flush must reach the underlying ResponseWriter, not be buffered")
	}
}

// newCapturingLogger returns a slog.Logger that writes to buf using the text handler,
// so key=value substrings are stable for the assertions above.
func newCapturingLogger(buf *strings.Builder) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, nil))
}

func TestInstrumentBoundsArbitraryMethod(t *testing.T) {
	observer := &fakeHTTPObserver{}
	h := Instrument(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }), discardLog(), false, observer)
	req := httptest.NewRequest("BREW", "/x", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)
	calls := observer.snapshot()
	if len(calls) != 1 || calls[0].method != "OTHER" {
		t.Fatalf("observations = %+v, want one OTHER method", calls)
	}
}

func TestInstrumentPanicObservesOneServerErrorAndRepans(t *testing.T) {
	observer := &fakeHTTPObserver{}
	h := Instrument(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		panic("boom")
	}), discardLog(), false, observer)
	defer func() {
		if recover() != "boom" {
			t.Fatal("panic must be preserved")
		}
		calls := observer.snapshot()
		if len(calls) != 1 || calls[0].statusClass != "5xx" {
			t.Fatalf("observations = %+v, want one 5xx", calls)
		}
	}()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))
}

type plainRecorder struct{ header http.Header }

func (w *plainRecorder) Header() http.Header         { return w.header }
func (w *plainRecorder) Write(b []byte) (int, error) { return len(b), nil }
func (w *plainRecorder) WriteHeader(int)             {}

type responseWriterWrapper struct{ http.ResponseWriter }

func (w responseWriterWrapper) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func TestInstrumentDoesNotExposeUnsupportedFlusher(t *testing.T) {
	under := &plainRecorder{header: make(http.Header)}
	h := Instrument(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, ok := w.(http.Flusher); ok {
			t.Error("wrapper must not expose Flusher when the underlying writer does not")
		}
		if err := http.NewResponseController(w).Flush(); err == nil {
			t.Error("Flush must be unsupported when the underlying writer does not support it")
		}
	}), discardLog(), false, nil)
	h.ServeHTTP(under, httptest.NewRequest(http.MethodGet, "/", nil))
}

func TestInstrumentCorrelatesUnexpectedErrorAndAccessLogs(t *testing.T) {
	var buf strings.Builder
	log := newCapturingLogger(&buf)
	h := Instrument(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError(responseWriterWrapper{responseWriterWrapper{w}}, log, errors.New("database unavailable"))
	}), log, true, nil)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/secret?token=not-logged", nil))
	output := buf.String()
	var requestIDs []string
	for _, field := range strings.Fields(output) {
		if requestID, ok := strings.CutPrefix(field, "request_id="); ok {
			requestIDs = append(requestIDs, requestID)
		}
	}
	if len(requestIDs) != 2 || requestIDs[0] != requestIDs[1] {
		t.Fatalf("unexpected/access logs must share one request ID through response-writer wrappers: %s", output)
	}
	if strings.Contains(output, "token") || strings.Contains(output, "/secret") {
		t.Fatalf("logs contain sensitive request data: %s", output)
	}
}

func TestInstrumentPreservesRoutePatternsAcrossRejectedAndFleetRequests(t *testing.T) {
	humanRoutes := http.NewServeMux()
	humanRoutes.HandleFunc("GET /protected", func(http.ResponseWriter, *http.Request) {})
	humanRoutes.HandleFunc("GET /wild/{id}", func(http.ResponseWriter, *http.Request) {})
	human := annotateRoutePattern(humanRoutes, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forbidden") != "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	top := http.NewServeMux()
	top.HandleFunc("POST /api/v1/fleet/agents/{id}/heartbeat", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	top.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Pattern = ""
		human.ServeHTTP(w, r)
	}))
	observer := &fakeHTTPObserver{}
	h := Instrument(top, discardLog(), false, observer)
	for _, test := range []struct {
		name, method, path, route string
		forbidden                 bool
	}{
		{name: "unauthorized known", method: http.MethodGet, path: "/protected", route: "GET /protected"},
		{name: "forbidden known", method: http.MethodGet, path: "/protected", route: "GET /protected", forbidden: true},
		{name: "wildcard", method: http.MethodGet, path: "/wild/e-123", route: "GET /wild/{id}"},
		{name: "method mismatch", method: http.MethodPost, path: "/protected", route: unmatchedRoute},
		{name: "unmatched", method: http.MethodGet, path: "/missing", route: unmatchedRoute},
		{name: "fleet", method: http.MethodPost, path: "/api/v1/fleet/agents/a-123/heartbeat", route: "POST /api/v1/fleet/agents/{id}/heartbeat"},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(test.method, test.path, nil)
			if test.forbidden {
				req.Header.Set("X-Forbidden", "1")
			}
			h.ServeHTTP(httptest.NewRecorder(), req)
		})
	}
	calls := observer.snapshot()
	if len(calls) != 6 {
		t.Fatalf("observations = %d, want 6", len(calls))
	}
	for i, want := range []string{"GET /protected", "GET /protected", "GET /wild/{id}", unmatchedRoute, unmatchedRoute, "POST /api/v1/fleet/agents/{id}/heartbeat"} {
		if calls[i].route != want {
			t.Errorf("observation %d route = %q, want %q", i, calls[i].route, want)
		}
	}
}
