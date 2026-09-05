package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/alerting"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func alert() alerting.Alert {
	return alerting.Alert{ID: "a1", TenantID: "t1", Kind: alerting.KindIncidentCreated, Severity: shared.SeverityHigh, Title: "process: det.process_enumeration", IncidentID: "inc-1", Link: "/fleet/incidents/inc-1", OccurredAt: time.Unix(1_700_000_000, 0).UTC()}
}

// newSink points at a loopback test server (http is allowed for loopback) with retries made instant.
func newSink(t *testing.T, url, secret string) *Sink {
	t.Helper()
	s, err := New(url, secret, 5*time.Second, true, secret == "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.sleep = func(context.Context, time.Duration) error { return nil }
	s.now = func() time.Time { return time.Unix(1_700_000_100, 0).UTC() }
	return s
}

func TestDeliverPostsSignedEnvelope(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	var gotBody []byte
	var gotHeaders http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	s := newSink(t, srv.URL+"/hooks/synapse", secret)
	if err := s.Deliver(context.Background(), alert()); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	var env envelope
	if err := json.Unmarshal(gotBody, &env); err != nil {
		t.Fatal(err)
	}
	if env.Type != alerting.KindIncidentCreated || env.Alert.IncidentID != "inc-1" || env.Alert.Link != "/fleet/incidents/inc-1" || env.SentAt.Unix() != 1_700_000_100 {
		t.Fatalf("envelope = %+v", env)
	}
	if gotHeaders.Get("Content-Type") != "application/json" || gotHeaders.Get("X-Synapse-Alert-Kind") != "incident.created" || gotHeaders.Get("X-Synapse-Alert-ID") != "a1" || gotHeaders.Get("User-Agent") != userAgent {
		t.Fatalf("headers = %v", gotHeaders)
	}
	ts := gotHeaders.Get("X-Synapse-Timestamp")
	if ts != "1700000100" {
		t.Fatalf("timestamp = %q", ts)
	}
	if !Verify([]byte(secret), ts, gotBody, gotHeaders.Get("X-Synapse-Signature")) {
		t.Fatalf("signature does not verify: %q", gotHeaders.Get("X-Synapse-Signature"))
	}
	if Verify([]byte("wrong-secret-wrong-secret"), ts, gotBody, gotHeaders.Get("X-Synapse-Signature")) {
		t.Fatal("signature verified with the wrong secret")
	}
}

func TestDeliverWithoutSecretSendsNoSignature(t *testing.T) {
	var signed bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signed = r.Header.Get("X-Synapse-Signature") != ""
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	if err := newSink(t, srv.URL, "").Deliver(context.Background(), alert()); err != nil {
		t.Fatal(err)
	}
	if signed {
		t.Fatal("unsigned sink sent a signature header")
	}
}

func TestDeliverRetriesTransientAndStopsOnClientError(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	if err := newSink(t, srv.URL, "").Deliver(context.Background(), alert()); err != nil {
		t.Fatalf("third attempt should succeed: %v", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("calls = %d, want 3", calls.Load())
	}

	calls.Store(0)
	always := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("upstream down"))
	}))
	defer always.Close()
	err := newSink(t, always.URL, "").Deliver(context.Background(), alert())
	if err == nil || calls.Load() != attempts {
		t.Fatalf("persistent 5xx: err=%v calls=%d", err, calls.Load())
	}

	calls.Store(0)
	reject := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer reject.Close()
	err = newSink(t, reject.URL, "").Deliver(context.Background(), alert())
	if err == nil || calls.Load() != 1 {
		t.Fatalf("4xx must be final: err=%v calls=%d", err, calls.Load())
	}
}

func TestDeliverHonoursContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusInternalServerError) }))
	defer srv.Close()
	s := newSink(t, srv.URL, "")
	s.sleep = func(ctx context.Context, _ time.Duration) error { return context.Canceled }
	if err := s.Deliver(context.Background(), alert()); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled from the retry wait", err)
	}
}

func TestNewValidatesDestination(t *testing.T) {
	cases := map[string]struct {
		url, secret string
		unsigned    bool
		ok          bool
	}{
		"https unsigned opt-in":   {"https://hooks.example.com/synapse", "", true, true},
		"https no secret refused": {"https://hooks.example.com/synapse", "", false, false},
		"http loopback unsigned":  {"http://127.0.0.1:9000/hook", "", true, true},
		"http localhost unsigned": {"http://localhost:9000/hook", "", true, true},
		"http remote":             {"http://hooks.example.com/synapse", "", true, false},
		"ftp":                     {"ftp://hooks.example.com/synapse", "", true, false},
		"relative":                {"/hooks", "", true, false},
		"credentials in url":      {"https://user:pw@hooks.example.com/synapse", "", true, false},
		"short secret":            {"https://hooks.example.com/synapse", "short", false, false},
		"long enough secret":      {"https://hooks.example.com/synapse", "0123456789abcdef", false, true},
	}
	for name, tc := range cases {
		_, err := New(tc.url, tc.secret, time.Second, false, tc.unsigned)
		if tc.ok && err != nil {
			t.Errorf("%s: unexpected error %v", name, err)
		}
		if !tc.ok && !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: err = %v, want ErrValidation", name, err)
		}
	}
}

// A transport failure must not put the destination URL into the error: for Slack-style hooks the path
// is the credential, and the error text lands in the audit log.
func TestDeliverErrorNeverCarriesTheURL(t *testing.T) {
	s, err := New("https://hooks.example.invalid/services/T000/B000/SECRETTOKENXYZ", "", 500*time.Millisecond, false, true)
	if err != nil {
		t.Fatal(err)
	}
	s.sleep = func(context.Context, time.Duration) error { return nil }
	err = s.Deliver(context.Background(), alert())
	if err == nil {
		t.Fatal("delivery to an unresolvable host succeeded")
	}
	if strings.Contains(err.Error(), "SECRETTOKENXYZ") || strings.Contains(err.Error(), "/services/") {
		t.Fatalf("error leaks the credential path: %v", err)
	}
}

func TestDeliverCancelledRetryKeepsTheLastCause(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("db down"))
	}))
	defer srv.Close()
	s := newSink(t, srv.URL, "")
	s.sleep = func(ctx context.Context, _ time.Duration) error { return context.Canceled }
	err := s.Deliver(context.Background(), alert())
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "responded 500") {
		t.Fatalf("err = %v, want the cancellation with the last 500 attached", err)
	}
}
