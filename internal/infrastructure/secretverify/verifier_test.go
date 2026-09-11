package secretverify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// newTestVerifier builds a Verifier whose providers point at a test server and that uses the server's
// (localhost-permitting) client, since the production safehttp client blocks loopback.
func newTestVerifier(t *testing.T, srv *httptest.Server) *Verifier {
	t.Helper()
	v := newWithClient(srv.Client(), 1000) // high rps: the limiter must not slow tests
	for _, p := range v.byRule {
		p.baseURL = srv.URL
	}
	return v
}

func TestVerifyGitHubLiveIsVerified(t *testing.T) {
	const token = "ghp_livetoken0000000000000000000000000000"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user" {
			t.Errorf("expected GET /user, got %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "token "+token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"login":"octocat"}`))
	}))
	defer srv.Close()

	v := newTestVerifier(t, srv)
	got, err := v.Verify(context.Background(), "github-token", []byte(token))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got != ports.SecretVerified {
		t.Errorf("a live GitHub token must be verified, got %q", got)
	}
}

func TestVerifyRejectedIsUnverifiedForUnambiguousProvider(t *testing.T) {
	// OpenAI has a single global host, so a 401 proves the key is dead → unverified.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	v := newTestVerifier(t, srv)
	got, err := v.Verify(context.Background(), "openai-api-key", []byte("sk-proj-deadkey0000000000"))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got != ports.SecretUnverified {
		t.Errorf("a 401 from an unambiguous provider must map to unverified, got %q", got)
	}
}

// A 401 from a HOST-AMBIGUOUS provider (GitHub/GitLab) must be UNKNOWN, not unverified: the token could be
// a live enterprise/self-managed credential rejected only by the public host. Falsely stamping it "dead"
// would understate a live leak.
func TestVerifyHostAmbiguous401IsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	v := newTestVerifier(t, srv)
	for _, rule := range []string{"github-token", "github-fine-grained-pat", "gitlab-pat"} {
		got, err := v.Verify(context.Background(), rule, []byte("tok_"+rule+"_000000000000000000000000"))
		if err != nil {
			t.Fatalf("%s: %v", rule, err)
		}
		if got != ports.SecretUnknown {
			t.Errorf("%s: a public-host 401 must be unknown (enterprise ambiguity), got %q", rule, got)
		}
	}
}

// A 403 is always inconclusive (rate limit / abuse / SSO / missing scope), never a rejection — even for an
// unambiguous provider.
func TestVerify403IsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	v := newTestVerifier(t, srv)
	for _, rule := range []string{"github-token", "openai-api-key"} {
		got, err := v.Verify(context.Background(), rule, []byte("sk-proj-throttled000000000"))
		if err != nil {
			t.Fatalf("%s: %v", rule, err)
		}
		if got != ports.SecretUnknown {
			t.Errorf("%s: a 403 must be unknown (not a rejection), got %q", rule, got)
		}
	}
}

func TestVerifyServerErrorIsUnknownNotUnverified(t *testing.T) {
	// A 5xx (or a rate-limit 429) must NOT be read as a rejection: it is inconclusive. Confusing "server
	// error" with "credential rejected" could understate a live leak.
	for _, status := range []int{http.StatusInternalServerError, http.StatusTooManyRequests, http.StatusBadGateway} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		}))
		v := newTestVerifier(t, srv)
		got, err := v.Verify(context.Background(), "openai-api-key", []byte("sk-proj-livekey000000000000"))
		srv.Close()
		if err != nil {
			t.Fatalf("verify (status %d): %v", status, err)
		}
		if got != ports.SecretUnknown {
			t.Errorf("status %d must be unknown (never unverified), got %q", status, got)
		}
	}
}

func TestVerifyUnknownRuleIsUnknownNoCall(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	v := newTestVerifier(t, srv)
	got, err := v.Verify(context.Background(), "some-unsupported-rule", []byte("whatever"))
	if err != nil || got != ports.SecretUnknown {
		t.Fatalf("an unsupported rule must be unknown with no error, got %q err=%v", got, err)
	}
	if called {
		t.Error("no provider call must be made for an unsupported rule")
	}
}

func TestVerifyEmptySecretIsUnknownNoCall(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { called = true }))
	defer srv.Close()
	v := newTestVerifier(t, srv)
	got, _ := v.Verify(context.Background(), "github-token", nil)
	if got != ports.SecretUnknown || called {
		t.Errorf("an empty secret must not be verified (got %q, called=%v)", got, called)
	}
}

func TestVerifyTransportErrorIsUnknownAndScrubsSecret(t *testing.T) {
	const token = "ghp_supersecretvalue00000000000000000000"
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // force a connection-refused transport error
	v := New(1000)
	v.byRule["github-token"].baseURL = url
	got, err := v.Verify(context.Background(), "github-token", []byte(token))
	if got != ports.SecretUnknown {
		t.Errorf("a transport failure must map to unknown, got %q", got)
	}
	if err == nil {
		t.Fatal("a transport failure should surface an error (for a best-effort caller)")
	}
	if strings.Contains(err.Error(), token) {
		t.Errorf("the returned error must NEVER contain the raw secret: %q", err.Error())
	}
}

func TestVerifyDedupCallsPerVerifierAreCallerControlled(t *testing.T) {
	// The Verifier itself does not cache (dedup is the scanner's per-scan cache); confirm a second call
	// still works and the header still carries the token, i.e. Verify is stateless and safe to call again.
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if strings.HasPrefix(r.Header.Get("Authorization"), "token ") {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	v := newTestVerifier(t, srv)
	for i := 0; i < 3; i++ {
		if got, err := v.Verify(context.Background(), "github-token", []byte("ghp_x000000000000000000000000000000000000")); err != nil || got != ports.SecretVerified {
			t.Fatalf("call %d: got %q err=%v", i, got, err)
		}
	}
	if calls != 3 {
		t.Errorf("Verify must call the provider each time (no internal cache), got %d calls", calls)
	}
}

// A secret that matched the broad sk- rule but is not a high-confidence OpenAI shape (too short, or no
// sk- prefix) must NOT be transmitted to api.openai.com, and returns unknown with no call.
func TestOpenAIEligibilityGatesForeignKeys(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	v := newTestVerifier(t, srv)

	// Ineligible: short sk- key (a foreign tool's sk- secret) → not sent.
	if got, _ := v.Verify(context.Background(), "openai-api-key", []byte("sk-short")); got != ports.SecretUnknown || called {
		t.Errorf("a short/foreign sk- key must not be sent to OpenAI (got %q, called=%v)", got, called)
	}
	// Eligible: a plausible OpenAI shape → sent and verified.
	called = false
	if got, err := v.Verify(context.Background(), "openai-api-key", []byte("sk-proj-abcdefghijklmnopqrstuvwxyz0123456789")); err != nil || got != ports.SecretVerified || !called {
		t.Errorf("a plausible OpenAI key must be sent and verified (got %q err=%v called=%v)", got, err, called)
	}
}
