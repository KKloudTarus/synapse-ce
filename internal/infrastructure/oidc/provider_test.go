package oidc

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type responseTransport struct{ response *http.Response }

func (t responseTransport) RoundTrip(*http.Request) (*http.Response, error) { return t.response, nil }

func TestHTTPSIssuer(t *testing.T) {
	for _, input := range []string{"http://issuer.example", "https://", "https://issuer.example/?x=1", "https://issuer.example/#x"} {
		if _, err := httpsIssuer(input); err == nil {
			t.Errorf("httpsIssuer(%q) succeeded", input)
		}
	}
	got, err := httpsIssuer("https://issuer.example/")
	if err != nil || got != "https://issuer.example" {
		t.Fatalf("httpsIssuer() = %q, %v", got, err)
	}
}

func TestVerifiedAuthTimeRequiresPresentFreshNonFutureIntegerValue(t *testing.T) {
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	for _, raw := range []json.RawMessage{nil, []byte(`null`), []byte(`"1"`), []byte(`1.5`), []byte(`1760000001`)} {
		if _, err := verifiedAuthTime(raw, now, time.Hour); err == nil {
			t.Fatalf("verifiedAuthTime(%s) succeeded", raw)
		}
	}
	got, err := verifiedAuthTime([]byte(`1760000000`), time.Unix(1760000001, 0), time.Hour)
	if err != nil || !got.Equal(time.Unix(1760000000, 0).UTC()) {
		t.Fatalf("verifiedAuthTime() = %v, %v", got, err)
	}
}

func TestVerifyAuthorizedPartyRejectsAmbiguousOrForeignParty(t *testing.T) {
	for _, tc := range []struct {
		audience []string
		azp      string
		wantErr  bool
	}{
		{[]string{"client"}, "", false},
		{[]string{"client", "other"}, "client", false},
		{[]string{"client", "other"}, "", true},
		{[]string{"client"}, "other", true},
	} {
		if err := verifyAuthorizedParty(tc.audience, tc.azp, "client"); (err != nil) != tc.wantErr {
			t.Errorf("verifyAuthorizedParty(%v, %q) = %v", tc.audience, tc.azp, err)
		}
	}
}

func TestSupportsS256RefusesMissingOrPlainOnlyDiscovery(t *testing.T) {
	if supportsS256(nil) || supportsS256([]string{"plain"}) {
		t.Fatal("discovery without S256 was accepted")
	}
	if !supportsS256([]string{"plain", "S256"}) {
		t.Fatal("discovery S256 support was rejected")
	}
}

func TestSafeClientDisablesProxyRedirectAndPrivateDestinations(t *testing.T) {
	client := newSafeClient()
	if client.Timeout <= 0 || client.CheckRedirect == nil {
		t.Fatal("safe client lacks bounds")
	}
	if err := client.CheckRedirect(&http.Request{}, nil); err != http.ErrUseLastResponse {
		t.Fatalf("redirect policy = %v", err)
	}
	if _, err := resolvePublic(t.Context(), "127.0.0.1"); err == nil {
		t.Fatal("loopback destination was accepted")
	}
	if _, err := resolvePublic(t.Context(), "10.0.0.1"); err == nil {
		t.Fatal("private destination was accepted")
	}
}

func TestCappedTransportRejectsCompressedAndOversizedResponses(t *testing.T) {
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://issuer.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, response := range []*http.Response{
		{Header: http.Header{"Content-Encoding": []string{"gzip"}}, Body: io.NopCloser(strings.NewReader("compressed"))},
		{Header: make(http.Header), ContentLength: maxOIDCResponseBytes + 1, Body: io.NopCloser(strings.NewReader("large"))},
	} {
		if _, err := (cappedTransport{next: responseTransport{response: response}}).RoundTrip(request); err == nil {
			t.Fatal("unsafe response was accepted")
		}
	}
}

func TestTLSProviderFixtureRequiresS256AndSendsPKCEAndMaxAge(t *testing.T) {
	var issuer string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "code_challenge_methods_supported": []string{"S256"}})
		case "/token":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()
	issuer = server.URL
	provider := newProvider(Config{Issuer: issuer, ClientID: "client", ClientSecret: "secret", RedirectURL: "https://synapse.example/callback"}, issuer, server.Client())
	authorizationURL, err := provider.AuthorizationURLWithMaxAge(t.Context(), "state", "nonce", "verifier", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(authorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") == "" || query.Get("nonce") != "nonce" || query.Get("max_age") != "600" {
		t.Fatalf("authorization query = %v", query)
	}
	if _, err := provider.ExchangeAndVerify(t.Context(), "bad", "verifier", "nonce"); err == nil {
		t.Fatal("token-exchange failure was accepted")
	}
}

func TestProviderDiscoveryCallerCancellationDoesNotHoldTheDiscoveryWorker(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(started) })
		<-release
		_ = json.NewEncoder(w).Encode(discoveryMetadata(issuer))
	}))
	defer server.Close()
	issuer = server.URL
	provider := newProvider(Config{Issuer: issuer, ClientID: "client", ClientSecret: "secret", RedirectURL: "https://synapse.example/callback"}, issuer, server.Client())

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := provider.ensure(ctx)
		result <- err
	}()
	<-started
	cancel()
	if err := <-result; err != context.Canceled {
		t.Fatalf("canceled discovery wait=%v, want context canceled", err)
	}
	close(release)
	if _, err := provider.ensure(t.Context()); err != nil {
		t.Fatalf("bounded discovery did not complete after initiating caller canceled: %v", err)
	}
}

func TestProviderDiscoveryCoalescesConcurrentCallers(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var requests atomic.Int32
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		close(started)
		<-release
		_ = json.NewEncoder(w).Encode(discoveryMetadata(issuer))
	}))
	defer server.Close()
	issuer = server.URL
	provider := newProvider(Config{Issuer: issuer, ClientID: "client", ClientSecret: "secret", RedirectURL: "https://synapse.example/callback"}, issuer, server.Client())

	first := make(chan error, 1)
	go func() {
		_, err := provider.ensure(t.Context())
		first <- err
	}()
	<-started
	const callers = 4
	entered := make(chan struct{}, callers)
	results := make(chan error, callers)
	for range callers {
		go func() {
			entered <- struct{}{}
			_, err := provider.ensure(t.Context())
			results <- err
		}()
	}
	for range callers {
		<-entered
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	for range callers {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("discovery requests=%d, want one coalesced request", got)
	}
}

func TestProviderDiscoveryFailureCooldownSuppressesOutageRetries(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	provider := newProvider(Config{Issuer: server.URL, ClientID: "client", ClientSecret: "secret", RedirectURL: "https://synapse.example/callback"}, server.URL, server.Client())
	provider.now = func() time.Time { return now }
	if _, err := provider.ensure(t.Context()); err == nil {
		t.Fatal("unavailable discovery succeeded")
	}
	if _, err := provider.ensure(t.Context()); err == nil || !strings.Contains(err.Error(), "cooling down") {
		t.Fatalf("immediate discovery retry=%v, want cooldown error", err)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("outage requests=%d, want one", got)
	}
	now = now.Add(discoveryFailureCooldown)
	if _, err := provider.ensure(t.Context()); err == nil {
		t.Fatal("retry after cooldown succeeded against outage")
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("post-cooldown outage requests=%d, want two", got)
	}
}

func discoveryMetadata(issuer string) map[string]any {
	return map[string]any{
		"issuer":                           issuer,
		"authorization_endpoint":           "https://issuer.example/authorize",
		"token_endpoint":                   "https://issuer.example/token",
		"jwks_uri":                         "https://issuer.example/keys",
		"code_challenge_methods_supported": []string{"S256"},
	}
}

// An operator-approved link stores the issuer exactly as the provider compares it, so the
// normalization the link command uses must be the verifier's own.
func TestNormalizeIssuerMatchesVerifierForm(t *testing.T) {
	for input, want := range map[string]string{
		"https://issuer.example":        "https://issuer.example",
		"https://issuer.example/":       "https://issuer.example",
		" https://issuer.example/realm": "https://issuer.example/realm",
	} {
		got, err := NormalizeIssuer(input)
		if err != nil || got != want {
			t.Errorf("NormalizeIssuer(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	if _, err := NormalizeIssuer("http://issuer.example"); err == nil {
		t.Fatal("a non-HTTPS issuer must be rejected")
	}
}

func TestVerifiedEmailClaimRequiresBooleanTrue(t *testing.T) {
	for _, claim := range []json.RawMessage{nil, []byte(`null`), []byte(`false`), []byte(`"true"`), []byte(`1`)} {
		email, verified, err := verifiedEmailClaim("alice@example.com", claim)
		if err != nil || verified || email != "" {
			t.Fatalf("claim %s imported %q/%t: %v", claim, email, verified, err)
		}
	}
	email, verified, err := verifiedEmailClaim("Alice@EXAMPLE.COM", []byte(`true`))
	if err != nil || !verified || email != "Alice@example.com" {
		t.Fatalf("verified claim = %q/%t: %v", email, verified, err)
	}
	if _, _, err := verifiedEmailClaim("bad\r\nBcc: x@example.com", []byte(`true`)); err == nil {
		t.Fatal("accepted unsafe verified email")
	}
}
