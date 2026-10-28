package oidc

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const entraTestTenant = "11111111-2222-3333-4444-555555555555"
const entraTestOrigin = "https://login.microsoftonline.com/" + entraTestTenant

func entraDiscoveryMetadata() map[string]any {
	return map[string]any{
		"issuer":                 entraTestOrigin + "/v2.0",
		"authorization_endpoint": entraTestOrigin + "/oauth2/v2.0/authorize",
		"token_endpoint":         entraTestOrigin + "/oauth2/v2.0/token",
		"jwks_uri":               entraTestOrigin + "/discovery/v2.0/keys",
	}
}

func TestEntraDiscoveryAllowsOnlyCanonicalOmittedPKCEMetadata(t *testing.T) {
	for _, tc := range []struct {
		name   string
		field  string
		value  any
		wantOK bool
	}{
		{name: "canonical omission", wantOK: true},
		{name: "advertised S256", field: "code_challenge_methods_supported", value: []string{"S256"}, wantOK: true},
		{name: "explicit null", field: "code_challenge_methods_supported", value: nil},
		{name: "empty list", field: "code_challenge_methods_supported", value: []string{}},
		{name: "plain only", field: "code_challenge_methods_supported", value: []string{"plain"}},
		{name: "malformed capability", field: "code_challenge_methods_supported", value: "S256"},
		{name: "unfamiliar issuer", field: "issuer", value: "https://issuer.example/v2.0"},
		{name: "lookalike host", field: "issuer", value: "https://login.microsoftonline.com.attacker.example/" + entraTestTenant + "/v2.0"},
		{name: "common tenant", field: "issuer", value: "https://login.microsoftonline.com/common/v2.0"},
		{name: "organizations tenant", field: "issuer", value: "https://login.microsoftonline.com/organizations/v2.0"},
		{name: "malformed tenant", field: "issuer", value: "https://login.microsoftonline.com/zzzzzzzz-2222-3333-4444-555555555555/v2.0"},
		{name: "issuer trailing slash", field: "issuer", value: entraTestOrigin + "/v2.0/"},
		{name: "issuer port", field: "issuer", value: "https://login.microsoftonline.com:443/" + entraTestTenant + "/v2.0"},
		{name: "encoded issuer path", field: "issuer", value: entraTestOrigin + "/v%32.0"},
		{name: "foreign authorize tenant", field: "authorization_endpoint", value: "https://login.microsoftonline.com/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/oauth2/v2.0/authorize"},
		{name: "foreign token tenant", field: "token_endpoint", value: "https://login.microsoftonline.com/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/oauth2/v2.0/token"},
		{name: "common keys", field: "jwks_uri", value: "https://login.microsoftonline.com/common/discovery/v2.0/keys"},
		{name: "token query", field: "token_endpoint", value: entraTestOrigin + "/oauth2/v2.0/token?other=1"},
		{name: "keys trailing slash", field: "jwks_uri", value: entraTestOrigin + "/discovery/v2.0/keys/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			metadata := entraDiscoveryMetadata()
			if tc.field != "" {
				metadata[tc.field] = tc.value
			}
			body, err := json.Marshal(metadata)
			if err != nil {
				t.Fatal(err)
			}
			issuer := metadata["issuer"].(string)
			client := &http.Client{Transport: responseTransport{response: &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(body)))}}}
			provider := newProvider(Config{Issuer: issuer, ClientID: "client", ClientSecret: "secret", RedirectURL: "https://synapse.example/callback"}, issuer, client)
			authorization, err := provider.AuthorizationURLWithMaxAge(t.Context(), "state", "nonce", "verifier", 0)
			if (err == nil) != tc.wantOK {
				t.Fatalf("authorization success=%t, want %t: %v", err == nil, tc.wantOK, err)
			}
			if !tc.wantOK && authorization != "" {
				t.Fatal("rejected discovery produced an authorization URL")
			}
		})
	}
}

type entraFixtureTransport func(*http.Request) (*http.Response, error)

func (f entraFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestEntraOmittedMetadataPreservesS256ChallengeAndExchangeVerifier(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	metadata := entraDiscoveryMetadata()
	body, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	exchanges := 0
	client := &http.Client{Transport: entraFixtureTransport(func(r *http.Request) (*http.Response, error) {
		responseBody := string(body)
		status := http.StatusOK
		if r.URL.String() == metadata["token_endpoint"] {
			exchanges++
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if r.Method != http.MethodPost || r.Form.Get("code_verifier") != verifier || r.Form.Get("code") != "synthetic-code" {
				t.Fatal("exchange did not carry the bound PKCE verifier and code")
			}
			status, responseBody = http.StatusBadRequest, `{"error":"invalid_grant"}`
		} else if r.URL.String() != entraTestOrigin+"/v2.0/.well-known/openid-configuration" {
			t.Fatalf("unexpected request: %s", r.URL)
		}
		return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(responseBody)), Request: r}, nil
	})}
	issuer := metadata["issuer"].(string)
	provider := newProvider(Config{Issuer: issuer, ClientID: "client", ClientSecret: "secret", RedirectURL: "https://synapse.example/callback"}, issuer, client)
	authorization, err := provider.AuthorizationURLWithMaxAge(t.Context(), "state", "nonce", verifier, 0)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(authorization)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" || q.Get("nonce") != "nonce" || q.Get("state") != "state" {
		t.Fatal("authorization did not preserve RFC 7636 S256 challenge, state and nonce")
	}
	if _, err := provider.ExchangeAndVerify(t.Context(), "synthetic-code", verifier, "nonce"); err == nil || exchanges == 0 {
		t.Fatalf("exchange must reach the provider with PKCE and reject its denial: attempts=%d err=%v", exchanges, err)
	}
}
