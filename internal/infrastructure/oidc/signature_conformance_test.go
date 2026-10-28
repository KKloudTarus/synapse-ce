package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

func signIdentity(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", kid))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSigningKeyRefreshVerifiesEachConcurrentTokenAndBoundsAllMisses(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "approved", Use: "sig", Algorithm: "RS256"}}})
	}))
	defer server.Close()
	keys := &boundedKeySet{client: server.Client(), url: server.URL, now: time.Now, cooldown: time.Minute}
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := range 16 {
		wg.Go(func() {
			claims := map[string]any{"subject": i}
			token := signIdentity(t, key, "approved", claims)
			payload, err := keys.VerifySignature(t.Context(), token)
			if err == nil {
				var got map[string]int
				err = json.Unmarshal(payload, &got)
				if err == nil && got["subject"] != i {
					t.Errorf("token %d got claims %v", i, got)
				}
			}
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if requests.Load() != 1 {
		t.Fatalf("JWKS requests = %d", requests.Load())
	}
	attacker, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, kid := range []string{"approved", "unknown", "another"} {
		if _, err := keys.VerifySignature(t.Context(), signIdentity(t, attacker, kid, map[string]any{"sub": "attack"})); err == nil {
			t.Fatal("invalid signature accepted")
		}
	}
	if requests.Load() != 1 {
		t.Fatalf("invalid signatures caused %d fetches", requests.Load())
	}
}

func TestTLSProviderVerifiesSingleAudienceSignedIdentityAndNonce(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer, raw string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "code_challenge_methods_supported": []string{"S256"}})
		case "/keys":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "approved", Use: "sig", Algorithm: "RS256"}}})
		case "/token":
			if err := r.ParseForm(); err != nil || r.Form.Get("code_verifier") != "verifier" {
				t.Error("PKCE verifier not submitted")
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "id_token": raw})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	issuer = server.URL
	now := time.Now().UTC().Truncate(time.Second)
	raw = signIdentity(t, key, "approved", map[string]any{"iss": issuer, "sub": "approved-person", "aud": "client", "exp": now.Add(time.Hour).Unix(), "iat": now.Unix(), "auth_time": now.Unix(), "nonce": "nonce", "email": "person@example.com", "email_verified": true})
	provider := newProvider(Config{Issuer: issuer, ClientID: "client", ClientSecret: "secret", RedirectURL: "https://synapse.example/callback"}, issuer, server.Client())
	identity, err := provider.ExchangeAndVerifyWithMaxAge(t.Context(), "code", "verifier", "nonce", 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Subject != "approved-person" || !identity.EmailVerified || !identity.AuthenticatedAt.Equal(now) {
		t.Fatalf("identity = %+v", identity)
	}
	if _, err := provider.ExchangeAndVerifyWithMaxAge(t.Context(), "code", "verifier", "other-nonce", 15*time.Minute); err == nil {
		t.Fatal("mismatched nonce accepted")
	}
}

func TestTLSProviderEnforcesConfiguredAuth0OrganizationClaim(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer, raw string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "code_challenge_methods_supported": []string{"S256"}})
		case "/keys":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "approved", Use: "sig", Algorithm: "RS256"}}})
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "id_token": raw})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	issuer = server.URL
	now := time.Now().UTC().Truncate(time.Second)

	makeToken := func(include bool, organization any) string {
		claims := map[string]any{"iss": issuer, "sub": "approved-person", "aud": "client", "exp": now.Add(time.Hour).Unix(), "iat": now.Unix(), "nonce": "nonce"}
		if include {
			claims["org_id"] = organization
		}
		return signIdentity(t, key, "approved", claims)
	}
	configured := newProvider(Config{Issuer: issuer, ClientID: "client", ClientSecret: "secret", RedirectURL: "https://synapse.example/callback", Auth0OrganizationID: "org_CaseSensitive"}, issuer, server.Client())
	for _, tc := range []struct {
		name    string
		include bool
		claim   any
		wantErr bool
	}{
		{name: "exact signed claim", include: true, claim: "org_CaseSensitive"},
		{name: "wrong organization with same issuer client and subject", include: true, claim: "org_Other", wantErr: true},
		{name: "case changed organization", include: true, claim: "org_casesensitive", wantErr: true},
		{name: "missing claim", wantErr: true},
		{name: "null claim", include: true, claim: nil, wantErr: true},
		{name: "non string claim", include: true, claim: 7, wantErr: true},
		{name: "empty claim", include: true, claim: "", wantErr: true},
		{name: "malformed claim", include: true, claim: "organization_CaseSensitive", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw = makeToken(tc.include, tc.claim)
			_, err := configured.ExchangeAndVerify(t.Context(), "code", "verifier", "nonce")
			if (err != nil) != tc.wantErr {
				t.Fatalf("ExchangeAndVerify() error = %v, wantErr %t", err, tc.wantErr)
			}
		})
	}

	unconfigured := newProvider(Config{Issuer: issuer, ClientID: "client", ClientSecret: "secret", RedirectURL: "https://synapse.example/callback"}, issuer, server.Client())
	raw = makeToken(false, nil)
	if _, err := unconfigured.ExchangeAndVerify(t.Context(), "code", "verifier", "nonce"); err != nil {
		t.Fatalf("ordinary tenant token rejected: %v", err)
	}
	raw = makeToken(true, "org_Unsolicited")
	if _, err := unconfigured.ExchangeAndVerify(t.Context(), "code", "verifier", "nonce"); err == nil {
		t.Fatal("unconfigured provider accepted unsolicited org_id")
	}
}

func TestCappedBodyRejectsUnknownLengthOverflow(t *testing.T) {
	body := &limitedReadCloser{ReadCloser: io.NopCloser(strings.NewReader(strings.Repeat("x", int(maxOIDCResponseBytes)+1))), remaining: maxOIDCResponseBytes}
	if _, err := io.ReadAll(body); err == nil {
		t.Fatal("unknown-length overflow accepted")
	}
}

func TestEntraSigningKeysAreFilteredIndividuallyBeforeCaching(t *testing.T) {
	approved, _ := rsa.GenerateKey(rand.Reader, 2048)
	foreign, _ := rsa.GenerateKey(rand.Reader, 2048)
	encodeKey := func(key *rsa.PublicKey, issuer any) map[string]any {
		b, _ := json.Marshal(jose.JSONWebKey{Key: key, KeyID: "duplicate", Use: "sig", Algorithm: "RS256"})
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		if issuer != nil {
			m["issuer"] = issuer
		}
		return m
	}
	for _, allowedIssuer := range []string{entraTestOrigin + "/v2.0", "https://login.microsoftonline.com/{tenantid}/v2.0"} {
		for _, foreignIssuer := range []any{"https://evil.example/v2.0", 7, nil} {
			for _, reverse := range []bool{false, true} {
				entries := []map[string]any{encodeKey(&approved.PublicKey, allowedIssuer), encodeKey(&foreign.PublicKey, foreignIssuer)}
				if reverse {
					entries[0], entries[1] = entries[1], entries[0]
				}
				body, _ := json.Marshal(map[string]any{"keys": entries})
				keys := &boundedKeySet{client: &http.Client{Transport: responseTransport{response: &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(body)))}}}, url: "https://example.com/keys", now: time.Now, cooldown: time.Minute, entraIssuer: entraTestOrigin + "/v2.0"}
				for _, tc := range []struct {
					key *rsa.PrivateKey
					ok  bool
				}{{approved, true}, {foreign, false}, {approved, true}, {foreign, false}} {
					_, err := keys.VerifySignature(t.Context(), signIdentity(t, tc.key, "duplicate", map[string]any{"iss": entraTestOrigin + "/v2.0", "tid": entraTestTenant}))
					if (err == nil) != tc.ok {
						t.Fatalf("allowed=%s foreign=%v reversed=%t success=%t err=%v", allowedIssuer, foreignIssuer, reverse, tc.ok, err)
					}
				}
			}
		}
	}
}

func TestEntraSignedTokenRequiresMatchingDirectory(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk, _ := json.Marshal(jose.JSONWebKey{Key: &key.PublicKey, KeyID: "approved", Use: "sig", Algorithm: "RS256"})
	var entry map[string]any
	_ = json.Unmarshal(jwk, &entry)
	entry["issuer"] = entraTestOrigin + "/v2.0"
	keys, _ := json.Marshal(map[string]any{"keys": []any{entry}})
	issuer := entraTestOrigin + "/v2.0"
	for _, mode := range []string{"", "common", "organizations"} {
		t.Run("mode="+mode, func(t *testing.T) {
			metadata := entraDiscoveryMetadata()
			keyURL := entraTestOrigin + "/discovery/v2.0/keys"
			if mode != "" {
				base := "https://login.microsoftonline.com/" + mode
				metadata["issuer"] = "https://login.microsoftonline.com/{tenantid}/v2.0"
				metadata["authorization_endpoint"] = base + "/oauth2/v2.0/authorize"
				metadata["token_endpoint"] = base + "/oauth2/v2.0/token"
				keyURL = base + "/discovery/v2.0/keys"
				metadata["jwks_uri"] = keyURL
			}
			metadataJSON, _ := json.Marshal(metadata)
			var raw string
			client := &http.Client{Transport: entraFixtureTransport(func(r *http.Request) (*http.Response, error) {
				body := string(metadataJSON)
				switch r.URL.String() {
				case keyURL:
					body = string(keys)
				case entraTestOrigin + "/oauth2/v2.0/token":
					b, _ := json.Marshal(map[string]any{"access_token": "access", "token_type": "Bearer", "id_token": raw})
					body = string(b)
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})}
			p := newProvider(Config{Issuer: issuer, EntraDiscoveryMode: mode, ClientID: "client", ClientSecret: "secret", RedirectURL: "https://synapse.example/callback"}, issuer, client)
			for _, tc := range []struct {
				name        string
				tid         any
				include, ok bool
			}{{"correct", entraTestTenant, true, true}, {"wrong", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", true, false}, {"missing", nil, false, false}, {"null", nil, true, false}, {"number", 7, true, false}, {"empty", "", true, false}} {
				t.Run(tc.name, func(t *testing.T) {
					claims := map[string]any{"iss": issuer, "sub": "person", "aud": "client", "exp": time.Now().Add(time.Hour).Unix(), "nonce": "nonce"}
					if tc.include {
						claims["tid"] = tc.tid
					}
					raw = signIdentity(t, key, "approved", claims)
					_, err := p.ExchangeAndVerify(t.Context(), "code", "verifier", "nonce")
					if (err == nil) != tc.ok {
						t.Fatalf("error=%v", err)
					}
				})
			}
		})
	}
}

func TestEntraKeyRefreshRetainsScopeAndOriginalKeyCountLimit(t *testing.T) {
	approved, _ := rsa.GenerateKey(rand.Reader, 2048)
	foreign, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyEntry := func(key *rsa.PublicKey, issuer string) map[string]any {
		b, _ := json.Marshal(jose.JSONWebKey{Key: key, KeyID: "key", Use: "sig"})
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		m["issuer"] = issuer
		return m
	}
	approvedEntry := keyEntry(&approved.PublicKey, entraTestOrigin+"/v2.0")
	foreignEntry := keyEntry(&foreign.PublicKey, "https://foreign.example/v2.0")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	entries := []map[string]any{approvedEntry, foreignEntry}
	requests := 0
	client := &http.Client{Transport: entraFixtureTransport(func(r *http.Request) (*http.Response, error) {
		requests++
		b, _ := json.Marshal(map[string]any{"keys": entries})
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(b))), Request: r}, nil
	})}
	keys := &boundedKeySet{client: client, url: "https://example.com/keys", now: func() time.Time { return now }, cooldown: time.Second, entraIssuer: entraTestOrigin + "/v2.0"}
	valid := signIdentity(t, approved, "key", map[string]any{"sub": "person"})
	invalid := signIdentity(t, foreign, "key", map[string]any{"sub": "person"})
	if _, err := keys.VerifySignature(t.Context(), valid); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if _, err := keys.VerifySignature(t.Context(), invalid); err == nil {
		t.Fatal("foreign key accepted after refresh")
	}
	if requests != 2 {
		t.Fatalf("requests=%d", requests)
	}
	if _, err := keys.VerifySignature(t.Context(), invalid); err == nil {
		t.Fatal("foreign key accepted from cache")
	}
	entries = make([]map[string]any, 65)
	for i := range entries {
		entries[i] = foreignEntry
	}
	entries[0] = approvedEntry
	now = now.Add(2 * time.Second)
	if _, err := keys.VerifySignature(t.Context(), invalid); err == nil || !strings.Contains(err.Error(), "exceeds 64 keys") {
		t.Fatalf("oversized key set error: %v", err)
	}
	if requests != 3 {
		t.Fatalf("requests=%d", requests)
	}
}
