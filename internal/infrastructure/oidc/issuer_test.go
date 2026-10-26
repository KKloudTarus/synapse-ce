package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

func TestProviderPreservesExactIssuerDuringDiscoveryAndTokenVerification(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", "/", "/realm", "/realm/", "/realm//"} {
		t.Run(suffix, func(t *testing.T) {
			var issuer, tokenIssuer, origin string
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration"):
					_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": origin + "/authorize", "token_endpoint": origin + "/token", "jwks_uri": origin + "/keys", "code_challenge_methods_supported": []string{"S256"}})
				case r.URL.Path == "/keys":
					_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "approved", Use: "sig", Algorithm: "RS256"}}})
				case r.URL.Path == "/token":
					now := time.Now().UTC()
					raw := signIdentity(t, key, "approved", map[string]any{"iss": tokenIssuer, "sub": "approved-person", "aud": "client", "exp": now.Add(time.Hour).Unix(), "iat": now.Unix(), "nonce": "nonce"})
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "id_token": raw})
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			origin = server.URL
			issuer = origin + suffix
			tokenIssuer = issuer
			normalized, err := httpsIssuer(issuer)
			if err != nil {
				t.Fatal(err)
			}
			provider := newProvider(Config{Issuer: issuer, ClientID: "client", ClientSecret: "secret", RedirectURL: "https://synapse.example/callback"}, normalized, server.Client())
			identity, err := provider.ExchangeAndVerify(t.Context(), "code", "verifier", "nonce")
			if err != nil || identity.Issuer != issuer {
				t.Fatalf("exact issuer %q: identity=%+v err=%v", issuer, identity, err)
			}
			if strings.HasSuffix(issuer, "/") {
				tokenIssuer = strings.TrimSuffix(issuer, "/")
			} else {
				tokenIssuer = issuer + "/"
			}
			if _, err := provider.ExchangeAndVerify(t.Context(), "code", "verifier", "nonce"); err == nil {
				t.Fatal("opposite trailing-slash token issuer accepted")
			}
		})
	}
}

func TestDiscoveryRejectsTrailingSlashIssuerMismatch(t *testing.T) {
	for _, suffix := range []string{"", "/", "/realm", "/realm/"} {
		t.Run(suffix, func(t *testing.T) {
			var advertised string
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(discoveryMetadata(advertised))
			}))
			defer server.Close()
			issuer := server.URL + suffix
			if strings.HasSuffix(issuer, "/") {
				advertised = strings.TrimSuffix(issuer, "/")
			} else {
				advertised = issuer + "/"
			}
			provider := newProvider(Config{ClientID: "client", ClientSecret: "secret", RedirectURL: "https://synapse.example/callback"}, issuer, server.Client())
			if _, err := provider.AuthorizationURL("state", "nonce", "verifier"); err == nil {
				t.Fatal("opposite trailing-slash discovery issuer accepted")
			}
		})
	}
}
