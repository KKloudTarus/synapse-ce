// Package oidc provides the OpenID Connect protocol boundary for Synapse's browser BFF.
package oidc

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Config is the fixed, operator-supplied OIDC relying-party configuration.
var _ ports.OIDCProvider = (*Provider)(nil)

// There is deliberately no group-to-role mapping: provider groups never assign or change a
// Synapse role, so the adapter neither requests nor reads a groups claim.
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

// Provider executes the authorization-code OIDC protocol. It neither persists nor logs tokens.
type Provider struct {
	issuer   string
	verifier *coreoidc.IDTokenVerifier
	oauth    oauth2.Config
}

// New discovers a fixed HTTPS issuer and builds its verifier and OAuth client.
func New(ctx context.Context, cfg Config) (*Provider, error) {
	issuer, err := httpsIssuer(cfg.Issuer)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.ClientID) == "" || strings.TrimSpace(cfg.ClientSecret) == "" || strings.TrimSpace(cfg.RedirectURL) == "" {
		return nil, fmt.Errorf("OIDC client id, client secret, and redirect URL are required")
	}
	provider, err := coreoidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC issuer: %w", err)
	}
	return &Provider{
		issuer:   issuer,
		verifier: provider.Verifier(&coreoidc.Config{ClientID: cfg.ClientID}),
		oauth: oauth2.Config{
			ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, RedirectURL: cfg.RedirectURL,
			Endpoint: provider.Endpoint(), Scopes: []string{coreoidc.ScopeOpenID, "profile", "email"},
		},
	}, nil
}

// GenerateVerifier mints a PKCE code verifier with the OAuth2 library's own generator, keeping
// that dependency inside the protocol adapter.
func (p *Provider) GenerateVerifier() string { return oauth2.GenerateVerifier() }

// AuthorizationURL returns the authorization-code redirect with state, nonce, and PKCE S256.
func (p *Provider) AuthorizationURL(state, nonce, verifier string) (string, error) {
	if strings.TrimSpace(state) == "" || strings.TrimSpace(nonce) == "" || strings.TrimSpace(verifier) == "" {
		return "", fmt.Errorf("OIDC state, nonce, and PKCE verifier are required")
	}
	return p.oauth.AuthCodeURL(state,
		coreoidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
	), nil
}

// ExchangeAndVerify exchanges one authorization code and validates the resulting ID token.
func (p *Provider) ExchangeAndVerify(ctx context.Context, code, verifier, nonce string) (ports.OIDCIdentity, error) {
	if strings.TrimSpace(code) == "" || strings.TrimSpace(verifier) == "" || strings.TrimSpace(nonce) == "" {
		return ports.OIDCIdentity{}, fmt.Errorf("OIDC code, verifier, and nonce are required")
	}
	token, err := p.oauth.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return ports.OIDCIdentity{}, fmt.Errorf("exchange OIDC authorization code: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return ports.OIDCIdentity{}, fmt.Errorf("OIDC token response has no ID token")
	}
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return ports.OIDCIdentity{}, fmt.Errorf("verify OIDC ID token: %w", err)
	}
	var claims struct {
		Nonce         string          `json:"nonce"`
		AtHash        string          `json:"at_hash"`
		Email         string          `json:"email"`
		EmailVerified json.RawMessage `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return ports.OIDCIdentity{}, fmt.Errorf("decode OIDC ID token claims: %w", err)
	}
	if claims.Nonce == "" || subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(nonce)) != 1 {
		return ports.OIDCIdentity{}, fmt.Errorf("OIDC nonce mismatch")
	}
	if claims.AtHash != "" {
		if err := idToken.VerifyAccessToken(token.AccessToken); err != nil {
			return ports.OIDCIdentity{}, fmt.Errorf("verify OIDC access-token hash: %w", err)
		}
	}
	if idToken.Issuer != p.issuer || strings.TrimSpace(idToken.Subject) == "" {
		return ports.OIDCIdentity{}, fmt.Errorf("OIDC issuer or subject is invalid")
	}
	email, verifiedEmail, err := verifiedEmailClaim(claims.Email, claims.EmailVerified)
	if err != nil {
		return ports.OIDCIdentity{}, err
	}
	return ports.OIDCIdentity{Issuer: idToken.Issuer, Subject: idToken.Subject, Email: email, EmailVerified: verifiedEmail}, nil
}

// Only the JSON boolean true from the verified ID token grants email authority.
// String "true", false, null, and missing claims cannot mark a contact verified.
func verifiedEmailClaim(email string, claim json.RawMessage) (string, bool, error) {
	if string(claim) != "true" {
		return "", false, nil
	}
	address, err := user.NormalizeContactEmail(email)
	if err != nil {
		return "", false, fmt.Errorf("OIDC verified email is invalid: %w", err)
	}
	return address, true, nil
}

// NormalizeIssuer returns the exact issuer string the provider compares ID tokens against, so an
// operator-approved link and a verified callback use the same issuer value.
func NormalizeIssuer(value string) (string, error) { return httpsIssuer(value) }

func httpsIssuer(value string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(value))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("OIDC issuer must be an absolute HTTPS URL without query or fragment")
	}
	return strings.TrimRight(u.String(), "/"), nil
}
