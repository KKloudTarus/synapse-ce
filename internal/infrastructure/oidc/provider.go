// Package oidc provides the OpenID Connect protocol boundary for Synapse's browser BFF.
package oidc

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Config is the fixed, operator-supplied OIDC relying-party configuration.
var _ ports.OIDCProvider = (*Provider)(nil)

type Config struct {
	Issuer           string
	ClientID         string
	ClientSecret     string
	RedirectURL      string
	GroupRoleMapping []string
}

// Provider executes the authorization-code OIDC protocol. It neither persists nor logs tokens.
type Provider struct {
	issuer   string
	verifier *coreoidc.IDTokenVerifier
	oauth    oauth2.Config
	roles    map[string]user.Role
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
	roles, err := parseGroupRoleMapping(cfg.GroupRoleMapping)
	if err != nil {
		return nil, err
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
			Endpoint: provider.Endpoint(), Scopes: []string{coreoidc.ScopeOpenID, "profile", "groups"},
		},
		roles: roles,
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
		Nonce  string          `json:"nonce"`
		AtHash string          `json:"at_hash"`
		Groups json.RawMessage `json:"groups"`
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
	role, err := p.roleForGroups(claims.Groups)
	if err != nil {
		return ports.OIDCIdentity{}, err
	}
	if idToken.Issuer != p.issuer || strings.TrimSpace(idToken.Subject) == "" {
		return ports.OIDCIdentity{}, fmt.Errorf("OIDC issuer or subject is invalid")
	}
	return ports.OIDCIdentity{Issuer: idToken.Issuer, Subject: idToken.Subject, Role: role}, nil
}

func (p *Provider) roleForGroups(raw json.RawMessage) (user.Role, error) {
	var groups []string
	if len(raw) == 0 || string(raw) == "null" || json.Unmarshal(raw, &groups) != nil || len(groups) == 0 {
		return "", fmt.Errorf("OIDC groups claim is required")
	}
	roles := make(map[user.Role]struct{})
	seen := make(map[string]struct{}, len(groups))
	for _, group := range groups {
		group = strings.TrimSpace(group)
		if group == "" {
			return "", fmt.Errorf("OIDC groups claim is invalid")
		}
		if _, duplicate := seen[group]; duplicate {
			return "", fmt.Errorf("OIDC groups claim is ambiguous")
		}
		seen[group] = struct{}{}
		role, ok := p.roles[group]
		if !ok {
			return "", fmt.Errorf("OIDC group is not allowlisted")
		}
		roles[role] = struct{}{}
	}
	if len(roles) != 1 {
		return "", fmt.Errorf("OIDC groups map to ambiguous roles")
	}
	for role := range roles {
		return role, nil
	}
	return "", fmt.Errorf("OIDC groups claim is required")
}

func httpsIssuer(value string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(value))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("OIDC issuer must be an absolute HTTPS URL without query or fragment")
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func parseGroupRoleMapping(values []string) (map[string]user.Role, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("OIDC group-role mapping is required")
	}
	roles := make(map[string]user.Role, len(values))
	for _, value := range values {
		group, roleText, ok := strings.Cut(value, "=")
		group, roleText = strings.TrimSpace(group), strings.TrimSpace(roleText)
		role := user.Role(roleText)
		if !ok || group == "" || !role.Valid() || role == user.RoleMember {
			return nil, fmt.Errorf("OIDC group-role mapping is invalid")
		}
		if _, exists := roles[group]; exists {
			return nil, fmt.Errorf("OIDC group-role mapping has duplicate group")
		}
		roles[group] = role
	}
	return roles, nil
}

// GroupRoleMappings returns normalized mappings for validation and test inspection.
func (p *Provider) GroupRoleMappings() []string {
	result := make([]string, 0, len(p.roles))
	for group, role := range p.roles {
		result = append(result, group+"="+string(role))
	}
	sort.Strings(result)
	return result
}
