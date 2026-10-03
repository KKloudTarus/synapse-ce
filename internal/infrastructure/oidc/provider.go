// Package oidc provides the OpenID Connect protocol boundary for Synapse's browser BFF.
package oidc

import (
	"context"
	"crypto"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"

	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.OIDCProvider = (*Provider)(nil)
var _ ports.OIDCAuthentication = (*Provider)(nil)

// Config is an exact, operator-approved OIDC connection. ConnectionRevision is
// carried by callers that persist connection revisions; this adapter never
// selects a provider or derives an issuer from untrusted request input.
type Config struct {
	Issuer             string
	ClientID           string
	ClientSecret       string
	RedirectURL        string
	ConnectionRevision int64
}

type providerState struct {
	verifier *coreoidc.IDTokenVerifier
	oauth    oauth2.Config
}

const (
	unknownKeyRefreshCooldown = 5 * time.Second
	discoveryFailureCooldown  = 5 * time.Second
	discoveryTimeout          = 15 * time.Second
)

// Provider discovers metadata only when it is first used. A provider outage
// therefore cannot prevent API startup.
type Provider struct {
	issuer string
	cfg    Config
	client *http.Client
	mu     sync.Mutex
	state  *providerState
	now    func() time.Time

	discovery         chan struct{}
	discoveryErr      error
	nextDiscoveryTime time.Time
	discoveryTimeout  time.Duration
}

// New validates a fixed connection without doing I/O. Discovery is deliberately lazy.
func New(_ context.Context, cfg Config) (*Provider, error) {
	issuer, err := httpsIssuer(cfg.Issuer)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.ClientID) == "" || strings.TrimSpace(cfg.ClientSecret) == "" || strings.TrimSpace(cfg.RedirectURL) == "" {
		return nil, fmt.Errorf("OIDC client id, client secret, and redirect URL are required")
	}
	if _, err := httpsEndpoint(cfg.RedirectURL); err != nil {
		return nil, fmt.Errorf("OIDC redirect URL: %w", err)
	}
	return newProvider(cfg, issuer, newSafeClient()), nil
}

// newProvider is an unexported conformance-test seam. Production construction
// always uses newSafeClient, which forbids loopback and private destinations.
func newProvider(cfg Config, issuer string, client *http.Client) *Provider {
	return &Provider{issuer: issuer, cfg: cfg, client: client, now: time.Now, discoveryTimeout: discoveryTimeout}
}

func (p *Provider) ensure(ctx context.Context) (*providerState, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p.mu.Lock()
		if p.state != nil {
			state := p.state
			p.mu.Unlock()
			return state, nil
		}
		if p.now().Before(p.nextDiscoveryTime) {
			err := p.discoveryErr
			p.mu.Unlock()
			return nil, fmt.Errorf("OIDC discovery is cooling down: %w", err)
		}
		if wait := p.discovery; wait != nil {
			p.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-wait:
				continue
			}
		}
		wait := make(chan struct{})
		p.discovery = wait
		p.mu.Unlock()
		// Discovery owns a bounded context rather than the initiating request context. A canceled
		// caller stops waiting immediately, while its shared request still ends at this deadline.
		go p.discoverAsync(wait)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-wait:
		}
	}
}

func (p *Provider) discoverAsync(done chan struct{}) {
	ctx, cancel := context.WithTimeout(context.Background(), p.discoveryTimeout)
	state, err := p.discover(coreoidc.ClientContext(ctx, p.client))
	cancel()
	p.mu.Lock()
	if err == nil {
		p.state = state
		p.discoveryErr = nil
		p.nextDiscoveryTime = time.Time{}
	} else {
		p.discoveryErr = err
		p.nextDiscoveryTime = p.now().Add(discoveryFailureCooldown)
	}
	p.discovery = nil
	close(done)
	p.mu.Unlock()
}

func (p *Provider) discover(ctx context.Context) (*providerState, error) {
	provider, err := coreoidc.NewProvider(ctx, p.issuer)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC issuer: %w", err)
	}
	var metadata struct {
		Issuer                        string   `json:"issuer"`
		AuthorizationEndpoint         string   `json:"authorization_endpoint"`
		TokenEndpoint                 string   `json:"token_endpoint"`
		JWKSURI                       string   `json:"jwks_uri"`
		CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
	}
	if err := provider.Claims(&metadata); err != nil {
		return nil, fmt.Errorf("decode OIDC discovery: %w", err)
	}
	if metadata.Issuer != p.issuer {
		return nil, fmt.Errorf("OIDC discovery issuer mismatch")
	}
	if _, err := httpsEndpoint(metadata.AuthorizationEndpoint); err != nil {
		return nil, fmt.Errorf("OIDC authorization endpoint: %w", err)
	}
	if _, err := httpsEndpoint(metadata.TokenEndpoint); err != nil {
		return nil, fmt.Errorf("OIDC token endpoint: %w", err)
	}
	if _, err := httpsEndpoint(metadata.JWKSURI); err != nil {
		return nil, fmt.Errorf("OIDC JWKS endpoint: %w", err)
	}
	if !supportsS256(metadata.CodeChallengeMethodsSupported) {
		return nil, fmt.Errorf("OIDC provider does not advertise PKCE S256 support")
	}
	keys := &boundedKeySet{client: p.client, url: metadata.JWKSURI, now: p.now, cooldown: unknownKeyRefreshCooldown}
	return &providerState{verifier: coreoidc.NewVerifier(p.issuer, keys, &coreoidc.Config{ClientID: p.cfg.ClientID}), oauth: oauth2.Config{ClientID: p.cfg.ClientID, ClientSecret: p.cfg.ClientSecret, RedirectURL: p.cfg.RedirectURL, Endpoint: provider.Endpoint(), Scopes: []string{coreoidc.ScopeOpenID, "profile", "email"}}}, nil
}

// boundedKeySet coalesces metadata refreshes, never token verification results. Every
// token is verified independently against a bounded key snapshot. All cache misses,
// including invalid signatures with a known kid, share the refresh cooldown.
type boundedKeySet struct {
	client             *http.Client
	url                string
	now                func() time.Time
	cooldown           time.Duration
	mu                 sync.Mutex
	nextUnknownRefresh time.Time
	keys               []jose.JSONWebKey
	refresh            singleflight.Group
}

func (k *boundedKeySet) VerifySignature(ctx context.Context, rawIDToken string) ([]byte, error) {
	kid, err := tokenKeyID(rawIDToken)
	if err != nil {
		return nil, err
	}
	if payload, err := k.verifyCached(ctx, kid, rawIDToken); err == nil {
		return payload, nil
	}
	refreshed := k.refresh.DoChan("jwks", func() (any, error) {
		k.mu.Lock()
		now := k.now()
		if now.Before(k.nextUnknownRefresh) {
			k.mu.Unlock()
			return nil, fmt.Errorf("OIDC unknown key refresh is cooling down")
		}
		k.nextUnknownRefresh = now.Add(k.cooldown)
		k.mu.Unlock()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url, nil)
		if err != nil {
			return nil, err
		}
		response, err := k.client.Do(request)
		if err != nil {
			return nil, fmt.Errorf("fetch OIDC signing keys: %w", err)
		}
		defer func() { _ = response.Body.Close() }()
		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("OIDC signing keys returned status %d", response.StatusCode)
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, maxOIDCResponseBytes+1))
		if err != nil || int64(len(body)) > maxOIDCResponseBytes {
			return nil, fmt.Errorf("OIDC signing key response is unavailable or too large")
		}
		var set jose.JSONWebKeySet
		if err := json.Unmarshal(body, &set); err != nil || len(set.Keys) == 0 || len(set.Keys) > 64 {
			return nil, fmt.Errorf("OIDC signing key set is invalid or exceeds 64 keys")
		}
		for _, key := range set.Keys {
			if !key.IsPublic() || !key.Valid() || len(key.KeyID) > 256 {
				return nil, fmt.Errorf("OIDC signing key set contains an invalid public key")
			}
		}
		k.mu.Lock()
		k.keys = set.Keys
		k.mu.Unlock()
		return nil, nil
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-refreshed:
		if result.Err != nil {
			return nil, result.Err
		}
	}
	return k.verifyCached(ctx, kid, rawIDToken)
}

func (k *boundedKeySet) verifyCached(ctx context.Context, kid, raw string) ([]byte, error) {
	k.mu.Lock()
	var publicKeys []crypto.PublicKey
	for _, key := range k.keys {
		if key.KeyID == kid && (key.Use == "" || key.Use == "sig") {
			publicKeys = append(publicKeys, key.Key)
		}
	}
	k.mu.Unlock()
	return (&coreoidc.StaticKeySet{PublicKeys: publicKeys}).VerifySignature(ctx, raw)
}

func tokenKeyID(raw string) (string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("OIDC ID token is malformed")
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("decode OIDC ID token header: %w", err)
	}
	var parsed struct {
		KeyID string `json:"kid"`
	}
	if err := json.Unmarshal(header, &parsed); err != nil || parsed.KeyID == "" || len(parsed.KeyID) > 256 {
		return "", fmt.Errorf("OIDC ID token has no key id")
	}
	return parsed.KeyID, nil
}

func supportsS256(methods []string) bool {
	for _, method := range methods {
		if method == "S256" {
			return true
		}
	}
	return false
}
func (p *Provider) GenerateVerifier() string { return oauth2.GenerateVerifier() }
func (p *Provider) AuthorizationURL(state, nonce, verifier string) (string, error) {
	return p.AuthorizationURLWithMaxAge(context.Background(), state, nonce, verifier, 0)
}

func (p *Provider) AuthorizationURLWithMaxAge(ctx context.Context, state, nonce, verifier string, maxAge time.Duration) (string, error) {
	if strings.TrimSpace(state) == "" || strings.TrimSpace(nonce) == "" || strings.TrimSpace(verifier) == "" || maxAge < 0 {
		return "", fmt.Errorf("OIDC state, nonce, PKCE verifier, and non-negative max age are required")
	}
	stateful, err := p.ensure(ctx)
	if err != nil {
		return "", err
	}
	opts := []oauth2.AuthCodeOption{coreoidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)}
	if maxAge > 0 {
		opts = append(opts, oauth2.SetAuthURLParam("max_age", strconv.FormatInt(int64(maxAge.Seconds()), 10)))
	}
	return stateful.oauth.AuthCodeURL(state, opts...), nil
}

func (p *Provider) ExchangeAndVerify(ctx context.Context, code, verifier, nonce string) (ports.OIDCIdentity, error) {
	return p.ExchangeAndVerifyWithMaxAge(ctx, code, verifier, nonce, 0)
}

func (p *Provider) ExchangeAndVerifyWithMaxAge(ctx context.Context, code, verifier, nonce string, maxAge time.Duration) (ports.OIDCIdentity, error) {
	if strings.TrimSpace(code) == "" || strings.TrimSpace(verifier) == "" || strings.TrimSpace(nonce) == "" || maxAge < 0 {
		return ports.OIDCIdentity{}, fmt.Errorf("OIDC code, verifier, nonce, and non-negative max age are required")
	}
	stateful, err := p.ensure(ctx)
	if err != nil {
		return ports.OIDCIdentity{}, err
	}
	ctx = coreoidc.ClientContext(ctx, p.client)
	token, err := stateful.oauth.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return ports.OIDCIdentity{}, fmt.Errorf("exchange OIDC authorization code: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return ports.OIDCIdentity{}, fmt.Errorf("OIDC token response has no ID token")
	}
	idToken, err := stateful.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return ports.OIDCIdentity{}, fmt.Errorf("verify OIDC ID token: %w", err)
	}
	var claims struct {
		Nonce           string          `json:"nonce"`
		AtHash          string          `json:"at_hash"`
		Email           string          `json:"email"`
		EmailVerified   json.RawMessage `json:"email_verified"`
		Name            string          `json:"name"`
		AuthTime        json.RawMessage `json:"auth_time"`
		AuthorizedParty string          `json:"azp"`
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
	if err := verifyAuthorizedParty(idToken.Audience, claims.AuthorizedParty, p.cfg.ClientID); err != nil {
		return ports.OIDCIdentity{}, err
	}
	email, verifiedEmail, err := verifiedEmailClaim(claims.Email, claims.EmailVerified)
	if err != nil {
		return ports.OIDCIdentity{}, err
	}
	authenticatedAt, err := verifiedAuthTime(claims.AuthTime, p.now().UTC(), maxAge)
	if err != nil {
		return ports.OIDCIdentity{}, err
	}
	return ports.OIDCIdentity{Issuer: idToken.Issuer, Subject: idToken.Subject, Email: email, EmailVerified: verifiedEmail, Name: boundedName(claims.Name), AuthenticatedAt: authenticatedAt}, nil
}

func verifyAuthorizedParty(audience []string, authorizedParty, clientID string) error {
	if len(audience) > 1 && authorizedParty != clientID {
		return fmt.Errorf("OIDC azp must identify this client for a multi-audience token")
	}
	if authorizedParty != "" && authorizedParty != clientID {
		return fmt.Errorf("OIDC azp does not identify this client")
	}
	return nil
}

func verifiedAuthTime(raw json.RawMessage, now time.Time, maxAge time.Duration) (time.Time, error) {
	if maxAge == 0 {
		return time.Time{}, nil
	}
	var seconds json.Number
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if err := decoder.Decode(&seconds); err != nil {
		return time.Time{}, fmt.Errorf("OIDC auth_time is required and must be numeric")
	}
	unix, err := seconds.Int64()
	if err != nil {
		return time.Time{}, fmt.Errorf("OIDC auth_time is required and must be integral seconds")
	}
	authenticatedAt := time.Unix(unix, 0).UTC()
	if authenticatedAt.After(now) || now.Sub(authenticatedAt) >= maxAge {
		return time.Time{}, fmt.Errorf("OIDC auth_time is missing, future, or stale")
	}
	return authenticatedAt, nil
}

const maxDisplayNameBytes = 256

func boundedName(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > maxDisplayNameBytes {
		return ""
	}
	return value
}

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

func NormalizeIssuer(value string) (string, error) { return httpsIssuer(value) }
func httpsIssuer(value string) (string, error) {
	u, err := httpsEndpoint(value)
	if err != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("OIDC issuer must be an absolute HTTPS URL without query or fragment")
	}
	return strings.TrimRight(u.String(), "/"), nil
}
func httpsEndpoint(value string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(value))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.Hostname() == "" {
		return nil, fmt.Errorf("must be an absolute HTTPS URL")
	}
	if port := u.Port(); port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("has an invalid port")
		}
	}
	return u, nil
}
