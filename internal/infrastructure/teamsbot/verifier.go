package teamsbot

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	// botFrameworkIssuer signs every activity the Bot Framework sends to a bot.
	botFrameworkIssuer = "https://api.botframework.com"
	// botFrameworkKeys is the Bot Framework's published signing key set.
	botFrameworkKeys = "https://login.botframework.com/v1/.well-known/keys"
	// maxAuthorizationBytes bounds the Authorization header the verifier parses.
	maxAuthorizationBytes = 8 << 10
)

// ErrUnauthorized is the one error an inbound activity gets when its token is missing, malformed,
// expired, signed by another key, issued for another bot or bound to another service URL. The
// reason is not told to the caller.
var ErrUnauthorized = errors.New("teams bot: unauthorized activity")

// Verifier checks the JWT on inbound activities (#1420).
type Verifier struct {
	verifier *oidc.IDTokenVerifier
}

var _ ports.TeamsActivityVerifier = (*Verifier)(nil)

// NewVerifier fetches the Bot Framework keys through httpClient, which must be the SSRF-guarded
// client, and accepts only tokens for appID.
func NewVerifier(appID string, httpClient *http.Client) *Verifier {
	keys := oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), httpClient), botFrameworkKeys)
	return NewVerifierWithKeys(appID, keys)
}

// NewVerifierWithKeys verifies against a given key set. Tests use a static one.
func NewVerifierWithKeys(appID string, keys oidc.KeySet) *Verifier {
	return &Verifier{verifier: oidc.NewVerifier(botFrameworkIssuer, keys, &oidc.Config{ClientID: appID, SupportedSigningAlgs: []string{oidc.RS256}})}
}

// Verify implements ports.TeamsActivityVerifier.
func (v *Verifier) Verify(ctx context.Context, authorization, serviceURL string) error {
	if len(authorization) > maxAuthorizationBytes {
		return ErrUnauthorized
	}
	token, ok := strings.CutPrefix(authorization, "Bearer ")
	if !ok || token == "" || strings.ContainsAny(token, " \t\r\n") {
		return ErrUnauthorized
	}
	idToken, err := v.verifier.Verify(ctx, token)
	if err != nil {
		return ErrUnauthorized
	}
	var claims struct {
		ServiceURL string `json:"serviceurl"`
	}
	if idToken.Claims(&claims) != nil || claims.ServiceURL == "" || strings.TrimRight(claims.ServiceURL, "/") != strings.TrimRight(serviceURL, "/") {
		return ErrUnauthorized
	}
	return nil
}
