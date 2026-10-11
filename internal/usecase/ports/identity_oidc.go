package ports

import (
	"context"
	"time"
)

// OIDCIdentity is the verified non-secret identity output of a configured OpenID Provider.
// It carries no role: provider groups never assign or change a Synapse role.
type OIDCIdentity struct {
	Issuer  string
	Subject string
	// Email is advisory unless EmailVerified is true in the signed ID token.
	// Neither value is an account lookup key.
	Email         string
	EmailVerified bool
	// Name is an optional bounded display string. It is never an identity key: only
	// (Issuer, Subject) identifies the subject.
	Name string
	// AuthenticatedAt is signed upstream authentication evidence. It is separate
	// from local session lineage and is zero only for legacy fixed-provider flows
	// that do not require a maximum upstream authentication age.
	AuthenticatedAt time.Time
}

// OIDCAuthentication is the sensitive authorization-code protocol boundary. It
// keeps max_age request policy out of neutral verified identity evidence.
type OIDCAuthentication interface {
	AuthorizationURLWithMaxAge(ctx context.Context, state, nonce, verifier string, maxAge time.Duration) (string, error)
	ExchangeAndVerifyWithMaxAge(ctx context.Context, code, verifier, nonce string, maxAge time.Duration) (OIDCIdentity, error)
}

// OIDCProvider executes the authorization-code protocol. Implementations must use PKCE S256 and
// verify issuer, audience, signature, nonce, and optional at_hash before returning an identity.
type OIDCProvider interface {
	// GenerateVerifier mints a PKCE code verifier. It lives on the protocol adapter so no use
	// case depends on a concrete OAuth2 library.
	GenerateVerifier() string
	AuthorizationURL(state, nonce, verifier string) (string, error)
	ExchangeAndVerify(ctx context.Context, code, verifier, nonce string) (OIDCIdentity, error)
}
