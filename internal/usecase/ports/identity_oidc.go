package ports

import "context"

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
