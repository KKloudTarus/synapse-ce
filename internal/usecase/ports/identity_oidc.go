package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
)

// OIDCIdentity is the verified non-secret identity output of a configured OpenID Provider.
type OIDCIdentity struct {
	Issuer  string
	Subject string
	Role    user.Role
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
