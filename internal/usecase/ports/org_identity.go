package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/orgidentity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// CredentialLocatorResolver is intentionally the complete raw pre-authentication read surface.
// It resolves one exact digest and exposes no listing, prefix, organization, email, subject or
// arbitrary metadata query. Its result is never authentication or authorization proof: after
// binding the returned organization, a cutover caller must re-read the authoritative credential
// and membership through an RLS-scoped port and reject any credential whose status is not active.
// The rebuildable locator may still route an exact digest for a disabled legacy credential.
type CredentialLocatorResolver interface {
	ResolveExactHash(ctx context.Context, digest string) (orgidentity.CredentialLocator, error)
}

// CredentialLocatorWriter mutates the rebuildable exact-hash index inside the same database
// transaction as the tenant-owned credential target. Callers should normally consume a higher-level
// transactional store rather than invoke this independently.
type CredentialLocatorWriter interface {
	PutExactHash(ctx context.Context, locator orgidentity.CredentialLocator) error
	DeleteExactHash(ctx context.Context, digest string) error
}

// OrganizationIdentityReader exposes only authoritative tenant-bound reads. Implementations must
// apply tenant RLS before touching memberships, identities or connections.
type OrganizationIdentityReader interface {
	GetMembership(ctx context.Context, tenantID, membershipID shared.ID) (orgidentity.Membership, error)
	GetMembershipByPerson(ctx context.Context, tenantID, personID shared.ID) (orgidentity.Membership, error)
	GetPersonThroughMembership(ctx context.Context, tenantID, membershipID shared.ID) (orgidentity.Person, orgidentity.Membership, error)
	GetConnection(ctx context.Context, tenantID, connectionID shared.ID) (orgidentity.Connection, error)
	GetAuthenticationIdentity(ctx context.Context, tenantID, connectionID shared.ID, protocolSubject string) (orgidentity.AuthenticationIdentity, error)
}

// OrganizationIdentityStore owns additive identity foundations. CreatePersonMembership is one
// transaction because a global person without its first RLS-proven membership is not a usable
// organization identity. PutAuthenticationIdentity relies on database composite FKs to reject
// foreign/cross-organization membership attachment.
type OrganizationIdentityStore interface {
	OrganizationIdentityReader
	CreatePersonMembership(ctx context.Context, person orgidentity.Person, membership orgidentity.Membership) error
	PutMembership(ctx context.Context, membership orgidentity.Membership) error
	PutConnection(ctx context.Context, connection orgidentity.Connection) error
	PutConnectionRevision(ctx context.Context, revision orgidentity.ConnectionRevision) error
	PutAuthenticationIdentity(ctx context.Context, identity orgidentity.AuthenticationIdentity) error
}

// PlatformPersonIndex is deliberately exact-person only. It supports platform person suspension
// and fan-out without creating an ordinary global membership listing surface.
type PlatformPersonIndex interface {
	OrganizationsForExactPerson(ctx context.Context, personID shared.ID) ([]shared.ID, error)
}
