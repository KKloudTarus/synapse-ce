package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
)

// UserRepository persists operator identities. Every read and write except the authentication
// lookup carries its tenant explicitly: an implementation MUST apply that tenant as a query
// predicate rather than relying on an ambient default, so a user in another tenant is invisible
// whether or not row level security is present on the table.
//
// A row whose tenant_id is empty (the bootstrap admin and any pre-tenant row) belongs to
// shared.DefaultTenant; implementations normalize both sides with shared.TenantOrDefault before
// comparing, so ” and 'default' name the same tenant.
type UserRepository interface {
	Create(ctx context.Context, u *user.User) error
	// GetByID resolves a user inside tenantID. A user in another tenant reads as not found.
	GetByID(ctx context.Context, tenantID, id shared.ID) (*user.User, error)
	// GetByAPIKeyHash is the authentication path and is deliberately NOT tenant-scoped: the tenant
	// is unknown until the token resolves to a user, and the lookup key is the digest of a 192-bit
	// secret. The resolved user's own TenantID is what scopes every later request.
	GetByAPIKeyHash(ctx context.Context, apiKeyHash string) (*user.User, error)
	// List returns the users of tenantID only.
	List(ctx context.Context, tenantID shared.ID) ([]*user.User, error)
	// Update persists name, role, disabled state, and API-key hash for a user that already exists in
	// tenantID. It never moves a user between tenants, and a user in another tenant reads as not
	// found rather than being modified.
	Update(ctx context.Context, tenantID shared.ID, u *user.User) error
	// Upsert inserts or updates by id (used to keep the bootstrap admin's key in sync
	// with SYNAPSE_API_TOKEN across restarts).
	Upsert(ctx context.Context, u *user.User) error
	// Bootstrap atomically seeds or refreshes the bootstrap user. Durable implementations
	// record auditEntry only when the user is first created.
	Bootstrap(ctx context.Context, u *user.User, auditEntry AuditEntry) error
}

// UserRosterLocker is the optional capability that makes the last-admin guard safe against a
// concurrent second mutation. The guard is a read-modify-write: it counts the tenant's other
// enabled admins, then demotes or disables one. Two concurrent demotions each see the other admin
// still enabled, both pass, and the tenant is left with nobody who can administer it.
//
// An implementation returns the tenant's roster with those rows locked for the remainder of the
// caller's transaction, so the second mutation blocks until the first commits and then observes it.
// A repository that cannot lock simply does not implement this, and the service falls back to the
// plain read; the in-process mutex still serializes a single replica.
type UserRosterLocker interface {
	ListForUpdate(ctx context.Context, tenantID shared.ID) ([]*user.User, error)
}
