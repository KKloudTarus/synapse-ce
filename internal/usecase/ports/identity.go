package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/identity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// IdentityStore persists OIDC subject links, login transactions, and opaque browser sessions.
// ConsumeAuthorizationTransaction must atomically return a transaction at most once across all
// processes. Values passed to it are hashes, never raw browser credentials.
type IdentityStore interface {
	// CreateExternalIdentity joins a tenant transaction already bound to ctx, so an approved link
	// and its audit record commit or roll back together.
	CreateExternalIdentity(ctx context.Context, identity identity.ExternalIdentity) error
	GetExternalIdentity(ctx context.Context, issuer, subject string) (identity.ExternalIdentity, error)
	// ListExternalIdentities returns the approved links of one user inside tenantID.
	ListExternalIdentities(ctx context.Context, tenantID, userID shared.ID) ([]identity.ExternalIdentity, error)
	// DeleteExternalIdentity removes one approved link of userID inside tenantID and returns it. It
	// joins a tenant transaction already bound to ctx, so the removal, the user's session
	// revocation and the audit record commit or roll back together. A link that does not exist for
	// that tenant and user is shared.ErrNotFound.
	DeleteExternalIdentity(ctx context.Context, tenantID, userID, linkID shared.ID) (identity.ExternalIdentity, error)

	CreateAuthorizationTransaction(ctx context.Context, transaction identity.AuthorizationTransaction) error
	ConsumeAuthorizationTransaction(ctx context.Context, tenantID shared.ID, stateHash string, now time.Time) (identity.AuthorizationTransaction, error)

	CreateSession(ctx context.Context, session identity.Session) error
	// RotateSession atomically creates replacement and revokes the active previous session.
	RotateSession(ctx context.Context, previousSessionID shared.ID, replacement identity.Session, now time.Time) error
	GetSessionByTokenHash(ctx context.Context, tokenHash string) (identity.Session, error)
	RevokeSession(ctx context.Context, tenantID, sessionID shared.ID, now time.Time) error
	UserSessionRevoker
}

// UserSessionRevoker terminally revokes every active browser session of one user. It joins a
// tenant transaction already bound to ctx, so disabling a user, revoking its sessions and the
// audit record are one unit. It returns the number of sessions revoked.
type UserSessionRevoker interface {
	RevokeUserSessions(ctx context.Context, tenantID, userID shared.ID, now time.Time) (int, error)
}

// ExternalIdentitySessionIssuer performs the final OIDC callback write. It atomically verifies that
// the exact issuer/subject still links to session.UserID, verifies that the user is enabled and has
// not changed since approval was read, and creates the session. Implementations serialize it with
// link removal and user lifecycle revocation.
type ExternalIdentitySessionIssuer interface {
	CreateSessionForExternalIdentity(ctx context.Context, issuer, subject string, approvedUserUpdatedAt time.Time, session identity.Session) error
}
