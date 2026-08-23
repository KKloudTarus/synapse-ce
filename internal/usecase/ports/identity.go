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
	CreateExternalIdentity(ctx context.Context, identity identity.ExternalIdentity) error
	GetExternalIdentity(ctx context.Context, issuer, subject string) (identity.ExternalIdentity, error)

	CreateAuthorizationTransaction(ctx context.Context, transaction identity.AuthorizationTransaction) error
	ConsumeAuthorizationTransaction(ctx context.Context, tenantID shared.ID, stateHash string, now time.Time) (identity.AuthorizationTransaction, error)

	CreateSession(ctx context.Context, session identity.Session) error
	// RotateSession atomically creates replacement and revokes the active previous session.
	RotateSession(ctx context.Context, previousSessionID shared.ID, replacement identity.Session, now time.Time) error
	GetSessionByTokenHash(ctx context.Context, tokenHash string) (identity.Session, error)
	RevokeSession(ctx context.Context, tenantID, sessionID shared.ID, now time.Time) error
}
