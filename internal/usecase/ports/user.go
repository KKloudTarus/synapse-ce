package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
)

// UserRepository persists operator identities. Lookups by API-key hash
// back authentication; Upsert seeds the bootstrap admin idempotently.
type UserRepository interface {
	Create(ctx context.Context, u *user.User) error
	GetByID(ctx context.Context, id shared.ID) (*user.User, error)
	GetByAPIKeyHash(ctx context.Context, apiKeyHash string) (*user.User, error)
	List(ctx context.Context) ([]*user.User, error)
	// Upsert inserts or updates by id (used to keep the bootstrap admin's key in sync
	// with SYNAPSE_API_TOKEN across restarts).
	Upsert(ctx context.Context, u *user.User) error
	// Bootstrap atomically seeds or refreshes the bootstrap user. Durable implementations
	// record auditEntry only when the user is first created.
	Bootstrap(ctx context.Context, u *user.User, auditEntry AuditEntry) error
}
