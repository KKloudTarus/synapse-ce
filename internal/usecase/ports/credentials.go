package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// CredentialMeta is the non-secret metadata about a stored credential – safe to list,
// log, and return over the API. The secret value is NEVER part of it.
type CredentialMeta struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CredentialVault stores per-engagement secrets encrypted at rest and resolves them
// only at tool-execution time. Implementations MUST NOT log, audit, or otherwise
// surface the plaintext; Resolve is the ONLY path that returns it. Put
// upserts (re-storing a name replaces its secret); Resolve returns shared.ErrNotFound
// when the name is absent.
type CredentialVault interface {
	Put(ctx context.Context, engagementID shared.ID, name string, secret []byte) error
	Resolve(ctx context.Context, engagementID shared.ID, name string) ([]byte, error)
	List(ctx context.Context, engagementID shared.ID) ([]CredentialMeta, error)
	Delete(ctx context.Context, engagementID shared.ID, name string) error
}
