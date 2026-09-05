package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scmconnector"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// SCMConnectorMeta is the non-secret view of a stored source-control connector: safe to
// list, log, and return over the API. The token is NEVER part of it.
type SCMConnectorMeta struct {
	ID        shared.ID             `json:"id"`
	Name      string                `json:"name"`
	Provider  scmconnector.Provider `json:"provider"`
	Host      string                `json:"host"`
	Username  string                `json:"username"`
	AuthKind  scmconnector.AuthKind `json:"auth_kind"`
	CreatedAt time.Time             `json:"created_at"`
	UpdatedAt time.Time             `json:"updated_at"`
}

// GitCredential is a resolved clone-time credential. Token is plaintext and lives only in
// process memory and the git child's environment; it is never logged, audited, or persisted
// to the workspace's .git/config (the acquirer injects it via GIT_ASKPASS, not the URL).
type GitCredential struct {
	Username string
	Token    []byte
}

// GitCredentialResolver resolves a normalized clone-URL host to a source-control credential.
// The acquirer holds one to authenticate a PRIVATE-repository clone; it returns ok=false when
// the tenant has no connector for that host, so a public clone proceeds unauthenticated. The
// host must already be normalized with scmconnector.NormalizeHost. Tenant comes from ctx.
type GitCredentialResolver interface {
	ResolveGitCredential(ctx context.Context, host string) (GitCredential, bool, error)
}

// SCMConnectorStore persists tenant-scoped source-control connectors. The token is sealed at rest
// (AES-256-GCM, bound by AAD to tenant+id+host+username) and returned ONLY via ResolveGitCredential at
// clone time. Every method is tenant-scoped from ctx (Postgres RLS + WithTenant). Put upserts by id and
// always requires a token; a second connector for the same host is a conflict. Get/List never return
// the token.
type SCMConnectorStore interface {
	GitCredentialResolver
	Put(ctx context.Context, c scmconnector.Connector, token []byte) error
	List(ctx context.Context) ([]SCMConnectorMeta, error)
	Get(ctx context.Context, id shared.ID) (SCMConnectorMeta, error)
	Delete(ctx context.Context, id shared.ID) error
}
