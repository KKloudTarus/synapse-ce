package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// IdentityAdminProof is server-owned authentication context, never a request DTO.
type IdentityAdminProof struct {
	Principal authz.Principal
	Bootstrap *authz.BootstrapEligibility
	At        time.Time
	// Recovery is set only by the server-side break-glass proof constructor. Stores accept it
	// solely for the closed repair/relax operations, never as general administration.
	Recovery bool
}

// IdentityOIDCSettings contains immutable trust inputs and a sealed client secret. The secret
// never appears in administrative projections or audit diffs.
type IdentityOIDCSettings struct {
	ClientID           string `json:"client_id"`
	RedirectURL        string `json:"redirect_url"`
	SealedClientSecret string `json:"sealed_client_secret"`
}

type IdentityConnection struct {
	TenantID         shared.ID            `json:"-"`
	ID               shared.ID            `json:"id"`
	DisplayName      string               `json:"display_name"`
	Issuer           string               `json:"issuer"`
	Enabled          bool                 `json:"enabled"`
	Revision         int                  `json:"revision"`
	DraftRevision    int                  `json:"draft_revision"`
	Version          int                  `json:"version"`
	Epoch            int64                `json:"-"`
	TestPassed       bool                 `json:"test_passed"`
	Settings         IdentityOIDCSettings `json:"-"`
	SettingsRevision int                  `json:"-"`
}

type IdentityConnectionDraft struct {
	TenantID        shared.ID
	ID              shared.ID
	DisplayName     string
	Issuer          string
	Settings        IdentityOIDCSettings
	ExpectedVersion int
}

type IdentityConnectionTest struct {
	ID           shared.ID
	TenantID     shared.ID
	ConnectionID shared.ID
	Revision     int
	Passed       bool
	At           time.Time
	ExpiresAt    time.Time
}

// IdentityConnectionStore owns revision, test, activation and disable fences with their audits.
type IdentityConnectionStore interface {
	ListIdentityConnections(context.Context, shared.ID, bool) ([]IdentityConnection, error)
	GetIdentityConnection(context.Context, shared.ID, shared.ID, int) (IdentityConnection, error)
	SaveIdentityConnectionDraft(context.Context, IdentityConnectionDraft, IdentityAdminProof) (IdentityConnection, error)
	RecordIdentityConnectionTest(context.Context, IdentityConnectionTest, IdentityAdminProof) error
	ActivateIdentityConnection(context.Context, shared.ID, shared.ID, int, int, IdentityAdminProof) (IdentityConnection, error)
	DisableIdentityConnection(context.Context, shared.ID, shared.ID, int, IdentityAdminProof) (IdentityConnection, error)
}

// IdentityOIDCProviderFactory selects a protocol client for one immutable revision. Provider
// outage is reported when a protocol operation is invoked, independently of process startup.
type IdentityOIDCProviderFactory interface {
	ProviderForConnection(context.Context, IdentityConnection) (OIDCProvider, error)
}
