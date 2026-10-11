package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// IdentityAuthorizationPurpose is persisted protocol intent. It is deliberately closed so a
// callback cannot be reinterpreted as a more privileged operation.
type IdentityAuthorizationPurpose string

const (
	IdentityAuthorizationLogin      IdentityAuthorizationPurpose = "login"
	IdentityAuthorizationLink       IdentityAuthorizationPurpose = "link"
	IdentityAuthorizationSwitch     IdentityAuthorizationPurpose = "switch"
	IdentityAuthorizationStepUp     IdentityAuthorizationPurpose = "step_up"
	IdentityAuthorizationInvitation IdentityAuthorizationPurpose = "invitation"
	IdentityAuthorizationTest       IdentityAuthorizationPurpose = "test"
)

func (p IdentityAuthorizationPurpose) Valid() bool {
	switch p {
	case IdentityAuthorizationLogin, IdentityAuthorizationLink, IdentityAuthorizationSwitch, IdentityAuthorizationStepUp, IdentityAuthorizationInvitation, IdentityAuthorizationTest:
		return true
	}
	return false
}

// IdentityAuthorizationTransaction contains no protocol secret in plaintext. ContextSealed
// carries caller-bound state (such as an initiating session) and is authenticated by the use case.
type IdentityAuthorizationTransaction struct {
	ID                 shared.ID
	TenantID           shared.ID
	Purpose            IdentityAuthorizationPurpose
	ConnectionID       shared.ID
	ConnectionRevision int
	StateDigest        string
	NonceDigest        string
	CallerNonceDigest  string
	PKCEVerifierSealed string
	ContextSealed      string
	SessionID          shared.ID
	ExpiresAt          time.Time
	ConsumedAt         *time.Time
	CreatedAt          time.Time
}

// IdentityAuthorizationStore owns the atomic single-use transaction transition. Consume must
// mark the row consumed before returning the sealed verifier, including failed exchanges.
type IdentityAuthorizationStore interface {
	CreateIdentityAuthorization(context.Context, IdentityAuthorizationTransaction) error
	ConsumeIdentityAuthorization(context.Context, shared.ID, string, string, time.Time) (IdentityAuthorizationTransaction, error)
	CleanupIdentityAuthorizations(context.Context, shared.ID, time.Time, int) (int, error)
}
