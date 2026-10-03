package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/identity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// IdentityRecoveryPolicy controls the emergency credential path for one organization. A
// recovery credential is deliberately independent of normal SSO step-up: it is usable only for
// the closed recovery action allowlist.
type IdentityRecoveryPolicy struct {
	TenantID        shared.ID
	Organization    authz.OrganizationPolicy
	ExpectedVersion int
	Version         int
	LastRehearsedAt time.Time
	AlertConfigured bool
	UpdatedAt       time.Time
}

type IdentityRecoveryActivation struct {
	ID           shared.ID
	TenantID     shared.ID
	MembershipID shared.ID
	PersonID     shared.ID
	SecretDigest string
	ExpiresAt    time.Time
	CreatedAt    time.Time
	CreatedBy    string
}

// IdentityRecoveryConsume binds one exact activation to the break-glass browser session it
// creates. Implementations must consume, audit, retain the alert obligation, and create the
// session in the same transaction.
type IdentityRecoveryConsume struct {
	SecretDigest string
	Issue        IdentitySessionIssue
	Actor        string
	Now          time.Time
}

type IdentityRecoveryAlert struct {
	ID            shared.ID
	TenantID      shared.ID
	MembershipID  shared.ID
	SessionID     shared.ID
	State         string
	Attempts      int
	MaxAttempts   int
	NextAttemptAt time.Time
	CreatedAt     time.Time
}

type IdentityRecoveryStore interface {
	GetIdentityRecoveryPolicy(context.Context, shared.ID) (IdentityRecoveryPolicy, error)
	SaveIdentityRecoveryPolicy(context.Context, IdentityRecoveryPolicy, IdentityAdminProof) (IdentityRecoveryPolicy, error)
	RehearseIdentityRecovery(context.Context, shared.ID, IdentityAdminProof, time.Time) error
	RecordIdentityRecoveryAlertTest(context.Context, shared.ID, IdentityAdminProof, time.Time) error
	CreateIdentityRecoveryActivation(context.Context, IdentityRecoveryActivation, IdentityAdminProof) error
	ResolveIdentityRecoveryActivationTenant(context.Context, string) (shared.ID, error)
	ConsumeIdentityRecoveryActivation(context.Context, IdentityRecoveryConsume) (identity.EnterpriseSession, error)
	ClaimIdentityRecoveryAlerts(context.Context, shared.ID, time.Time, int) ([]IdentityRecoveryAlert, error)
	CompleteIdentityRecoveryAlert(context.Context, shared.ID, shared.ID, bool, string, time.Time) error
	ListIdentityRecoveryAlerts(context.Context, shared.ID, int) ([]IdentityRecoveryAlert, error)
	IdentityRecoveryAlertRecipients(context.Context, shared.ID, shared.ID) ([]string, error)
}

// IdentityRecoveryAlertMailer is intentionally separate from tenant notification rules. Recovery
// alerts are mandatory operational obligations and must remain deliverable when that framework is
// disabled or paused.
type IdentityRecoveryAlertMailer interface {
	SendIdentityRecoveryAlert(context.Context, string, shared.ID) NotificationSendResult
}
