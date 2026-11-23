package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
)

// IdentityInitialProvisioning reserves only the first connection and administrator invitation.
// Its encrypted retry result stays internal and is never part of a status projection.
type IdentityInitialProvisioning struct {
	TenantID, ID, ConnectionID, InvitationID         shared.ID
	ActorID, SourceTenantID, CredentialID, Recipient string
	State                                            string
	Version                                          int
	CreatedAt, UpdatedAt                             time.Time
	ClosedAt                                         *time.Time
	Connection                                       *IdentityConnection
	Invitation                                       *IdentityInvitation
	InvitationCodeSealed                             string
}

type IdentityProvisioningBegin struct {
	TenantID, ID, ConnectionID, InvitationID shared.ID
	Principal                                authz.Principal
	Recipient                                string
	At                                       time.Time
}

// IdentityProvisioningProof is server-owned scoped authority, not ordinary administrator proof.
// The application verifies the sealed capability and current deployment credential before use.
type IdentityProvisioningProof struct {
	TenantID, ID, ConnectionID, InvitationID shared.ID
	Principal                                authz.Principal
	Recipient                                string
	IssuedAt, ExpiresAt, At                  time.Time
}

func (p IdentityProvisioningProof) Active() bool {
	return !p.TenantID.IsZero() && !p.ID.IsZero() && !p.ConnectionID.IsZero() && !p.InvitationID.IsZero() && p.Principal.IsBootstrap() && p.Principal.Role == user.RoleAdmin && p.Principal.Credential.ID != "" && p.Principal.TenantID != p.TenantID.String() && p.Recipient != "" && !p.At.IsZero() && !p.IssuedAt.IsZero() && !p.IssuedAt.After(p.At) && p.ExpiresAt.After(p.At) && !p.ExpiresAt.After(p.IssuedAt.Add(15*time.Minute))
}

type IdentityProvisioningStore interface {
	BeginIdentityProvisioning(context.Context, IdentityProvisioningBegin) (IdentityInitialProvisioning, error)
	ReadIdentityProvisioning(context.Context, IdentityProvisioningProof) (IdentityInitialProvisioning, error)
	SaveIdentityProvisioningDraft(context.Context, IdentityConnectionDraft, IdentityProvisioningProof) (IdentityInitialProvisioning, error)
	RecordIdentityProvisioningTest(context.Context, IdentityConnectionTest, IdentityProvisioningProof) error
	ActivateIdentityProvisioningConnection(context.Context, int, int, IdentityProvisioningProof) (IdentityInitialProvisioning, error)
	IssueIdentityProvisioningInvitation(context.Context, IdentityInvitationCreate, string, IdentityProvisioningProof) (IdentityInitialProvisioning, error)
}
