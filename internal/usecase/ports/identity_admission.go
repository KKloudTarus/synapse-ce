package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/identity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
)

type IdentityInvitation struct {
	ID                   shared.ID
	TenantID             shared.ID
	Recipient            string
	Role                 user.Role
	State                string
	Version              int
	ExpiresAt            time.Time
	CreatedAt            time.Time
	AcceptedMembershipID shared.ID
	AcceptedPersonID     shared.ID
}

type IdentityInvitationCreate struct {
	Invitation IdentityInvitation
	CodeDigest string
	Actor      string
}

// IdentityInvitationRoute is the deliberately minimal result of an exact invitation-code
// lookup. It does not reveal a recipient, role, or whether another code exists.
type IdentityInvitationRoute struct {
	TenantID     shared.ID
	InvitationID shared.ID
}

// IdentityAdmissionCommand is the only persistence command that turns verified upstream
// evidence into local authority. Caller-provided person and membership values are hints only;
// the store locks and resolves the authoritative binding before inserting a session.
type IdentityAdmissionCommand struct {
	Purpose                IdentityAuthorizationPurpose
	TenantID               shared.ID
	ConnectionID           shared.ID
	ConnectionRevision     int
	Subject                string
	AuthenticatedAt        time.Time
	InvitationID           shared.ID
	InvitationVersion      int
	InvitationCodeDigest   string
	VerifiedMailbox        string
	ChallengeDigest        string
	ExpectedPersonID       shared.ID
	SourceCredentialDigest string
	SourceSessionID        shared.ID
	NewPersonID            shared.ID
	DisplayName            string
	Issue                  IdentitySessionIssue
	Actor                  string
	Now                    time.Time
}

type IdentityAdmissionResult struct {
	Session    identity.EnterpriseSession
	Membership IdentityMembership
	PersonID   shared.ID
}

// IdentityAdmissionStore contains the atomic database operations that add an authenticator or
// consume an invitation. A callback never decides membership state from a stale read.
type IdentityAdmissionStore interface {
	CreateIdentityInvitation(context.Context, IdentityInvitationCreate, IdentityAdminProof) error
	ListIdentityInvitations(context.Context, shared.ID, int) ([]IdentityInvitation, error)
	RevokeIdentityInvitation(context.Context, shared.ID, shared.ID, int, IdentityAdminProof, time.Time) error
	GetIdentityInvitation(context.Context, shared.ID, shared.ID) (IdentityInvitation, error)
	ResolveIdentityInvitationCode(context.Context, string) (IdentityInvitationRoute, error)
	CreateMailboxChallenge(context.Context, shared.ID, shared.ID, int, string, shared.ID, string, time.Time, time.Time) error
	AdmitIdentity(context.Context, IdentityAdmissionCommand) (IdentityAdmissionResult, error)
}
