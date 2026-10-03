package ports

import (
	"context"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
)

type IdentityRosterMember struct {
	ID, PersonID shared.ID
	Name         string
	Role         user.Role
	State        IdentityMembershipState
	Version      int
}
type IdentityAuthenticatorProjection struct {
	ConnectionID shared.ID
	Name         string
	State        string
}
type IdentityMembershipAdministration struct {
	TenantID, MembershipID shared.ID
	Kind                   IdentityMembershipChangeKind
	Role                   user.Role
	ExpectedVersion        int
	Proof                  IdentityAdminProof
}
type IdentityAdministrationStore interface {
	ListIdentityRoster(context.Context, shared.ID, int) ([]IdentityRosterMember, error)
	ChangeIdentityMembershipAdministration(context.Context, IdentityMembershipAdministration) (IdentityMembership, error)
	ListOwnIdentityAuthenticators(context.Context, IdentityAdminProof) ([]IdentityAuthenticatorProjection, error)
}
