package orgidentity

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// AuthenticationIdentity binds one provider subject to one existing membership/person. It carries
// no email or mutable claims. Revision is provenance; stable identity is connection+subject.
type AuthenticationIdentity struct {
	TenantID         shared.ID
	ID               shared.ID
	MembershipID     shared.ID
	PersonID         shared.ID
	ConnectionID     shared.ID
	ProtocolSubject  string
	CreationRevision int64
	CreatedAt        time.Time
}

func NewAuthenticationIdentity(tenantID, id, membershipID, personID, connectionID shared.ID, protocolSubject string, creationRevision int64, now time.Time) (*AuthenticationIdentity, error) {
	protocolSubject = strings.TrimSpace(protocolSubject)
	if tenantID.IsZero() || id.IsZero() || membershipID.IsZero() || personID.IsZero() || connectionID.IsZero() || protocolSubject == "" || len(protocolSubject) > 2048 || creationRevision <= 0 || now.IsZero() {
		return nil, fmt.Errorf("%w: invalid authentication identity", shared.ErrValidation)
	}
	return &AuthenticationIdentity{TenantID: tenantID, ID: id, MembershipID: membershipID, PersonID: personID, ConnectionID: connectionID, ProtocolSubject: protocolSubject, CreationRevision: creationRevision, CreatedAt: now.UTC()}, nil
}

type CredentialKind string

const (
	CredentialLegacyAPIKey   CredentialKind = "legacy_api_key"
	CredentialBrowserSession CredentialKind = "browser_session"
	CredentialOIDCState      CredentialKind = "oidc_state"
	CredentialInvitation     CredentialKind = "invitation"
	CredentialBreakGlass     CredentialKind = "break_glass"
	CredentialConnectionLaunch CredentialKind = "connection_launch"
)

func (k CredentialKind) Valid() bool {
	switch k {
	case CredentialLegacyAPIKey, CredentialBrowserSession, CredentialOIDCState, CredentialInvitation, CredentialBreakGlass, CredentialConnectionLaunch:
		return true
	default:
		return false
	}
}

var sha256Hex = regexp.MustCompile(`^[a-f0-9]{64}$`)

// CredentialLocator is the entire global pre-authentication result. Intentionally absent: person,
// email, subject, role, connection and arbitrary metadata. The caller MUST bind OrganizationID and
// then read the authoritative credential/membership through an RLS-scoped port.
type CredentialLocator struct {
	Digest         string
	OrganizationID shared.ID
	Kind           CredentialKind
	CredentialID   shared.ID
}

func NewCredentialLocator(digest string, organizationID shared.ID, kind CredentialKind, credentialID shared.ID) (CredentialLocator, error) {
	digest = strings.TrimSpace(digest)
	if !sha256Hex.MatchString(digest) || organizationID.IsZero() || !kind.Valid() || credentialID.IsZero() {
		return CredentialLocator{}, fmt.Errorf("%w: exact SHA-256 digest, organization, allowed credential kind, and credential id are required", shared.ErrValidation)
	}
	return CredentialLocator{Digest: digest, OrganizationID: organizationID, Kind: kind, CredentialID: credentialID}, nil
}
