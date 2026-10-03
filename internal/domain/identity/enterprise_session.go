package identity

import (
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// EnterpriseSession is the authoritative browser session issued from the enterprise identity
// model. The credential and CSRF values are SHA-256 digests; raw browser values never enter this
// aggregate or durable session storage.
type EnterpriseSession struct {
	ID                   shared.ID
	TenantID             shared.ID
	CredentialID         shared.ID
	MembershipID         shared.ID
	PersonID             shared.ID
	ConnectionID         shared.ID
	Kind                 string
	LineageID            shared.ID
	RotatedFromSessionID shared.ID
	AuthenticatedAt      time.Time
	OriginAt             time.Time
	ExpiresAt            time.Time
	PersonEpoch          int64
	MembershipEpoch      int64
	ConnectionEpoch      int64
	CSRFTokenHash        string
	RevokedAt            *time.Time
	CreatedAt            time.Time
}

const (
	EnterpriseSessionKindBrowser    = "browser_session"
	EnterpriseSessionKindBreakGlass = "break_glass"
)

func (s EnterpriseSession) Active(now time.Time) bool {
	return s.RevokedAt == nil && s.ExpiresAt.After(now.UTC())
}

func (s EnterpriseSession) BeyondMaxAge(now time.Time) bool {
	return s.OriginAt.IsZero() || !now.UTC().Before(s.OriginAt.Add(MaxSessionAge))
}

func (s EnterpriseSession) Valid() error {
	if s.ID.IsZero() || s.TenantID.IsZero() || s.CredentialID.IsZero() || s.MembershipID.IsZero() || s.PersonID.IsZero() || s.LineageID.IsZero() {
		return fmt.Errorf("%w: enterprise session identity is incomplete", shared.ErrValidation)
	}
	if s.Kind != EnterpriseSessionKindBrowser && s.Kind != EnterpriseSessionKindBreakGlass {
		return fmt.Errorf("%w: invalid enterprise session kind", shared.ErrValidation)
	}
	if strings.TrimSpace(s.CSRFTokenHash) == "" || s.AuthenticatedAt.IsZero() || s.OriginAt.IsZero() || s.CreatedAt.IsZero() || !s.ExpiresAt.After(s.CreatedAt) {
		return fmt.Errorf("%w: invalid enterprise session timestamps or CSRF hash", shared.ErrValidation)
	}
	if s.PersonEpoch < 1 || s.MembershipEpoch < 1 || (s.ConnectionID.IsZero() != (s.ConnectionEpoch == 0)) || (!s.ConnectionID.IsZero() && s.ConnectionEpoch < 1) {
		return fmt.Errorf("%w: invalid enterprise session epoch binding", shared.ErrValidation)
	}
	return nil
}
