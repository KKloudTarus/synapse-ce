package orgidentity

import (
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
)

type MembershipStatus string

const (
	MembershipActive    MembershipStatus = "active"
	MembershipSuspended MembershipStatus = "suspended"
	MembershipRemoved   MembershipStatus = "removed"
)

func (s MembershipStatus) Valid() bool {
	return s == MembershipActive || s == MembershipSuspended || s == MembershipRemoved
}

// Membership is the sole bridge from a global person into one organization/tenant. Authorization
// consumes Role only after this row has been loaded under that tenant's RLS context.
type Membership struct {
	TenantID  shared.ID
	ID        shared.ID
	PersonID  shared.ID
	Role      user.Role
	Status    MembershipStatus
	Epoch     int64
	Version   int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

func NewMembership(tenantID, id, personID shared.ID, role user.Role, now time.Time) (*Membership, error) {
	if tenantID.IsZero() || id.IsZero() || personID.IsZero() || !role.Valid() || now.IsZero() {
		return nil, fmt.Errorf("%w: tenant, membership, person, valid human role, and timestamp are required", shared.ErrValidation)
	}
	now = now.UTC()
	return &Membership{TenantID: tenantID, ID: id, PersonID: personID, Role: role, Status: MembershipActive, Epoch: 1, Version: 1, CreatedAt: now, UpdatedAt: now}, nil
}

func (m Membership) Valid() error {
	if m.TenantID.IsZero() || m.ID.IsZero() || m.PersonID.IsZero() || !m.Role.Valid() || !m.Status.Valid() || m.Epoch <= 0 || m.Version <= 0 || m.CreatedAt.IsZero() || m.UpdatedAt.Before(m.CreatedAt) {
		return fmt.Errorf("%w: invalid membership", shared.ErrValidation)
	}
	return nil
}

func (m *Membership) ChangeRole(role user.Role, expectedVersion int64, now time.Time) error {
	if err := m.mutable(expectedVersion, now); err != nil {
		return err
	}
	if !role.Valid() {
		return fmt.Errorf("%w: invalid membership role", shared.ErrValidation)
	}
	if m.Role == role {
		return nil
	}
	m.Role = role
	// Role changes alter effective authorization immediately and therefore invalidate credentials
	// issued under the old membership authority.
	m.Epoch++
	m.bump(now)
	return nil
}

func (m *Membership) Suspend(expectedVersion int64, now time.Time) error {
	if err := m.mutable(expectedVersion, now); err != nil {
		return err
	}
	if m.Status == MembershipSuspended {
		return nil
	}
	m.Status = MembershipSuspended
	m.Epoch++
	m.bump(now)
	return nil
}

func (m *Membership) Activate(expectedVersion int64, now time.Time) error {
	if expectedVersion != m.Version {
		return fmt.Errorf("%w: stale membership version", shared.ErrConflict)
	}
	if m.Status == MembershipRemoved {
		return fmt.Errorf("%w: removed membership is terminal", shared.ErrForbidden)
	}
	if now.IsZero() {
		return fmt.Errorf("%w: timestamp is required", shared.ErrValidation)
	}
	if m.Status == MembershipActive {
		return nil
	}
	m.Status = MembershipActive
	m.Epoch++
	m.bump(now)
	return nil
}

func (m *Membership) Remove(expectedVersion int64, now time.Time) error {
	if expectedVersion != m.Version {
		return fmt.Errorf("%w: stale membership version", shared.ErrConflict)
	}
	if now.IsZero() {
		return fmt.Errorf("%w: timestamp is required", shared.ErrValidation)
	}
	if m.Status == MembershipRemoved {
		return nil
	}
	m.Status = MembershipRemoved
	m.Epoch++
	m.bump(now)
	return nil
}

func (m *Membership) mutable(expectedVersion int64, now time.Time) error {
	if expectedVersion != m.Version {
		return fmt.Errorf("%w: stale membership version", shared.ErrConflict)
	}
	if m.Status == MembershipRemoved {
		return fmt.Errorf("%w: removed membership is terminal", shared.ErrForbidden)
	}
	if now.IsZero() {
		return fmt.Errorf("%w: timestamp is required", shared.ErrValidation)
	}
	return nil
}

func (m *Membership) bump(now time.Time) {
	m.Version++
	m.UpdatedAt = now.UTC()
}
