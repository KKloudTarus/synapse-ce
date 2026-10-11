package siem

import (
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Lease is a fence around one sink partition. A worker whose token or
// generation no longer matches cannot commit, even if its HTTP call succeeded.
type Lease struct {
	SinkID     shared.ID
	TenantID   shared.ID
	Source     Source
	Owner      string
	Token      int64
	Generation int64
	ExpiresAt  time.Time
}

// Validate checks a lease that is being stored or presented.
func (l Lease) Validate() error {
	if l.SinkID.IsZero() || l.TenantID.IsZero() || !l.Source.Valid() {
		return fmt.Errorf("%w: lease identity is incomplete", shared.ErrValidation)
	}
	if l.Owner == "" || len(l.Owner) > 120 || l.Token < 1 || l.Generation < 1 || l.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: lease owner, token, generation, and expiry are required", shared.ErrValidation)
	}
	return nil
}

// Holds reports whether this lease still authorizes owner at now.
func (l Lease) Holds(owner string, token, generation int64, now time.Time) error {
	if err := l.Validate(); err != nil {
		return err
	}
	if l.Owner != owner || l.Token != token || l.Generation != generation || !now.Before(l.ExpiresAt) {
		return fmt.Errorf("%w: owner %q token %d", ErrStaleLease, owner, token)
	}
	return nil
}

// Claimable reports whether a free or expired lease can be taken.
func Claimable(current Lease, now time.Time) bool {
	if current.Owner == "" || current.Token == 0 {
		return true
	}
	return !now.Before(current.ExpiresAt)
}
