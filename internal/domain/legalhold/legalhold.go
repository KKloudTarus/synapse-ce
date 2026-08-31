// Package legalhold is the pure domain for a LEGAL HOLD on an engagement's data (#635 privacy &
// data governance). A hold suspends retention expiry: while an engagement is held, its
// retention-bounded projection rows must NOT be deleted, even after their retention window elapses —
// preserving data that a legal/regulatory obligation requires kept. Placement and release are audited
// operator actions; this package defines the record + its invariants, not the storage or the HTTP edge.
package legalhold

import (
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Hold is a legal hold placed on one engagement's data within a tenant. Active while ReleasedAt is zero;
// a released hold is retained (append-only history) so the hold+release trail is auditable.
type Hold struct {
	TenantID     shared.ID
	EngagementID shared.ID
	Reason       string // why the data must be preserved — mandatory (accountability)
	PlacedBy     string // the operator who placed it — mandatory
	PlacedAt     time.Time
	ReleasedBy   string    // set on release
	ReleasedAt   time.Time // zero = still active
}

// Active reports whether the hold currently suspends retention.
func (h Hold) Active() bool { return h.ReleasedAt.IsZero() }

// Validate enforces the mandatory fields for placing a hold.
func (h Hold) Validate() error {
	if h.TenantID.IsZero() {
		return fmt.Errorf("%w: legal hold requires a tenant", shared.ErrValidation)
	}
	if h.EngagementID.IsZero() {
		return fmt.Errorf("%w: legal hold requires an engagement id", shared.ErrValidation)
	}
	if strings.TrimSpace(h.Reason) == "" {
		return fmt.Errorf("%w: legal hold requires a reason", shared.ErrValidation)
	}
	if strings.TrimSpace(h.PlacedBy) == "" {
		return fmt.Errorf("%w: legal hold requires the placing operator", shared.ErrValidation)
	}
	return nil
}
