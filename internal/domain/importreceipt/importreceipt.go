// Package importreceipt models durable receipts for logical external imports.
package importreceipt

import (
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Outcome is the durable state of one logical import.
type Outcome string

const (
	OutcomePending  Outcome = "pending"
	OutcomeComplete Outcome = "complete"
	OutcomePartial  Outcome = "partial"
	OutcomeFailed   Outcome = "failed"
)

// Valid reports whether o is a supported import outcome.
func (o Outcome) Valid() bool {
	switch o {
	case OutcomePending, OutcomeComplete, OutcomePartial, OutcomeFailed:
		return true
	default:
		return false
	}
}

// Terminal reports whether o is a finalized outcome.
func (o Outcome) Terminal() bool {
	switch o {
	case OutcomeComplete, OutcomePartial, OutcomeFailed:
		return true
	default:
		return false
	}
}

// Counters preserve the externally observable ingest result for replay.
type Counters struct {
	Accepted     int
	Deduplicated int
	Refused      int
}

// Validate rejects impossible counters rather than silently converting them to zero.
func (c Counters) Validate() error {
	if c.Accepted < 0 || c.Deduplicated < 0 || c.Refused < 0 {
		return fmt.Errorf("%w: import receipt counters cannot be negative", shared.ErrValidation)
	}
	return nil
}

// Receipt is the durable identity and outcome of one logical import.
//
// The idempotency identity is (tenant, engagement, source identity, digest). ParserVersion is deliberately
// not part of that identity: retrying the same logical source bytes after a deploy must resolve the same
// receipt instead of manufacturing a second history entry.
type Receipt struct {
	ID             shared.ID
	TenantID       shared.ID
	EngagementID   shared.ID
	SourceIdentity string
	Digest         string
	ParserVersion  string
	Outcome        Outcome
	Counters       Counters
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// Validate enforces the invariants shared by every receipt store.
func (r Receipt) Validate() error {
	if r.ID.IsZero() {
		return fmt.Errorf("%w: import receipt needs an id", shared.ErrValidation)
	}
	if r.TenantID.IsZero() {
		return fmt.Errorf("%w: import receipt needs a tenant", shared.ErrValidation)
	}
	if r.EngagementID.IsZero() {
		return fmt.Errorf("%w: import receipt needs an engagement", shared.ErrValidation)
	}
	if strings.TrimSpace(r.SourceIdentity) == "" {
		return fmt.Errorf("%w: import receipt needs a source identity", shared.ErrValidation)
	}
	if strings.TrimSpace(r.Digest) == "" {
		return fmt.Errorf("%w: import receipt needs a digest", shared.ErrValidation)
	}
	if strings.TrimSpace(r.ParserVersion) == "" {
		return fmt.Errorf("%w: import receipt needs a parser version", shared.ErrValidation)
	}
	if !r.Outcome.Valid() {
		return fmt.Errorf("%w: import receipt outcome %q is not supported", shared.ErrValidation, r.Outcome)
	}
	if err := r.Counters.Validate(); err != nil {
		return err
	}
	if r.Outcome == OutcomeComplete && r.Counters.Refused != 0 {
		return fmt.Errorf("%w: a complete import receipt cannot contain refused results", shared.ErrValidation)
	}
	if r.CreatedAt.IsZero() || r.UpdatedAt.IsZero() {
		return fmt.Errorf("%w: import receipt needs created and updated timestamps", shared.ErrValidation)
	}
	if r.UpdatedAt.Before(r.CreatedAt) {
		return fmt.Errorf("%w: import receipt updated_at precedes created_at", shared.ErrValidation)
	}
	return nil
}

// IdempotencyKey is the exact identity enforced by the persistent unique constraint.
func IdempotencyKey(r Receipt) string {
	return strings.Join([]string{
		r.TenantID.String(),
		r.EngagementID.String(),
		r.SourceIdentity,
		r.Digest,
	}, "\x00")
}
