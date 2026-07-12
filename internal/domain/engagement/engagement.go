// Package engagement is the aggregate root for a security-testing project:
// its scope, legal authorization window, and lifecycle status.
package engagement

import (
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Status is the engagement lifecycle state.
type Status string

const (
	StatusDraft     Status = "draft"
	StatusActive    Status = "active"
	StatusCompleted Status = "completed"
	StatusArchived  Status = "archived"
)

// Valid reports whether s is a known engagement status.
func (s Status) Valid() bool {
	switch s {
	case StatusDraft, StatusActive, StatusCompleted, StatusArchived:
		return true
	}
	return false
}

// canTransitionTo reports whether a status change s -> to is allowed by the
// engagement lifecycle: draft -> active -> completed -> archived, with draft and
// active also permitted to go straight to archived (abandon). Archived is
// terminal.
func (s Status) canTransitionTo(to Status) bool {
	switch s {
	case StatusDraft:
		return to == StatusActive || to == StatusArchived
	case StatusActive:
		return to == StatusCompleted || to == StatusArchived
	case StatusCompleted:
		return to == StatusArchived
	}
	return false
}

// Engagement is the aggregate root for a pentest/security assessment.
type Engagement struct {
	ID       shared.ID
	TenantID shared.ID // multi-tenant-ready; zero value = default tenant in single-tenant mode
	Name     string
	Client   string
	Status   Status
	Scope    Scope
	// RoE holds the minimal rules of engagement (allowed tool classes + blackout
	// windows) the execution gate enforces alongside scope + the auth window.
	RoE RoE

	// Authorization window: the execution layer MUST refuse to run tools
	// outside [AuthorizedFrom, AuthorizedTo]. nil bound = open on that side.
	AuthorizedFrom *time.Time
	AuthorizedTo   *time.Time
	// Timezone is the IANA tz the operator entered the window in (display/audit only;
	// enforcement uses the absolute instants above).
	Timezone string

	// LiveReconEnabled gates live reconnaissance: until the
	// sandbox + egress allowlist exist, active recon is lab-only and must be
	// explicitly enabled per engagement. Default false (off).
	LiveReconEnabled bool

	Audit shared.Audit
}

// SetLiveRecon toggles whether live reconnaissance may run for this engagement and
// stamps UpdatedAt. The operator opts in explicitly (lab-only posture).
func (e *Engagement) SetLiveRecon(enabled bool, now time.Time) {
	e.LiveReconEnabled = enabled
	e.Audit.UpdatedAt = now
}

// authClockSkew tolerates small clock differences between the operator's host and
// the server when enforcing the authorization window.
const authClockSkew = 2 * time.Minute

// SetAuthorizationWindow validates and sets the window, stamping UpdatedAt (like
// the other mutators). from must be before to when both are present.
func (e *Engagement) SetAuthorizationWindow(from, to *time.Time, tz string, now time.Time) error {
	if from != nil && to != nil && !from.Before(*to) {
		return fmt.Errorf("%w: authorized_from must be before authorized_to", shared.ErrValidation)
	}
	e.AuthorizedFrom, e.AuthorizedTo, e.Timezone = from, to, strings.TrimSpace(tz)
	e.Audit.UpdatedAt = now
	return nil
}

// New creates a validated Engagement in draft status.
func New(id, tenantID shared.ID, name, client string, now time.Time) (*Engagement, error) {
	if id.IsZero() {
		return nil, fmt.Errorf("%w: engagement id is required", shared.ErrValidation)
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("%w: engagement name is required", shared.ErrValidation)
	}
	return &Engagement{
		ID:       id,
		TenantID: tenantID,
		Name:     name,
		Client:   strings.TrimSpace(client),
		Status:   StatusDraft,
		Scope:    Scope{},
		Audit:    shared.Audit{CreatedAt: now, UpdatedAt: now},
	}, nil
}

// IsAuthorizedAt reports whether testing is legally authorized at time t.
func (e *Engagement) IsAuthorizedAt(t time.Time) bool {
	if e.AuthorizedFrom != nil && t.Before(e.AuthorizedFrom.Add(-authClockSkew)) {
		return false
	}
	if e.AuthorizedTo != nil && t.After(e.AuthorizedTo.Add(authClockSkew)) {
		return false
	}
	return true
}

// AllowsExecution reports whether the engagement's lifecycle status permits
// running tools. Terminal states (completed/archived) mean the test is over, so
// no tool may run regardless of the authorization window. Draft + Active are both
// permitted. Enforced by the execution guard before any tool starts.
func (e *Engagement) AllowsExecution() bool {
	return e.Status != StatusCompleted && e.Status != StatusArchived
}

// Transition validates and applies a lifecycle status change, stamping UpdatedAt.
// Re-setting the current status is a no-op. The execution guard separately
// refuses tools on terminal engagements (AllowsExecution).
func (e *Engagement) Transition(to Status, now time.Time) error {
	if !to.Valid() {
		return fmt.Errorf("%w: unknown engagement status %q", shared.ErrValidation, to)
	}
	if e.Status == to {
		return nil
	}
	if !e.Status.canTransitionTo(to) {
		return fmt.Errorf("%w: engagement cannot transition from %s to %s", shared.ErrValidation, e.Status, to)
	}
	e.Status = to
	e.Audit.UpdatedAt = now
	return nil
}

// SetScope validates and replaces the in/out-of-scope target sets, stamping
// UpdatedAt. Every target must have a known kind and a non-empty value, so the
// execution gate never matches against a malformed entry.
func (e *Engagement) SetScope(in, out []Target, now time.Time) error {
	normalize := func(targets []Target) ([]Target, error) {
		canonical := make([]Target, 0, len(targets))
		for _, t := range targets {
			normalized, err := NormalizeTarget(t, true)
			if err != nil {
				return nil, err
			}
			canonical = append(canonical, normalized)
		}
		return canonical, nil
	}
	canonicalIn, err := normalize(in)
	if err != nil {
		return err
	}
	canonicalOut, err := normalize(out)
	if err != nil {
		return err
	}
	e.Scope = Scope{InScope: canonicalIn, OutOfScope: canonicalOut}
	e.Audit.UpdatedAt = now
	return nil
}
