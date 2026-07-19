package issue

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ErrInvalidTransition marks an attempted lifecycle move the graph forbids.
var ErrInvalidTransition = errors.New("invalid issue transition")

// Status is the triage lifecycle vocabulary for a Project code-quality issue.
type Status string

const (
	StatusOpen          Status = "open"
	StatusAccepted      Status = "accepted"
	StatusFalsePositive Status = "false_positive"
	StatusWontFix       Status = "wont_fix"
)

func (s Status) Valid() bool {
	switch s {
	case StatusOpen, StatusAccepted, StatusFalsePositive, StatusWontFix:
		return true
	default:
		return false
	}
}

// Resolved reports whether the status is a triaged terminal decision. A resolved
// issue is retained and sealed, and is exempt from the Project quality gate.
func (s Status) Resolved() bool {
	switch s {
	case StatusAccepted, StatusFalsePositive, StatusWontFix:
		return true
	default:
		return false
	}
}

// GateExempt reports whether an issue in this status is excluded from gate metrics.
func (s Status) GateExempt() bool { return s.Resolved() }

// CanTransitionTo enforces the allowed lifecycle graph: Open triages into any
// resolved bucket, a resolved issue can be re-triaged into another bucket or
// reopened, and no self-transition is permitted.
func (s Status) CanTransitionTo(to Status) bool {
	if s == to || !s.Valid() || !to.Valid() {
		return false
	}
	switch s {
	case StatusOpen:
		return to == StatusAccepted || to == StatusFalsePositive || to == StatusWontFix
	case StatusAccepted, StatusFalsePositive, StatusWontFix:
		return to == StatusOpen || to.Resolved()
	}
	return false
}

// ReviewEvent is one immutable, append-only record of a lifecycle transition.
type ReviewEvent struct {
	ID              shared.ID
	TenantID        shared.ID
	ProjectID       shared.ID
	IssueID         shared.ID
	From            Status
	To              Status
	Actor           string
	Rationale       string
	PreviousVersion int
	Version         int
	CreatedAt       time.Time
}

// TransitionCommand carries the arguments for a lifecycle transition.
type TransitionCommand struct {
	TenantID        shared.ID
	ProjectID       shared.ID
	IssueID         shared.ID
	EventID         shared.ID
	To              Status
	Actor           string
	Rationale       string
	ExpectedVersion int
}

// Transition evaluates and applies a triage decision, returning the new immutable
// Issue state and its ReviewEvent, or an error. Optimistic concurrency is enforced
// via expectedVersion (stale → ErrConflict); the transition graph and rationale are
// validated in the domain, never in the handler.
func (i Issue) Transition(to Status, actor, rationale string, expectedVersion int, eventID shared.ID, now time.Time) (Issue, ReviewEvent, error) {
	if i.Version != expectedVersion {
		return Issue{}, ReviewEvent{}, fmt.Errorf("%w: version mismatch (expected %d, got %d)", shared.ErrConflict, expectedVersion, i.Version)
	}
	if !i.Status.CanTransitionTo(to) {
		return Issue{}, ReviewEvent{}, fmt.Errorf("%w: %w: cannot transition from %s to %s", shared.ErrValidation, ErrInvalidTransition, i.Status, to)
	}
	actorTrimmed := strings.TrimSpace(actor)
	if actorTrimmed == "" {
		return Issue{}, ReviewEvent{}, fmt.Errorf("%w: actor is required", shared.ErrValidation)
	}
	rat := strings.TrimSpace(rationale)
	if len([]rune(rat)) < 3 {
		return Issue{}, ReviewEvent{}, fmt.Errorf("%w: rationale must be at least 3 characters", shared.ErrValidation)
	}
	if len([]rune(rat)) > 4000 {
		return Issue{}, ReviewEvent{}, fmt.Errorf("%w: rationale exceeds maximum length of 4000 characters", shared.ErrValidation)
	}
	for _, r := range rat {
		if r < 32 && r != '\n' && r != '\t' {
			return Issue{}, ReviewEvent{}, fmt.Errorf("%w: rationale contains invalid control characters", shared.ErrValidation)
		}
	}
	if eventID.IsZero() {
		return Issue{}, ReviewEvent{}, fmt.Errorf("%w: event ID is required", shared.ErrValidation)
	}
	if now.IsZero() {
		return Issue{}, ReviewEvent{}, fmt.Errorf("%w: transition timestamp is required", shared.ErrValidation)
	}

	from := i.Status
	updated := i
	updated.Status = to
	updated.Version++
	updated.LastReviewedBy = actorTrimmed
	updated.LastReviewedAt = &now
	updated.Audit.UpdatedAt = now

	event := ReviewEvent{
		ID:              eventID,
		TenantID:        i.TenantID,
		ProjectID:       i.ProjectID,
		IssueID:         i.ID,
		From:            from,
		To:              to,
		Actor:           actorTrimmed,
		Rationale:       rat,
		PreviousVersion: expectedVersion,
		Version:         updated.Version,
		CreatedAt:       now,
	}
	return updated, event, nil
}
