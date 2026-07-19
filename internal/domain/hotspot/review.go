package hotspot

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

var (
	ErrInvalidTransition = errors.New("invalid hotspot transition")
)

// Reviewed returns true if the status represents a reviewed state.
func (s Status) Reviewed() bool {
	switch s {
	case StatusAcknowledged, StatusFixed, StatusSafe:
		return true
	default:
		return false
	}
}

// CanTransitionTo determines if a state transition is allowed.
func (s Status) CanTransitionTo(to Status) bool {
	if s == to {
		return false
	}
	if !s.Valid() || !to.Valid() {
		return false
	}
	switch s {
	case StatusToReview:
		return to == StatusAcknowledged || to == StatusFixed || to == StatusSafe
	case StatusAcknowledged:
		return to == StatusFixed || to == StatusSafe || to == StatusToReview
	case StatusFixed:
		return to == StatusToReview
	case StatusSafe:
		return to == StatusToReview
	}
	return false
}

// ReviewEvent records a transition in the review workflow.
type ReviewEvent struct {
	ID              shared.ID
	TenantID        shared.ID
	ProjectID       shared.ID
	HotspotID       shared.ID
	From            Status
	To              Status
	Actor           string
	Rationale       string
	PreviousVersion int
	Version         int
	CreatedAt       time.Time
}

// TransitionCommand carries the arguments for a review transition.
type TransitionCommand struct {
	TenantID        shared.ID
	ProjectID       shared.ID
	HotspotID       shared.ID
	EventID         shared.ID
	To              Status
	Actor           string
	Rationale       string
	ExpectedVersion int
}

// Lens defines the scope of hotspots to return (overall vs new code).
type Lens string

const (
	LensOverall Lens = "overall"
	LensNewCode Lens = "new-code"
)

// Transition evaluates and applies a review decision, returning a new immutable Hotspot state
// and the corresponding ReviewEvent, or an error if the transition is invalid.
func (h Hotspot) Transition(
	to Status,
	actor string,
	rationale string,
	expectedVersion int,
	eventID shared.ID,
	now time.Time,
) (Hotspot, ReviewEvent, error) {
	if h.Version != expectedVersion {
		return Hotspot{}, ReviewEvent{}, fmt.Errorf("%w: version mismatch (expected %d, got %d)", shared.ErrConflict, expectedVersion, h.Version)
	}
	if !h.Status.CanTransitionTo(to) {
		return Hotspot{}, ReviewEvent{}, fmt.Errorf("%w: cannot transition from %s to %s", ErrInvalidTransition, h.Status, to)
	}

	actorTrimmed := strings.TrimSpace(actor)
	if actorTrimmed == "" {
		return Hotspot{}, ReviewEvent{}, fmt.Errorf("%w: actor is required", shared.ErrValidation)
	}

	rat := strings.TrimSpace(rationale)
	if len([]rune(rat)) < 3 {
		return Hotspot{}, ReviewEvent{}, fmt.Errorf("%w: rationale must be at least 3 characters", shared.ErrValidation)
	}
	if len([]rune(rat)) > 4000 {
		return Hotspot{}, ReviewEvent{}, fmt.Errorf("%w: rationale exceeds maximum length of 4000 characters", shared.ErrValidation)
	}
	for _, r := range rat {
		if r < 32 && r != '\n' && r != '\t' {
			return Hotspot{}, ReviewEvent{}, fmt.Errorf("%w: rationale contains invalid control characters", shared.ErrValidation)
		}
	}

	if eventID.IsZero() {
		return Hotspot{}, ReviewEvent{}, fmt.Errorf("%w: event ID is required", shared.ErrValidation)
	}
	if now.IsZero() {
		return Hotspot{}, ReviewEvent{}, fmt.Errorf("%w: transition timestamp is required", shared.ErrValidation)
	}

	from := h.Status
	
	// Create the mutated clone
	updated := h
	updated.Status = to
	updated.Version++
	updated.LastReviewedBy = actorTrimmed
	updated.LastReviewedAt = &now
	updated.Audit.UpdatedAt = now

	event := ReviewEvent{
		ID:              eventID,
		TenantID:        h.TenantID,
		ProjectID:       h.ProjectID,
		HotspotID:       h.ID,
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
