package incident

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	maxActorBytes     = 256
	maxRationaleRunes = 4000
)

// EventKind identifies the one mutation an immutable IncidentEvent applies.
type EventKind string

const (
	EventCreated            EventKind = "incident_created"
	EventStateChanged       EventKind = "incident_state_changed"
	EventDispositionChanged EventKind = "incident_disposition_changed"
	EventDetectionLinked    EventKind = "incident_detection_linked"
)

// Valid reports whether k is a supported event kind.
func (k EventKind) Valid() bool {
	switch k {
	case EventCreated, EventStateChanged, EventDispositionChanged, EventDetectionLinked:
		return true
	default:
		return false
	}
}

// IncidentEvent is one immutable append to an Incident stream. Revision is the aggregate sequence,
// OccurredAt is event time, and RecordedAt is control-plane append time. A late detection may therefore
// have an OccurredAt older than earlier revisions while RecordedAt remains monotonic.
//
// The payload is discriminated by Kind and validated strictly: unused typed fields must be zero so an
// adapter cannot persist ambiguous state and later interpret it differently.
type IncidentEvent struct {
	ID           shared.ID
	IncidentID   shared.ID
	TenantID     shared.ID
	EngagementID shared.ID
	AssetID      shared.ID
	Revision     uint64
	Kind         EventKind
	Actor        string
	Rationale    string
	OccurredAt   time.Time
	RecordedAt   time.Time

	FromState       State
	ToState         State
	FromDisposition Disposition
	ToDisposition   Disposition
	DetectionID     shared.ID
}

// Validate rejects malformed, ambiguous, or unauthorized event material before it reaches a stream.
func (e IncidentEvent) Validate() error {
	if e.ID.IsZero() || e.IncidentID.IsZero() || e.TenantID.IsZero() ||
		e.EngagementID.IsZero() || e.AssetID.IsZero() {
		return fmt.Errorf("%w: incident event identity and scope are required", shared.ErrValidation)
	}
	if e.Revision == 0 {
		return fmt.Errorf("%w: incident event revision must be positive", shared.ErrValidation)
	}
	if !e.Kind.Valid() {
		return fmt.Errorf("%w: unknown incident event kind %q", shared.ErrValidation, e.Kind)
	}
	if err := validateActor(e.Actor); err != nil {
		return err
	}
	if err := validateRationale(e.Rationale, e.Kind == EventStateChanged || e.Kind == EventDispositionChanged); err != nil {
		return err
	}
	if e.OccurredAt.IsZero() || e.RecordedAt.IsZero() {
		return fmt.Errorf("%w: incident event timestamps are required", shared.ErrValidation)
	}
	if e.OccurredAt.After(e.RecordedAt) {
		return fmt.Errorf("%w: incident event occurred-at is after recorded-at", shared.ErrValidation)
	}

	switch e.Kind {
	case EventCreated:
		if e.Revision != 1 || e.FromState != "" || e.ToState != StateNew ||
			e.FromDisposition != "" || e.ToDisposition != DispositionUnknown || e.DetectionID.IsZero() {
			return fmt.Errorf("%w: incident-created payload is invalid", shared.ErrValidation)
		}
	case EventStateChanged:
		if !e.FromState.CanTransitionTo(e.ToState) || e.FromDisposition != "" ||
			e.ToDisposition != "" || !e.DetectionID.IsZero() {
			return fmt.Errorf("%w: %w: cannot transition from %q to %q", shared.ErrValidation, ErrInvalidTransition, e.FromState, e.ToState)
		}
	case EventDispositionChanged:
		if !e.FromDisposition.Valid() || !e.ToDisposition.Valid() || e.FromDisposition == e.ToDisposition ||
			e.FromState != "" || e.ToState != "" || !e.DetectionID.IsZero() {
			return fmt.Errorf("%w: incident disposition-change payload is invalid", shared.ErrValidation)
		}
		if shared.IsMachineActor(e.Actor) {
			return fmt.Errorf("%w: incident disposition requires a human principal", shared.ErrForbidden)
		}
	case EventDetectionLinked:
		if e.DetectionID.IsZero() || e.FromState != "" || e.ToState != "" ||
			e.FromDisposition != "" || e.ToDisposition != "" {
			return fmt.Errorf("%w: incident detection-link payload is invalid", shared.ErrValidation)
		}
	}
	return nil
}

func validateActor(actor string) error {
	if actor == "" || actor != strings.TrimSpace(actor) || len(actor) > maxActorBytes || !utf8.ValidString(actor) {
		return fmt.Errorf("%w: incident event actor is required, canonical UTF-8, and at most %d bytes", shared.ErrValidation, maxActorBytes)
	}
	return nil
}

func validateRationale(rationale string, required bool) error {
	if rationale != strings.TrimSpace(rationale) || !utf8.ValidString(rationale) {
		return fmt.Errorf("%w: incident event rationale must be canonical UTF-8", shared.ErrValidation)
	}
	runes := []rune(rationale)
	if required && len(runes) < 3 {
		return fmt.Errorf("%w: incident event rationale must be at least 3 characters", shared.ErrValidation)
	}
	if len(runes) > maxRationaleRunes {
		return fmt.Errorf("%w: incident event rationale exceeds %d characters", shared.ErrValidation, maxRationaleRunes)
	}
	for _, r := range runes {
		if r < 32 && r != '\n' && r != '\t' {
			return fmt.Errorf("%w: incident event rationale contains a control character", shared.ErrValidation)
		}
	}
	return nil
}

func canonicalEvent(e IncidentEvent) IncidentEvent {
	e.OccurredAt = e.OccurredAt.UTC()
	e.RecordedAt = e.RecordedAt.UTC()
	return e
}

// Equal reports exact semantic equality, including identity, payload, attribution, and both timestamps.
// Rebuild uses it to distinguish an idempotent EventID retry from a conflicting replay.
func (e IncidentEvent) Equal(other IncidentEvent) bool {
	return e.ID == other.ID && e.IncidentID == other.IncidentID && e.TenantID == other.TenantID &&
		e.EngagementID == other.EngagementID && e.AssetID == other.AssetID && e.Revision == other.Revision &&
		e.Kind == other.Kind && e.Actor == other.Actor && e.Rationale == other.Rationale &&
		e.OccurredAt.Equal(other.OccurredAt) && e.RecordedAt.Equal(other.RecordedAt) &&
		e.FromState == other.FromState && e.ToState == other.ToState &&
		e.FromDisposition == other.FromDisposition && e.ToDisposition == other.ToDisposition &&
		e.DetectionID == other.DetectionID
}
