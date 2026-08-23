package incident

import (
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/riskassessment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// EventKind is the type of an incident state-transition event. The log of these, folded in order, IS the
// incident.
type EventKind string

const (
	EventCreated           EventKind = "created"
	EventDetectionAttached EventKind = "detection_attached"
	EventDetectionDetached EventKind = "detection_detached"
	EventStatusChanged     EventKind = "status_changed"
	EventOwnerChanged      EventKind = "owner_changed"
	EventDispositionSet    EventKind = "disposition_set"
	EventRiskReassessed    EventKind = "risk_reassessed"
	EventAnalystCommented  EventKind = "analyst_commented"
	EventMerged            EventKind = "merged"
	EventResponseRequested EventKind = "response_requested"
	EventResponseVerified  EventKind = "response_verified"
)

// IncidentEvent is one attributable change to an incident. Exactly the payload field(s) named for its Kind
// are meaningful; the rest are zero. Actor is the human or agent id responsible (attribution, golden rule
// 6). The events for one incident share IncidentID and are ordered by the position they are folded in
// (their 1-based index becomes the projection Revision).
type IncidentEvent struct {
	IncidentID shared.ID
	Kind       EventKind
	At         time.Time
	Actor      string

	// Created
	AssetID  shared.ID
	Title    string
	Severity shared.Severity
	// Created (optional first detection) + DetectionAttached/Detached
	DetectionID shared.ID
	// StatusChanged
	To State
	// OwnerChanged
	Owner string
	// DispositionSet
	Disposition Disposition
	// RiskReassessed
	Risk *riskassessment.RiskAssessment
	// AnalystCommented
	Comment string
	// Merged (this incident was merged INTO another)
	MergedInto shared.ID
	// ResponseRequested / ResponseVerified
	ResponseActionID shared.ID
	// ResponseVerified
	Verified bool
}

// Validate enforces a well-formed event for its kind: the required identity and the payload the kind needs.
func (e IncidentEvent) Validate() error {
	if e.IncidentID.IsZero() {
		return fmt.Errorf("%w: incident event has no incident id", shared.ErrValidation)
	}
	if e.At.IsZero() {
		return fmt.Errorf("%w: incident event has no timestamp", shared.ErrValidation)
	}
	if e.Actor == "" {
		return fmt.Errorf("%w: incident event has no actor", shared.ErrValidation)
	}
	switch e.Kind {
	case EventCreated:
		if e.AssetID.IsZero() {
			return fmt.Errorf("%w: created event has no asset id", shared.ErrValidation)
		}
		if e.Severity != "" && !e.Severity.Valid() {
			return fmt.Errorf("%w: created event has invalid severity %q", shared.ErrValidation, e.Severity)
		}
	case EventDetectionAttached, EventDetectionDetached:
		if e.DetectionID.IsZero() {
			return fmt.Errorf("%w: %s event has no detection id", shared.ErrValidation, e.Kind)
		}
	case EventStatusChanged:
		if !e.To.Valid() {
			return fmt.Errorf("%w: status_changed event has invalid target state %q", shared.ErrValidation, e.To)
		}
	case EventOwnerChanged:
		if e.Owner == "" {
			return fmt.Errorf("%w: owner_changed event has no owner", shared.ErrValidation)
		}
	case EventDispositionSet:
		if !e.Disposition.Valid() {
			return fmt.Errorf("%w: disposition_set event has invalid disposition %q", shared.ErrValidation, e.Disposition)
		}
	case EventRiskReassessed:
		if e.Risk == nil {
			return fmt.Errorf("%w: risk_reassessed event has no assessment", shared.ErrValidation)
		}
		if err := e.Risk.Validate(); err != nil {
			return err
		}
	case EventAnalystCommented:
		if e.Comment == "" {
			return fmt.Errorf("%w: analyst_commented event has no comment", shared.ErrValidation)
		}
	case EventMerged:
		if e.MergedInto.IsZero() {
			return fmt.Errorf("%w: merged event has no target incident id", shared.ErrValidation)
		}
	case EventResponseRequested, EventResponseVerified:
		if e.ResponseActionID.IsZero() {
			return fmt.Errorf("%w: %s event has no response action id", shared.ErrValidation, e.Kind)
		}
	default:
		return fmt.Errorf("%w: unknown incident event kind %q", shared.ErrValidation, e.Kind)
	}
	return nil
}
