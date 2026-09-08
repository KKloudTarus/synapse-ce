package incident

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
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
	EventTimelineAttached  EventKind = "timeline_attached"
	EventSeverityChanged   EventKind = "severity_changed"
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
	// CorrelationKey is a stable idempotency key for correlator-authored revisions. Other incident writers
	// leave it empty. It lets a retry repair its checkpoint without appending the same revision twice.
	CorrelationKey string

	// Created
	AssetID  shared.ID
	Title    string
	Severity shared.Severity
	// Created (optional first detection) + DetectionAttached/Detached
	DetectionID shared.ID
	// TimelineAttached
	Timeline TimelineRef
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
	// ResponseRequested / ResponseVerified. These immutable fields bind the incident event to the exact
	// governed action and stable target rather than to a reusable action label alone.
	ResponseActionID     shared.ID
	ResponseEngagementID shared.ID
	ResponseActionDigest string
	ResponseTarget       responsesaga.TargetFingerprint
	// ResponseVerified
	ResponseAttemptKey string
	ResponseExecutorID string
	ResponseVerifierID string
	ResponseEvidenceID shared.ID
	Verified           bool
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
	case EventCreated, EventSeverityChanged:
		if e.AssetID.IsZero() {
			if e.Kind == EventCreated {
				return fmt.Errorf("%w: created event has no asset id", shared.ErrValidation)
			}
		}
		if e.Severity != "" && !e.Severity.Valid() {
			return fmt.Errorf("%w: %s event has invalid severity %q", shared.ErrValidation, e.Kind, e.Severity)
		}
		if e.Kind == EventSeverityChanged && e.Severity == "" {
			return fmt.Errorf("%w: severity_changed event has no severity", shared.ErrValidation)
		}
	case EventDetectionAttached, EventDetectionDetached:
		if e.DetectionID.IsZero() {
			return fmt.Errorf("%w: %s event has no detection id", shared.ErrValidation, e.Kind)
		}
	case EventTimelineAttached:
		if err := e.Timeline.Validate(); err != nil {
			return fmt.Errorf("timeline_attached event: %w", err)
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
		if e.MergedInto == e.IncidentID {
			return fmt.Errorf("%w: incident cannot merge into itself", shared.ErrValidation)
		}
	case EventResponseRequested, EventResponseVerified:
		if err := e.validateResponseBinding(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: unknown incident event kind %q", shared.ErrValidation, e.Kind)
	}
	return nil
}

func (e IncidentEvent) validateResponseBinding() error {
	if e.ResponseActionID.IsZero() || e.ResponseEngagementID.IsZero() {
		return fmt.Errorf("%w: %s event has no response action or engagement id", shared.ErrValidation, e.Kind)
	}
	digest, err := hex.DecodeString(strings.TrimSpace(e.ResponseActionDigest))
	if err != nil || len(digest) != 32 {
		return fmt.Errorf("%w: %s event has an invalid response action digest", shared.ErrValidation, e.Kind)
	}
	if err := e.ResponseTarget.Validate(); err != nil {
		return fmt.Errorf("%s event response target: %w", e.Kind, err)
	}
	if e.Kind == EventResponseRequested {
		if e.Verified || e.ResponseAttemptKey != "" || e.ResponseExecutorID != "" ||
			e.ResponseVerifierID != "" || !e.ResponseEvidenceID.IsZero() {
			return fmt.Errorf("%w: response_requested event contains verification provenance", shared.ErrValidation)
		}
		return nil
	}
	if !e.Verified || strings.TrimSpace(e.ResponseAttemptKey) == "" || strings.TrimSpace(e.ResponseExecutorID) == "" ||
		strings.TrimSpace(e.ResponseVerifierID) == "" || e.ResponseEvidenceID.IsZero() {
		return fmt.Errorf("%w: response_verified event has incomplete verification provenance", shared.ErrValidation)
	}
	if strings.EqualFold(strings.TrimSpace(e.ResponseExecutorID), strings.TrimSpace(e.ResponseVerifierID)) {
		return fmt.Errorf("%w: response executor cannot verify its own effect", shared.ErrForbidden)
	}
	if shared.IsMachineActor(e.ResponseVerifierID) {
		return fmt.Errorf("%w: response verification requires a non-machine verifier", shared.ErrForbidden)
	}
	if !strings.EqualFold(strings.TrimSpace(e.Actor), strings.TrimSpace(e.ResponseVerifierID)) {
		return fmt.Errorf("%w: response_verified actor does not match its verifier", shared.ErrForbidden)
	}
	return nil
}
