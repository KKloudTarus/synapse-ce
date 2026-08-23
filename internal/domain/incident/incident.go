package incident

import (
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/riskassessment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Comment is one analyst note on an incident, attributable and timestamped.
type Comment struct {
	At    time.Time
	Actor string
	Text  string
}

// ResponseRef links an incident to a governed response action (the saga itself lives in domain/response,
// C6) and records whether its post-condition has been telemetry-verified.
type ResponseRef struct {
	ActionID shared.ID
	Verified bool
}

// Incident is the projection folded from an incident's event log. It is a VIEW over the events, which
// remain the source of truth; State, Disposition, and Risk are independent. Revision equals the number of
// events folded, so a projection is comparable to any point in the log.
//
// This is DISTINCT from detection.Incident (internal/domain/detection/record.go), which is a lightweight
// rule+asset rollup view of raw detections. This incident.Incident is the richer, event-sourced Phase-C
// case object an analyst triages; a detection.Incident rollup may seed one but does not replace it.
type Incident struct {
	ID           shared.ID
	AssetID      shared.ID
	Title        string
	Severity     shared.Severity
	State        State
	Disposition  Disposition
	OwnerID      string
	DetectionIDs []shared.ID
	Risk         *riskassessment.RiskAssessment
	MergedInto   shared.ID
	Comments     []Comment
	Responses    []ResponseRef
	Revision     int
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// IsMerged reports whether the incident was merged into another.
func (i Incident) IsMerged() bool { return !i.MergedInto.IsZero() }

// Project folds an incident's ordered event log into its current projection. It is deterministic and
// fail-closed: the log must begin with a Created event, every event must validate, must belong to the same
// incident, and a StatusChanged must be a legal transition — otherwise Project returns an error and no
// partial projection. Replaying the same events always yields the same Incident.
func Project(events []IncidentEvent) (Incident, error) {
	if len(events) == 0 {
		return Incident{}, fmt.Errorf("%w: incident has no events", shared.ErrValidation)
	}
	if events[0].Kind != EventCreated {
		return Incident{}, fmt.Errorf("%w: incident log must begin with a created event, got %q", shared.ErrValidation, events[0].Kind)
	}
	var inc Incident
	id := events[0].IncidentID
	var prevAt time.Time
	for i, e := range events {
		if err := e.Validate(); err != nil {
			return Incident{}, fmt.Errorf("incident event %d: %w", i, err)
		}
		if e.IncidentID != id {
			return Incident{}, fmt.Errorf("%w: incident event %d belongs to %s, not %s", shared.ErrValidation, i, e.IncidentID, id)
		}
		// The event log is append-only and causal: an event may not be timestamped before the one before
		// it. A backdated event is rejected rather than silently folded (chain-of-custody integrity).
		if i > 0 && e.At.Before(prevAt) {
			return Incident{}, fmt.Errorf("%w: incident event %d at %s predates the previous event at %s", shared.ErrValidation, i, e.At, prevAt)
		}
		prevAt = e.At
		if i == 0 {
			if err := applyCreated(&inc, e); err != nil {
				return Incident{}, err
			}
		} else if e.Kind == EventCreated {
			return Incident{}, fmt.Errorf("%w: incident event %d is a second created event", shared.ErrValidation, i)
		} else if err := apply(&inc, e); err != nil {
			return Incident{}, fmt.Errorf("incident event %d: %w", i, err)
		}
		inc.Revision = i + 1
		inc.UpdatedAt = e.At
	}
	return inc, nil
}

func applyCreated(inc *Incident, e IncidentEvent) error {
	inc.ID = e.IncidentID
	inc.AssetID = e.AssetID
	inc.Title = e.Title
	inc.Severity = e.Severity
	inc.State = StateNew
	inc.Disposition = DispositionUnknown
	inc.CreatedAt = e.At
	if !e.DetectionID.IsZero() {
		inc.DetectionIDs = []shared.ID{e.DetectionID}
	}
	return nil
}

func apply(inc *Incident, e IncidentEvent) error {
	switch e.Kind {
	case EventDetectionAttached:
		if !containsID(inc.DetectionIDs, e.DetectionID) {
			inc.DetectionIDs = append(inc.DetectionIDs, e.DetectionID)
		}
	case EventDetectionDetached:
		inc.DetectionIDs = removeID(inc.DetectionIDs, e.DetectionID)
	case EventStatusChanged:
		if err := requireTransition(inc.State, e.To); err != nil {
			return err
		}
		inc.State = e.To
	case EventOwnerChanged:
		inc.OwnerID = e.Owner
	case EventDispositionSet:
		inc.Disposition = e.Disposition
	case EventRiskReassessed:
		r := e.Risk.Clone()
		inc.Risk = &r
	case EventAnalystCommented:
		inc.Comments = append(inc.Comments, Comment{At: e.At, Actor: e.Actor, Text: e.Comment})
	case EventMerged:
		inc.MergedInto = e.MergedInto
	case EventResponseRequested:
		if !hasResponse(inc.Responses, e.ResponseActionID) {
			inc.Responses = append(inc.Responses, ResponseRef{ActionID: e.ResponseActionID})
		}
	case EventResponseVerified:
		if !setResponseVerified(inc.Responses, e.ResponseActionID) {
			inc.Responses = append(inc.Responses, ResponseRef{ActionID: e.ResponseActionID, Verified: true})
		}
	default:
		return fmt.Errorf("%w: unhandled incident event kind %q", shared.ErrValidation, e.Kind)
	}
	return nil
}

func containsID(ids []shared.ID, id shared.ID) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

func removeID(ids []shared.ID, id shared.ID) []shared.ID {
	out := ids[:0:0]
	for _, x := range ids {
		if x != id {
			out = append(out, x)
		}
	}
	return out
}

func hasResponse(refs []ResponseRef, id shared.ID) bool {
	for _, r := range refs {
		if r.ActionID == id {
			return true
		}
	}
	return false
}

func setResponseVerified(refs []ResponseRef, id shared.ID) bool {
	for i := range refs {
		if refs[i].ActionID == id {
			refs[i].Verified = true
			return true
		}
	}
	return false
}
