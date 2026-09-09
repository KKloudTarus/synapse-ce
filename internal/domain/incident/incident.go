package incident

import (
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
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
	ActionID     shared.ID
	EngagementID shared.ID
	ActionDigest string
	Target       responsesaga.TargetFingerprint
	AttemptKey   string
	ExecutorID   string
	VerifierID   string
	EvidenceID   shared.ID
	Verified     bool
}

// ResponseLink is one durable, not-yet-verified incident response binding. It is derived only from the
// append-only incident log, so a reconciliation pass can recover a crash after the response saga persists
// independently verified evidence but before its ResponseVerified event reaches the incident.
type ResponseLink struct {
	IncidentID shared.ID
	Response   ResponseRef
}

// TimelineRef is one endpoint State Timeline transition causally linked to the incident by signed
// detection provenance. Both OccurredAt and the append-only incident event carrying it preserve the
// transition's event time; storage may clamp a late append to retain a nondecreasing incident log.
type TimelineRef struct {
	EventID    shared.ID
	OccurredAt time.Time
	Kind       string
	Summary    string
}

// Validate rejects an incomplete timeline reference before it enters the incident log.
func (r TimelineRef) Validate() error {
	if r.EventID.IsZero() || r.OccurredAt.IsZero() || r.Kind == "" || r.Summary == "" {
		return fmt.Errorf("%w: invalid incident timeline reference", shared.ErrValidation)
	}
	return nil
}

// Incident is the projection folded from an incident's event log. It is a VIEW over the events, which
// remain the source of truth; State, Disposition, and Risk are independent. Revision equals the number of
// events folded, so a projection is comparable to any point in the log.
//
// This is DISTINCT from detection.Incident (internal/domain/detection/record.go), which is a lightweight
// rule+asset rollup view of raw detections. This incident.Incident is the richer, event-sourced Phase-C
// case object an analyst triages; a detection.Incident rollup may seed one but does not replace it.
// MergeEdge is an immutable tenant-scoped canonicalization proof. Source event sequence binds the edge
// to the append-only log; BridgeKey is the correlator correlation key that proved the merge.
type MergeEdge struct {
	SourceID       shared.ID
	CanonicalID    shared.ID
	BridgeKey      string
	SourceEventSeq int
	Actor          string
	At             time.Time
}

// Member records the original identity and merge proof for one incident represented by a canonical view.
type Member struct {
	ID   shared.ID
	Edge *MergeEdge
}

type Incident struct {
	ID           shared.ID
	AssetID      shared.ID
	EngagementID shared.ID
	Title        string
	Severity     shared.Severity
	State        State
	Disposition  Disposition
	OwnerID      string
	DetectionIDs []shared.ID
	Timeline     []TimelineRef
	Risk         *riskassessment.RiskAssessment
	MergedInto   shared.ID
	// Members is only populated on canonical logical projections; event-sourced per-ID projections leave it empty.
	Members   []Member
	Comments  []Comment
	Responses []ResponseRef
	Revision  int
	CreatedAt time.Time
	UpdatedAt time.Time
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
	inc.EngagementID = e.EngagementID
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
	case EventTimelineAttached:
		if !hasTimelineRef(inc.Timeline, e.Timeline.EventID) {
			inc.Timeline = append(inc.Timeline, e.Timeline)
		}
	case EventSeverityChanged:
		inc.Severity = e.Severity
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
		ref := responseRef(e)
		if existing, found := findResponse(inc.Responses, e.ResponseActionID); found {
			if !sameResponseBinding(existing, ref) {
				return fmt.Errorf("%w: response action %s was requested with conflicting provenance", shared.ErrConflict, e.ResponseActionID)
			}
		} else {
			inc.Responses = append(inc.Responses, ref)
		}
	case EventResponseVerified:
		ref := responseRef(e)
		index, found := findResponseIndex(inc.Responses, e.ResponseActionID)
		if !found {
			return fmt.Errorf("%w: response action %s was verified before it was requested", shared.ErrValidation, e.ResponseActionID)
		}
		if !sameResponseBinding(inc.Responses[index], ref) {
			return fmt.Errorf("%w: response action %s verification provenance does not match its request", shared.ErrConflict, e.ResponseActionID)
		}
		if inc.Responses[index].Verified && inc.Responses[index] != ref {
			return fmt.Errorf("%w: response action %s has conflicting verification provenance", shared.ErrConflict, e.ResponseActionID)
		}
		inc.Responses[index] = ref
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

func hasTimelineRef(refs []TimelineRef, id shared.ID) bool {
	for _, ref := range refs {
		if ref.EventID == id {
			return true
		}
	}
	return false
}

func responseRef(e IncidentEvent) ResponseRef {
	return ResponseRef{
		ActionID: e.ResponseActionID, EngagementID: e.ResponseEngagementID,
		ActionDigest: e.ResponseActionDigest, Target: e.ResponseTarget,
		AttemptKey: e.ResponseAttemptKey, ExecutorID: e.ResponseExecutorID,
		VerifierID: e.ResponseVerifierID, EvidenceID: e.ResponseEvidenceID, Verified: e.Verified,
	}
}

func findResponse(refs []ResponseRef, id shared.ID) (ResponseRef, bool) {
	index, found := findResponseIndex(refs, id)
	if !found {
		return ResponseRef{}, false
	}
	return refs[index], true
}

func findResponseIndex(refs []ResponseRef, id shared.ID) (int, bool) {
	for i := range refs {
		if refs[i].ActionID == id {
			return i, true
		}
	}
	return 0, false
}

func sameResponseBinding(left, right ResponseRef) bool {
	return left.ActionID == right.ActionID && left.EngagementID == right.EngagementID &&
		left.ActionDigest == right.ActionDigest && left.Target == right.Target
}
