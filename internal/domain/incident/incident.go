package incident

import (
	"fmt"
	"sort"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Incident is the current projection of an immutable IncidentEvent stream.
type Incident struct {
	ID           shared.ID
	TenantID     shared.ID
	EngagementID shared.ID
	AssetID      shared.ID
	State        State
	Disposition  Disposition
	Revision     uint64
	DetectionIDs []shared.ID
	FirstEventAt time.Time
	LastEventAt  time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
	LastEventID  shared.ID
}

// IncidentRevision is an immutable projection snapshot immediately after one event was applied. It pins
// later risk assessments and investigations to the exact state and evidence membership they consumed.
type IncidentRevision struct {
	IncidentID      shared.ID
	TenantID        shared.ID
	EngagementID    shared.ID
	AssetID         shared.ID
	Revision        uint64
	EventID         shared.ID
	EventKind       EventKind
	State           State
	Disposition     Disposition
	DetectionIDs    []shared.ID
	FirstEventAt    time.Time
	LastEventAt     time.Time
	EventOccurredAt time.Time
	RecordedAt      time.Time
}

// Validate enforces a self-contained revision snapshot suitable for persistence or risk-input pinning.
func (r IncidentRevision) Validate() error {
	if r.IncidentID.IsZero() || r.TenantID.IsZero() || r.EngagementID.IsZero() || r.AssetID.IsZero() || r.EventID.IsZero() {
		return fmt.Errorf("%w: incident revision identity and scope are required", shared.ErrValidation)
	}
	if r.Revision == 0 || !r.EventKind.Valid() || !r.State.Valid() || !r.Disposition.Valid() {
		return fmt.Errorf("%w: incident revision lifecycle is invalid", shared.ErrValidation)
	}
	if r.FirstEventAt.IsZero() || r.LastEventAt.IsZero() || r.EventOccurredAt.IsZero() || r.RecordedAt.IsZero() ||
		r.LastEventAt.Before(r.FirstEventAt) || r.LastEventAt.After(r.RecordedAt) ||
		r.EventOccurredAt.Before(r.FirstEventAt) || r.EventOccurredAt.After(r.LastEventAt) ||
		r.EventOccurredAt.After(r.RecordedAt) {
		return fmt.Errorf("%w: incident revision timestamps are invalid", shared.ErrValidation)
	}
	if err := validateDetectionIDs(r.DetectionIDs); err != nil {
		return err
	}
	return nil
}

// CreateCommand carries platform-generated identity and timestamps for the first stream event. An
// Incident starts with one detection: empty, evidence-free incidents are not valid runtime facts.
type CreateCommand struct {
	EventID, IncidentID, TenantID, EngagementID, AssetID shared.ID
	DetectionID                                          shared.ID
	Actor, Rationale                                     string
	OccurredAt, RecordedAt                               time.Time
}

// StateTransitionCommand changes only lifecycle State at ExpectedRevision.
type StateTransitionCommand struct {
	EventID          shared.ID
	To               State
	Actor, Rationale string
	ExpectedRevision uint64
	OccurredAt       time.Time
	RecordedAt       time.Time
}

// DispositionCommand records a human analyst classification without changing lifecycle State.
type DispositionCommand struct {
	EventID          shared.ID
	To               Disposition
	Actor, Rationale string
	ExpectedRevision uint64
	OccurredAt       time.Time
	RecordedAt       time.Time
}

// LinkDetectionCommand appends one unique supporting detection to an Incident.
type LinkDetectionCommand struct {
	EventID, DetectionID shared.ID
	Actor, Rationale     string
	ExpectedRevision     uint64
	OccurredAt           time.Time
	RecordedAt           time.Time
}

// Create validates and applies the first event in an Incident stream.
func Create(cmd CreateCommand) (Incident, IncidentEvent, error) {
	e := canonicalEvent(IncidentEvent{
		ID: cmd.EventID, IncidentID: cmd.IncidentID, TenantID: cmd.TenantID,
		EngagementID: cmd.EngagementID, AssetID: cmd.AssetID, Revision: 1, Kind: EventCreated,
		Actor: cmd.Actor, Rationale: cmd.Rationale, OccurredAt: cmd.OccurredAt, RecordedAt: cmd.RecordedAt,
		ToState: StateNew, ToDisposition: DispositionUnknown, DetectionID: cmd.DetectionID,
	})
	if err := e.Validate(); err != nil {
		return Incident{}, IncidentEvent{}, err
	}
	current := applyCreated(e)
	if err := current.Validate(); err != nil {
		return Incident{}, IncidentEvent{}, err
	}
	return current, e, nil
}

// TransitionState validates optimistic concurrency and applies one lifecycle event.
func (i Incident) TransitionState(cmd StateTransitionCommand) (Incident, IncidentEvent, error) {
	if err := i.validateCommandRevision(cmd.ExpectedRevision); err != nil {
		return Incident{}, IncidentEvent{}, err
	}
	e := canonicalEvent(IncidentEvent{
		ID: cmd.EventID, IncidentID: i.ID, TenantID: i.TenantID, EngagementID: i.EngagementID,
		AssetID: i.AssetID, Revision: i.Revision + 1, Kind: EventStateChanged,
		Actor: cmd.Actor, Rationale: cmd.Rationale, OccurredAt: cmd.OccurredAt, RecordedAt: cmd.RecordedAt,
		FromState: i.State, ToState: cmd.To,
	})
	return i.applyCommand(e)
}

// SetDisposition records a human analyst classification and leaves State untouched.
func (i Incident) SetDisposition(cmd DispositionCommand) (Incident, IncidentEvent, error) {
	if err := i.validateCommandRevision(cmd.ExpectedRevision); err != nil {
		return Incident{}, IncidentEvent{}, err
	}
	e := canonicalEvent(IncidentEvent{
		ID: cmd.EventID, IncidentID: i.ID, TenantID: i.TenantID, EngagementID: i.EngagementID,
		AssetID: i.AssetID, Revision: i.Revision + 1, Kind: EventDispositionChanged,
		Actor: cmd.Actor, Rationale: cmd.Rationale, OccurredAt: cmd.OccurredAt, RecordedAt: cmd.RecordedAt,
		FromDisposition: i.Disposition, ToDisposition: cmd.To,
	})
	return i.applyCommand(e)
}

// LinkDetection appends a unique evidence link. The link never replaces or removes existing membership.
func (i Incident) LinkDetection(cmd LinkDetectionCommand) (Incident, IncidentEvent, error) {
	if err := i.validateCommandRevision(cmd.ExpectedRevision); err != nil {
		return Incident{}, IncidentEvent{}, err
	}
	if containsID(i.DetectionIDs, cmd.DetectionID) {
		return Incident{}, IncidentEvent{}, fmt.Errorf("%w: detection %s is already linked to incident %s", shared.ErrConflict, cmd.DetectionID, i.ID)
	}
	e := canonicalEvent(IncidentEvent{
		ID: cmd.EventID, IncidentID: i.ID, TenantID: i.TenantID, EngagementID: i.EngagementID,
		AssetID: i.AssetID, Revision: i.Revision + 1, Kind: EventDetectionLinked,
		Actor: cmd.Actor, Rationale: cmd.Rationale, OccurredAt: cmd.OccurredAt, RecordedAt: cmd.RecordedAt,
		DetectionID: cmd.DetectionID,
	})
	return i.applyCommand(e)
}

func (i Incident) validateCommandRevision(expected uint64) error {
	if err := i.Validate(); err != nil {
		return err
	}
	if expected != i.Revision {
		return fmt.Errorf("%w: incident revision changed (expected %d, current %d)", shared.ErrConflict, expected, i.Revision)
	}
	return nil
}

func (i Incident) applyCommand(e IncidentEvent) (Incident, IncidentEvent, error) {
	if err := e.Validate(); err != nil {
		return Incident{}, IncidentEvent{}, err
	}
	next, err := i.applyNext(e)
	if err != nil {
		return Incident{}, IncidentEvent{}, err
	}
	return next, e, nil
}

// Rebuild validates an unordered collection of stream events, removes exact EventID retries, orders the
// unique events by revision, and reconstructs both the current Incident and every immutable revision.
// Conflicting retries, revision gaps/duplicates, cross-scope events, and stale from-values fail closed.
func Rebuild(events []IncidentEvent) (Incident, []IncidentRevision, error) {
	if len(events) == 0 {
		return Incident{}, nil, fmt.Errorf("%w: incident event stream is empty", shared.ErrValidation)
	}
	unique := make([]IncidentEvent, 0, len(events))
	seen := make(map[shared.ID]IncidentEvent, len(events))
	for _, raw := range events {
		e := canonicalEvent(raw)
		if err := e.Validate(); err != nil {
			return Incident{}, nil, fmt.Errorf("incident event %s: %w", e.ID, err)
		}
		if previous, ok := seen[e.ID]; ok {
			if !previous.Equal(e) {
				return Incident{}, nil, fmt.Errorf("%w: incident event id %s was replayed with different material", shared.ErrConflict, e.ID)
			}
			continue
		}
		seen[e.ID] = e
		unique = append(unique, e)
	}
	sort.Slice(unique, func(a, b int) bool {
		if unique[a].Revision != unique[b].Revision {
			return unique[a].Revision < unique[b].Revision
		}
		return unique[a].ID < unique[b].ID
	})
	if unique[0].Kind != EventCreated || unique[0].Revision != 1 {
		return Incident{}, nil, fmt.Errorf("%w: incident stream must begin with revision 1 incident-created", shared.ErrConflict)
	}

	current := applyCreated(unique[0])
	revisions := []IncidentRevision{snapshot(current, unique[0])}
	for _, e := range unique[1:] {
		next, err := current.applyNext(e)
		if err != nil {
			return Incident{}, nil, fmt.Errorf("incident event %s: %w", e.ID, err)
		}
		current = next
		revisions = append(revisions, snapshot(current, e))
	}
	if err := current.Validate(); err != nil {
		return Incident{}, nil, err
	}
	return current.clone(), cloneRevisions(revisions), nil
}

func applyCreated(e IncidentEvent) Incident {
	return Incident{
		ID: e.IncidentID, TenantID: e.TenantID, EngagementID: e.EngagementID, AssetID: e.AssetID,
		State: StateNew, Disposition: DispositionUnknown, Revision: 1,
		DetectionIDs: []shared.ID{e.DetectionID}, FirstEventAt: e.OccurredAt, LastEventAt: e.OccurredAt,
		CreatedAt: e.RecordedAt, UpdatedAt: e.RecordedAt, LastEventID: e.ID,
	}
}

func (i Incident) applyNext(e IncidentEvent) (Incident, error) {
	if e.IncidentID != i.ID || e.TenantID != i.TenantID || e.EngagementID != i.EngagementID || e.AssetID != i.AssetID {
		return Incident{}, fmt.Errorf("%w: incident event scope differs from its stream", shared.ErrValidation)
	}
	if e.Revision != i.Revision+1 {
		return Incident{}, fmt.Errorf("%w: incident event revision is %d, want %d", shared.ErrConflict, e.Revision, i.Revision+1)
	}
	if e.RecordedAt.Before(i.UpdatedAt) {
		return Incident{}, fmt.Errorf("%w: incident recorded-at regressed at revision %d", shared.ErrConflict, e.Revision)
	}
	next := i.clone()
	switch e.Kind {
	case EventCreated:
		return Incident{}, fmt.Errorf("%w: incident-created can only be revision 1", shared.ErrConflict)
	case EventStateChanged:
		if e.FromState != i.State {
			return Incident{}, fmt.Errorf("%w: state event starts at %q, current state is %q", shared.ErrConflict, e.FromState, i.State)
		}
		next.State = e.ToState
	case EventDispositionChanged:
		if e.FromDisposition != i.Disposition {
			return Incident{}, fmt.Errorf("%w: disposition event starts at %q, current disposition is %q", shared.ErrConflict, e.FromDisposition, i.Disposition)
		}
		next.Disposition = e.ToDisposition
	case EventDetectionLinked:
		if containsID(i.DetectionIDs, e.DetectionID) {
			return Incident{}, fmt.Errorf("%w: detection %s is already linked", shared.ErrConflict, e.DetectionID)
		}
		next.DetectionIDs = append(next.DetectionIDs, e.DetectionID)
		sort.Slice(next.DetectionIDs, func(a, b int) bool { return next.DetectionIDs[a] < next.DetectionIDs[b] })
	}
	next.Revision = e.Revision
	next.LastEventID = e.ID
	next.UpdatedAt = e.RecordedAt
	if e.OccurredAt.Before(next.FirstEventAt) {
		next.FirstEventAt = e.OccurredAt
	}
	if e.OccurredAt.After(next.LastEventAt) {
		next.LastEventAt = e.OccurredAt
	}
	if err := next.Validate(); err != nil {
		return Incident{}, err
	}
	return next, nil
}

// Validate enforces projection invariants independently of how the Incident was reconstructed.
func (i Incident) Validate() error {
	if i.ID.IsZero() || i.TenantID.IsZero() || i.EngagementID.IsZero() || i.AssetID.IsZero() || i.LastEventID.IsZero() {
		return fmt.Errorf("%w: incident identity, scope, and last event are required", shared.ErrValidation)
	}
	if !i.State.Valid() || !i.Disposition.Valid() || i.Revision == 0 {
		return fmt.Errorf("%w: incident lifecycle or revision is invalid", shared.ErrValidation)
	}
	if i.CreatedAt.IsZero() || i.UpdatedAt.IsZero() || i.FirstEventAt.IsZero() || i.LastEventAt.IsZero() ||
		i.UpdatedAt.Before(i.CreatedAt) || i.LastEventAt.Before(i.FirstEventAt) || i.LastEventAt.After(i.UpdatedAt) {
		return fmt.Errorf("%w: incident timestamps are invalid", shared.ErrValidation)
	}
	if err := validateDetectionIDs(i.DetectionIDs); err != nil {
		return err
	}
	return nil
}

func (i Incident) clone() Incident {
	c := i
	c.DetectionIDs = append([]shared.ID(nil), i.DetectionIDs...)
	return c
}

func snapshot(i Incident, e IncidentEvent) IncidentRevision {
	return IncidentRevision{
		IncidentID: i.ID, TenantID: i.TenantID, EngagementID: i.EngagementID, AssetID: i.AssetID,
		Revision: i.Revision, EventID: e.ID, EventKind: e.Kind, State: i.State, Disposition: i.Disposition,
		DetectionIDs: append([]shared.ID(nil), i.DetectionIDs...), FirstEventAt: i.FirstEventAt,
		LastEventAt: i.LastEventAt, EventOccurredAt: e.OccurredAt, RecordedAt: e.RecordedAt,
	}
}

func cloneRevisions(values []IncidentRevision) []IncidentRevision {
	out := make([]IncidentRevision, len(values))
	for index, value := range values {
		out[index] = value
		out[index].DetectionIDs = append([]shared.ID(nil), value.DetectionIDs...)
	}
	return out
}

func containsID(values []shared.ID, id shared.ID) bool {
	index := sort.Search(len(values), func(index int) bool { return values[index] >= id })
	return index < len(values) && values[index] == id
}

func validateDetectionIDs(values []shared.ID) error {
	if len(values) == 0 {
		return fmt.Errorf("%w: incident must retain at least one detection", shared.ErrValidation)
	}
	for index, id := range values {
		if id.IsZero() || (index > 0 && values[index-1] >= id) {
			return fmt.Errorf("%w: incident detection ids must be non-zero, unique, and sorted", shared.ErrValidation)
		}
	}
	return nil
}
