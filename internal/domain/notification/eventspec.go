package notification

// This file defines the shape of an event declaration. The declarations themselves live in
// catalog.go.

// Filter names a rule filter. An event type accepts only the filters its EventSpec lists.
type Filter string

const (
	FilterMinSeverity Filter = "min_severity"
	FilterActionTypes Filter = "action_types"
	FilterEngagements Filter = "engagement_ids"
	FilterTeams       Filter = "team_ids"
	FilterLeadTime    Filter = "lead_time_seconds"
)

// DataClass is the most sensitive content a payload may carry (EPIC #1327 D7). signal is the event
// type, severity, counts and a deep link; summary adds titles, engagement or project names and
// target hosts; detail adds advisory IDs, assets, file paths and affected-item lists.
type DataClass string

const (
	DataClassSignal  DataClass = "signal"
	DataClassSummary DataClass = "summary"
	DataClassDetail  DataClass = "detail"
)

// Rank orders data classes; an unknown class ranks zero.
func (c DataClass) Rank() int {
	switch c {
	case DataClassSignal:
		return 1
	case DataClassSummary:
		return 2
	case DataClassDetail:
		return 3
	}
	return 0
}

// Variable is one template variable an event exposes. The per-type payload builders declare them.
type Variable struct {
	Name        string    `json:"name"`
	Class       DataClass `json:"class"`
	Description string    `json:"description"`
}

// EventSpec is the single declaration of an event type. Rule validation and matching read it,
// and the event-type API, the rule form and the docs derive from it.
type EventSpec struct {
	Type          EventType `json:"type"`
	SchemaVersion int       `json:"schema_version"`
	// SubjectKind is the entity the event is about, distinct from its idempotency source.
	SubjectKind   string    `json:"subject_kind"`
	HasEngagement bool      `json:"has_engagement"`
	HasSeverity   bool      `json:"has_severity"`
	HasTeam       bool      `json:"has_team"`
	HasLeadTime   bool      `json:"has_lead_time"`
	Filters       []Filter  `json:"filters"`
	MaxDataClass  DataClass `json:"max_data_class"`
	// Mandatory events cannot be muted by a rule or a user preference.
	Mandatory bool `json:"mandatory"`
	// OperatorOnly events are sent on demand to one channel and never matched by rules.
	OperatorOnly bool       `json:"operator_only"`
	Variables    []Variable `json:"variables"`
}

// Allows reports whether rules for this event type may use filter f.
func (s EventSpec) Allows(f Filter) bool {
	for _, allowed := range s.Filters {
		if allowed == f {
			return true
		}
	}
	return false
}

// clone keeps callers from mutating the shared catalog through its slices.
func (s EventSpec) clone() EventSpec {
	s.Filters = append([]Filter(nil), s.Filters...)
	s.Variables = append([]Variable(nil), s.Variables...)
	return s
}
