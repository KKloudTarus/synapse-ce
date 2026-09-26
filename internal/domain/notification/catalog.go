package notification

import "sort"

// catalog is the source of truth for every event type. A filter is listed only when the producer
// fills the field it reads, so a rule can never be saved with a filter that cannot match.
var catalog = map[EventType]EventSpec{
	EventVulnerabilityAction: {
		Type: EventVulnerabilityAction, SchemaVersion: 1, SubjectKind: "vulnerability_action",
		HasEngagement: true, HasSeverity: true,
		Filters:      []Filter{FilterMinSeverity, FilterActionTypes, FilterEngagements},
		MaxDataClass: DataClassDetail,
	},
	EventScanCompleted: {
		Type: EventScanCompleted, SchemaVersion: 1, SubjectKind: "scan_job",
		HasEngagement: true,
		Filters:       []Filter{FilterEngagements},
		MaxDataClass:  DataClassSummary,
	},
	EventQualityGateFailed: {
		Type: EventQualityGateFailed, SchemaVersion: 1, SubjectKind: "project_analysis",
		MaxDataClass: DataClassSummary,
	},
	EventSLAApproaching: {
		Type: EventSLAApproaching, SchemaVersion: 1, SubjectKind: "finding",
		HasEngagement: true, HasLeadTime: true,
		Filters:      []Filter{FilterEngagements, FilterLeadTime},
		MaxDataClass: DataClassSummary,
	},
	EventFleetAgentOffline: {
		Type: EventFleetAgentOffline, SchemaVersion: 1, SubjectKind: "fleet_agent",
		MaxDataClass: DataClassSummary,
	},
	EventIncidentCreated: {
		Type: EventIncidentCreated, SchemaVersion: 1, SubjectKind: "incident",
		HasEngagement: true, HasSeverity: true,
		Filters:      []Filter{FilterMinSeverity, FilterEngagements},
		MaxDataClass: DataClassDetail,
	},
	EventOwnershipChanged: {
		Type: EventOwnershipChanged, SchemaVersion: 1, SubjectKind: "finding",
		HasEngagement: true, HasTeam: true,
		Filters:      []Filter{FilterEngagements, FilterTeams},
		MaxDataClass: DataClassDetail,
	},
	EventTest: {
		Type: EventTest, SchemaVersion: 1, SubjectKind: "channel",
		MaxDataClass: DataClassSignal, OperatorOnly: true,
	},
}

// LookupEvent returns the spec for an event type.
func LookupEvent(t EventType) (EventSpec, bool) {
	spec, ok := catalog[t]
	if !ok {
		return EventSpec{}, false
	}
	return spec.clone(), true
}

// EventCatalog returns every spec ordered by type.
func EventCatalog() []EventSpec {
	out := make([]EventSpec, 0, len(catalog))
	for _, spec := range catalog {
		out = append(out, spec.clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}
