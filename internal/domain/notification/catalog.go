package notification

import "sort"

// catalog is the source of truth for every event type. A filter is listed only when the producer
// fills the field it reads, so a rule can never be saved with a filter that cannot match.
var catalog = map[EventType]EventSpec{
	EventVulnerabilityAction: {
		Type: EventVulnerabilityAction, Label: "Vulnerability risk action", SchemaVersion: 1, SubjectKind: "vulnerability_action",
		HasEngagement: true, HasSeverity: true,
		Filters:      []Filter{FilterMinSeverity, FilterActionTypes, FilterEngagements},
		MaxDataClass: DataClassDetail,
	},
	EventScanCompleted: {
		Type: EventScanCompleted, Label: "Scan completed", SchemaVersion: 1, SubjectKind: "scan_job",
		HasEngagement: true,
		Filters:       []Filter{FilterEngagements},
		MaxDataClass:  DataClassSummary,
	},
	EventQualityGateFailed: {
		Type: EventQualityGateFailed, Label: "Quality gate failed", SchemaVersion: 1, SubjectKind: "project_analysis",
		MaxDataClass: DataClassSummary,
	},
	EventSLAApproaching: {
		Type: EventSLAApproaching, Label: "SLA approaching deadline", SchemaVersion: 1, SubjectKind: "finding",
		HasEngagement: true, HasLeadTime: true,
		Filters:      []Filter{FilterEngagements, FilterLeadTime},
		MaxDataClass: DataClassSummary,
	},
	EventFleetAgentOffline: {
		Type: EventFleetAgentOffline, Label: "Fleet agent offline", SchemaVersion: 1, SubjectKind: "fleet_agent",
		MaxDataClass: DataClassSummary,
	},
	EventIncidentCreated: {
		Type: EventIncidentCreated, Label: "Incident created", SchemaVersion: 1, SubjectKind: "incident",
		HasEngagement: true, HasSeverity: true,
		Filters:      []Filter{FilterMinSeverity, FilterEngagements},
		MaxDataClass: DataClassDetail,
	},
	EventOwnershipChanged: {
		Type: EventOwnershipChanged, Label: "Finding ownership changed", SchemaVersion: 1, SubjectKind: "finding",
		HasEngagement: true, HasTeam: true,
		Filters:      []Filter{FilterEngagements, FilterTeams},
		MaxDataClass: DataClassDetail,
	},
	EventDestinationChanged: {
		Type: EventDestinationChanged, Label: "Destination changed", SchemaVersion: 1, SubjectKind: "user_contact",
		MaxDataClass: DataClassSummary, OperatorOnly: true,
	},
	EventTest: {
		Type: EventTest, Label: "Channel test", SchemaVersion: 1, SubjectKind: "channel",
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
