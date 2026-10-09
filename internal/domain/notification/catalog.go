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
		Variables: variables(
			signal("severity", "Severity of the assessed risk"),
			signal("action_type", "Kind of action requested, such as escalation"),
			summary("engagement_name", "Name of the engagement"),
		),
	},
	EventScanCompleted: {
		Type: EventScanCompleted, Label: "Scan completed", SchemaVersion: 1, SubjectKind: "scan_job",
		HasEngagement: true,
		Filters:       []Filter{FilterEngagements},
		MaxDataClass:  DataClassSummary,
		Variables: variables(
			signal("scan_kind", "Kind of scan, such as sast or dast"),
			summary("engagement_name", "Name of the engagement"),
			summary("target", "Scan target without credentials, query or fragment"),
		),
	},
	EventQualityGateFailed: {
		Type: EventQualityGateFailed, Label: "Quality gate failed", SchemaVersion: 1, SubjectKind: "project_analysis",
		MaxDataClass: DataClassSummary,
		Variables: variables(
			signal("failed_conditions", "Number of gate conditions that failed"),
			summary("project_name", "Name of the project"),
		),
	},
	EventSLAApproaching: {
		Type: EventSLAApproaching, Label: "SLA approaching deadline", SchemaVersion: 1, SubjectKind: "finding",
		HasEngagement: true, HasLeadTime: true,
		Filters:      []Filter{FilterEngagements, FilterLeadTime},
		MaxDataClass: DataClassSummary,
		Variables: variables(
			signal("tier", "SLA tier of the finding"),
			instant("deadline", "Remediation deadline"),
			signal("lead_time_hours", "Hours before the deadline the rule asked to be told"),
			summary("engagement_name", "Name of the engagement"),
			summary("finding_title", "Title of the finding"),
		),
	},
	EventFleetAgentOffline: {
		Type: EventFleetAgentOffline, Label: "Fleet agent offline", SchemaVersion: 1, SubjectKind: "fleet_agent",
		MaxDataClass: DataClassSummary,
		Variables: variables(
			instant("last_seen_at", "Last heartbeat of the agent"),
			summary("agent_name", "Name of the agent"),
		),
	},
	EventIncidentCreated: {
		Type: EventIncidentCreated, Label: "Incident created", SchemaVersion: 1, SubjectKind: "incident",
		HasEngagement: true, HasSeverity: true,
		Filters:      []Filter{FilterMinSeverity, FilterEngagements},
		MaxDataClass: DataClassDetail,
		Variables: variables(
			signal("severity", "Severity of the incident"),
			summary("engagement_name", "Name of the engagement"),
			detail("asset_name", "Name of the affected asset"),
		),
	},
	EventOwnershipChanged: {
		Type: EventOwnershipChanged, Label: "Finding ownership changed", SchemaVersion: 1, SubjectKind: "finding",
		HasEngagement: true, HasTeam: true,
		Filters:      []Filter{FilterEngagements, FilterTeams},
		MaxDataClass: DataClassDetail,
		Variables: variables(
			summary("engagement_name", "Name of the engagement"),
			summary("finding_title", "Title of the finding"),
			summary("old_team", "Previous owning team"),
			summary("new_team", "New owning team"),
			summary("old_assignee", "Previous assignee"),
			summary("new_assignee", "New assignee"),
			summary("actor", "Who made the change"),
			summary("reason", "Reason recorded with the change"),
		),
	},
	EventDestinationChanged: {
		Type: EventDestinationChanged, Label: "Destination changed", SchemaVersion: 1, SubjectKind: "user_contact",
		MaxDataClass: DataClassSummary, OperatorOnly: true,
		Variables: variables(),
	},
	EventChannelPaused: {
		Type: EventChannelPaused, Label: "Channel paused", SchemaVersion: 1, SubjectKind: "channel",
		MaxDataClass: DataClassSummary, OperatorOnly: true,
		Variables: variables(),
	},
	EventTest: {
		Type: EventTest, Label: "Channel test", SchemaVersion: 1, SubjectKind: "channel",
		MaxDataClass: DataClassSignal, OperatorOnly: true,
		Variables: variables(),
	},
}

// commonVariables are declared on every event type. A "*" template is validated against every
// event it can match (#1370), so these are the variables such a template can use.
var commonVariables = []Variable{
	signal("event_type", "Event type, such as scan.completed"),
	signal("event_label", "Readable name of the event type"),
	instant("occurred_at", "When the event happened"),
	summary("title", "Title of the event"),
	summary("summary", "One-sentence summary of the event"),
}

// variables returns the common variables followed by the event's own.
func variables(own ...Variable) []Variable {
	return append(append(make([]Variable, 0, len(commonVariables)+len(own)), commonVariables...), own...)
}

func signal(name, description string) Variable {
	return Variable{Name: name, Class: DataClassSignal, Description: description}
}

// instant is a signal-class time variable, shown in the tenant's time zone.
func instant(name, description string) Variable {
	return Variable{Name: name, Class: DataClassSignal, Description: description, Format: VariableFormatTime}
}

func summary(name, description string) Variable {
	return Variable{Name: name, Class: DataClassSummary, Description: description}
}

func detail(name, description string) Variable {
	return Variable{Name: name, Class: DataClassDetail, Description: description}
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
