package notification

import "sort"

// catalog is the source of truth for every event type. A filter is listed only when the producer
// fills the field it reads, so a rule can never be saved with a filter that cannot match.
var catalog = map[EventType]EventSpec{
	EventFindingCreated: {
		Type: EventFindingCreated, Label: "Finding created", SchemaVersion: 1, SubjectKind: "finding",
		HasEngagement: true, HasSeverity: true,
		Filters: []Filter{FilterMinSeverity, FilterEngagements, FilterFindingKinds}, MaxDataClass: DataClassDetail,
		Variables: variables(signal("severity", "Severity of the finding"), signal("finding_kind", "Kind of finding"), signal("status", "Initial finding status"), summary("engagement_name", "Name of the engagement"), summary("finding_title", "Title of the finding"), summary("actor", "Who created the finding")),
	},
	EventFindingStatusChanged: {
		Type: EventFindingStatusChanged, Label: "Finding status changed", SchemaVersion: 1, SubjectKind: "finding",
		HasEngagement: true, HasSeverity: true,
		Filters: []Filter{FilterMinSeverity, FilterEngagements, FilterFindingKinds, FilterFromStatuses, FilterToStatuses}, MaxDataClass: DataClassDetail,
		Variables: variables(signal("severity", "Severity of the finding"), signal("finding_kind", "Kind of finding"), signal("from_status", "Previous finding status"), signal("to_status", "New finding status"), summary("engagement_name", "Name of the engagement"), summary("finding_title", "Title of the finding"), summary("actor", "Who changed the finding")),
	},
	EventFindingRetestCompleted: {
		Type: EventFindingRetestCompleted, Label: "Finding retest completed", SchemaVersion: 1, SubjectKind: "finding",
		HasEngagement: true, HasSeverity: true,
		Filters: []Filter{FilterMinSeverity, FilterEngagements, FilterFindingKinds, FilterRetestResults}, MaxDataClass: DataClassDetail,
		Variables: variables(signal("severity", "Severity of the finding"), signal("finding_kind", "Kind of finding"), signal("result", "Retest result"), signal("status", "Resulting finding status"), summary("engagement_name", "Name of the engagement"), summary("finding_title", "Title of the finding"), summary("actor", "Who completed the retest")),
	},
	EventScanFailed:       runEventSpec(EventScanFailed, "Scan failed", "scan_job"),
	EventDASTRunFinished:  runEventSpec(EventDASTRunFinished, "DAST run finished", "dast_run"),
	EventReconRunFinished: runEventSpec(EventReconRunFinished, "Reconnaissance run finished", "recon_run"),
	EventCSPMRunFinished:  cspmRunEventSpec(),
	EventSLABreached: {
		Type: EventSLABreached, Label: "Remediation SLA breached", SchemaVersion: 1, SubjectKind: "finding", HasEngagement: true, HasSeverity: true, HasTeam: true,
		Filters: []Filter{FilterMinSeverity, FilterEngagements, FilterTeams}, MaxDataClass: DataClassSummary,
		Variables: variables(signal("severity", "Severity of the finding"), signal("tier", "SLA tier of the finding"), instant("deadline", "Remediation deadline"), instant("breached_at", "When the SLA breach began"), signal("reminder", "Breach episode reminder state"), summary("engagement_name", "Name of the engagement"), summary("finding_title", "Title of the finding"), summary("actor", "Actor recorded with the event")),
	},
	EventRiskAcceptanceCreated:    riskAcceptanceSpec(EventRiskAcceptanceCreated, "Risk acceptance created", false),
	EventRiskAcceptanceExpiring:   riskAcceptanceSpec(EventRiskAcceptanceExpiring, "Risk acceptance expiring", true),
	EventRiskAcceptanceExpired:    riskAcceptanceSpec(EventRiskAcceptanceExpired, "Risk acceptance expired", false),
	EventEngagementCreated:        engagementEventSpec(EventEngagementCreated, "Engagement created", false),
	EventEngagementStatusChanged:  engagementEventSpec(EventEngagementStatusChanged, "Engagement status changed", false),
	EventEngagementWindowStarting: engagementEventSpec(EventEngagementWindowStarting, "Engagement window starting", true),
	EventEngagementWindowEnding:   engagementEventSpec(EventEngagementWindowEnding, "Engagement window ending", true),
	EventFindingCommented: {
		Type: EventFindingCommented, Label: "Finding commented", SchemaVersion: 1, SubjectKind: "finding", HasEngagement: true, HasSeverity: true,
		Filters: []Filter{FilterMinSeverity, FilterEngagements}, MaxDataClass: DataClassDetail,
		Variables: variables(signal("severity", "Severity of the finding"), signal("status", "Finding status when the comment was added"), summary("actor", "Who added the comment"), detail("comment_excerpt", "Sanitized excerpt of the comment, capped at 500 characters")),
	},
	EventFindingMentioned: {
		Type: EventFindingMentioned, Label: "Finding mention", SchemaVersion: 1, SubjectKind: "finding", HasEngagement: true, HasSeverity: true,
		Filters: []Filter{FilterMinSeverity, FilterEngagements}, MaxDataClass: DataClassSignal,
		Variables: variables(signal("severity", "Severity of the finding"), signal("status", "Finding status when the mention was added")),
	},
	EventApprovalRequested: approvalEventSpec(EventApprovalRequested, "Approval requested"),
	EventApprovalDecided:   approvalEventSpec(EventApprovalDecided, "Approval decided"),
	EventApprovalTimedOut:  approvalEventSpec(EventApprovalTimedOut, "Approval timed out"),
	EventIncidentUpdated: {
		Type: EventIncidentUpdated, Label: "Incident updated", SchemaVersion: 1, SubjectKind: "incident", HasEngagement: true, HasSeverity: true,
		Filters: []Filter{FilterMinSeverity, FilterEngagements}, MaxDataClass: DataClassSummary,
		Variables: variables(signal("severity", "Severity of the incident"), signal("update_kind", "Kind of incident update"), signal("status", "Current incident status"), signal("disposition", "Current incident disposition"), summary("actor", "Who updated the incident"), summary("incident_title", "Title of the incident"), summary("owner", "Current incident owner")),
	},
	EventResponseFinished: {
		Type: EventResponseFinished, Label: "Response finished", SchemaVersion: 1, SubjectKind: "response", HasEngagement: true,
		Filters: []Filter{FilterEngagements, FilterOutcomes}, MaxDataClass: DataClassDetail,
		Variables: variables(signal("outcome", "Terminal response outcome"), signal("action_kind", "Kind of governed response action"), summary("actor", "Actor recorded with the response"), summary("engagement_name", "Name of the associated engagement"), detail("target", "Sanitized response target")),
	},
	EventEvidenceChainBroken: {
		Type: EventEvidenceChainBroken, Label: "Evidence chain broken", SchemaVersion: 1, SubjectKind: "evidence_chain", HasEngagement: true, HasSeverity: true,
		MaxDataClass: DataClassSummary, Mandatory: true,
		Variables: variables(signal("severity", "Severity of the custody failure"), signal("reason_code", "Stable reason the evidence chain failed verification"), summary("engagement_name", "Name of the associated engagement")),
	},
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
		Type: EventScanCompleted, Label: "Scan completed", SchemaVersion: 2, SubjectKind: "scan_job",
		HasEngagement: true,
		Filters:       []Filter{FilterEngagements},
		MaxDataClass:  DataClassDetail,
		Variables: variables(
			signal("scan_kind", "Kind of scan, such as sast or dast"),
			signal("total_count", "Total publishable findings in this scan"),
			signal("critical_count", "Critical publishable findings in this scan"),
			signal("high_count", "High severity publishable findings in this scan"),
			signal("medium_count", "Medium severity publishable findings in this scan"),
			signal("low_count", "Low severity publishable findings in this scan"),
			signal("info_count", "Informational publishable findings in this scan"),
			signal("new_count", "Findings newly observed from a comparable scan"),
			signal("fixed_count", "Findings no longer observed from a comparable scan"),
			signal("unchanged_count", "Findings retained from a comparable scan"),
			signal("delta_available", "Whether new, fixed and unchanged counts compare a compatible prior scan"),
			summary("engagement_name", "Name of the engagement"),
			summary("target", "Scan target without credentials, query or fragment"),
			list("findings", "Bounded publishable findings from this scan", DataClassDetail, 50, "id", "severity", "title", "status"),
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

func runEventSpec(typ EventType, label, subjectKind string) EventSpec {
	return EventSpec{
		Type: typ, Label: label, SchemaVersion: 1, SubjectKind: subjectKind, HasEngagement: true,
		Filters: []Filter{FilterEngagements, FilterScanKinds, FilterOutcomes, FilterProviders}, MaxDataClass: DataClassSummary,
		Variables: variables(
			signal("scan_kind", "Kind of scan or run"), signal("outcome", "Terminal run outcome"), signal("provider", "Run provider"),
			signal("counts_available", "Whether a total finding count was captured"), signal("severity_counts_available", "Whether severity finding counts were captured"),
			signal("total_count", "Total findings in the run"), signal("critical_count", "Critical findings in the run"), signal("high_count", "High findings in the run"),
			signal("medium_count", "Medium findings in the run"), signal("low_count", "Low findings in the run"), signal("info_count", "Informational findings in the run"), signal("error_code", "Stable failure code"),
			summary("engagement_name", "Name of the engagement"), summary("target", "Sanitized run target"),
		),
	}
}

func cspmRunEventSpec() EventSpec {
	spec := runEventSpec(EventCSPMRunFinished, "Cloud posture run finished", "cspm_run")
	spec.Filters = []Filter{FilterEngagements, FilterOutcomes, FilterProviders}
	return spec
}

func riskAcceptanceSpec(typ EventType, label string, expiring bool) EventSpec {
	filters := []Filter{FilterMinSeverity, FilterEngagements, FilterTeams}
	if expiring {
		filters = append(filters, FilterLeadTime)
	}
	return EventSpec{
		Type: typ, Label: label, SchemaVersion: 1, SubjectKind: "finding", HasEngagement: true, HasSeverity: true, HasTeam: true, HasLeadTime: expiring,
		Filters: filters, MaxDataClass: DataClassSummary,
		Variables: variables(
			signal("severity", "Severity of the finding"), signal("tier", "Risk acceptance tier"), instant("accepted_at", "When risk was accepted"), instant("expires_at", "When risk acceptance expires"), instant("deadline", "Finding remediation deadline"), signal("reminder", "Reminder state"), signal("lead_time_hours", "Hours until expiry"),
			summary("engagement_name", "Name of the engagement"), summary("finding_title", "Title of the finding"), summary("actor", "Actor recorded with the event"),
		),
	}
}

func engagementEventSpec(typ EventType, label string, leadTime bool) EventSpec {
	filters := []Filter{FilterEngagements}
	if leadTime {
		filters = append(filters, FilterLeadTime)
	}
	return EventSpec{
		Type: typ, Label: label, SchemaVersion: 1, SubjectKind: "engagement", HasEngagement: true, HasLeadTime: leadTime,
		Filters: filters, MaxDataClass: DataClassSummary,
		Variables: variables(
			signal("status", "Current engagement status"), signal("from_status", "Previous engagement status"), signal("to_status", "New engagement status"),
			instant("authorized_from", "Start of the engagement authorization window"), instant("authorized_to", "End of the engagement authorization window"), signal("timezone", "IANA time zone of the engagement"), signal("boundary", "Authorization boundary that triggered the reminder"), signal("lead_time_hours", "Hours before the authorization boundary"),
			summary("engagement_name", "Name of the engagement"), summary("actor", "Actor recorded with the event"),
		),
	}
}

func approvalEventSpec(typ EventType, label string) EventSpec {
	return EventSpec{
		Type: typ, Label: label, SchemaVersion: 1, SubjectKind: "approval", HasEngagement: true,
		Filters: []Filter{FilterEngagements, FilterKinds}, MaxDataClass: DataClassSummary,
		Variables: variables(signal("kind", "Approval kind"), signal("status", "Approval status"), signal("decision", "Recorded approval decision"), instant("expires_at", "When the approval expires"), summary("actor", "Actor recorded with the approval"), summary("engagement_name", "Name of the engagement")),
	}
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

func list(name, description string, class DataClass, cap int, fields ...string) Variable {
	return Variable{Name: name, Class: class, Description: description, ListCap: cap, ItemFields: append([]string(nil), fields...)}
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
