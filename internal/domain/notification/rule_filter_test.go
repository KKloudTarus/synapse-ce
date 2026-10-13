package notification

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ruleWithFilter builds an otherwise valid rule for eventType that uses exactly one filter.
func ruleWithFilter(eventType EventType, filter Filter) Rule {
	now := time.Now()
	r := Rule{TenantID: "tenant", ID: "rule", Name: "rule", Enabled: true, EventType: eventType, ChannelIDs: []shared.ID{"channel"}, Revision: 1, CreatedAt: now, UpdatedAt: now}
	switch filter {
	case FilterMinSeverity:
		r.MinSeverity = shared.SeverityHigh
	case FilterActionTypes:
		r.ActionTypes = []string{"escalation"}
	case FilterEngagements:
		r.EngagementIDs = []shared.ID{"eng"}
	case FilterTeams:
		r.TeamIDs = []shared.ID{"team"}
	case FilterLeadTime:
		r.LeadTimeSecs = 3600
	case FilterFindingKinds:
		r.FindingKinds = []string{"sast"}
	case FilterFromStatuses:
		r.FromStatuses = []string{"triage"}
	case FilterToStatuses:
		r.ToStatuses = []string{"confirmed"}
	case FilterRetestResults:
		r.RetestResults = []string{"remediated"}
	case FilterScanKinds:
		r.ScanKinds = []string{"dast"}
	case FilterOutcomes:
		r.Outcomes = []string{"failed"}
	case FilterProviders:
		r.Providers = []string{"native"}
	}
	return r
}

func TestRuleAcceptsOnlyDeclaredFilters(t *testing.T) {
	filters := []Filter{FilterMinSeverity, FilterActionTypes, FilterEngagements, FilterTeams, FilterLeadTime, FilterFindingKinds, FilterFromStatuses, FilterToStatuses, FilterRetestResults, FilterScanKinds, FilterOutcomes, FilterProviders}
	for _, spec := range EventCatalog() {
		if spec.OperatorOnly {
			continue
		}
		for _, filter := range filters {
			r := ruleWithFilter(spec.Type, filter)
			if spec.HasTeam && filter != FilterTeams {
				r.AllTeams = true
			}
			err := r.Normalize()
			if spec.Allows(filter) && err != nil {
				t.Fatalf("%s rejected declared filter %s: %v", spec.Type, filter, err)
			}
			if !spec.Allows(filter) && !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("%s accepted undeclared filter %s", spec.Type, filter)
			}
		}
	}
}

func TestRuleRejectsEngagementScopeWithoutEngagement(t *testing.T) {
	for _, eventType := range []EventType{EventQualityGateFailed, EventFleetAgentOffline} {
		r := ruleWithFilter(eventType, FilterEngagements)
		if err := r.Normalize(); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("%s accepted engagement_ids: %v", eventType, err)
		}
		r.EngagementIDs = nil
		if err := r.Normalize(); err != nil {
			t.Fatalf("%s without engagement_ids rejected: %v", eventType, err)
		}
	}
}

func TestRuleRejectsOperatorOnlyEvent(t *testing.T) {
	r := ruleWithFilter(EventTest, "")
	if err := r.Normalize(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("rule for %s accepted: %v", EventTest, err)
	}
	r.Enabled = true
	e := Event{TenantID: "tenant", ID: "event", Type: EventTest, SourceKind: "test", SourceID: "s", SchemaVersion: 1, OccurredAt: time.Now(), Data: json.RawMessage(`{}`)}
	if r.Matches(e) {
		t.Fatal("rule matched an operator-only event")
	}
}

func TestExistingRuleFixturesStillMatch(t *testing.T) {
	now := time.Now()
	event := func(eventType EventType, engagement shared.ID, severity shared.Severity, data any) Event {
		raw, _ := json.Marshal(data)
		return Event{TenantID: "tenant", ID: "event", Type: eventType, SourceKind: "source", SourceID: "id", EngagementID: engagement, Severity: severity, SchemaVersion: 1, OccurredAt: now, Data: raw}
	}
	cases := []struct {
		name  string
		rule  Rule
		match Event
		miss  Event
	}{
		{
			name:  "scan by engagement",
			rule:  ruleWithFilter(EventScanCompleted, FilterEngagements),
			match: event(EventScanCompleted, "eng", "", map[string]any{"scan_id": "s"}),
			miss:  event(EventScanCompleted, "other", "", map[string]any{"scan_id": "s"}),
		},
		{
			name:  "incident by severity",
			rule:  ruleWithFilter(EventIncidentCreated, FilterMinSeverity),
			match: event(EventIncidentCreated, "eng", shared.SeverityCritical, map[string]any{"incident_id": "i"}),
			miss:  event(EventIncidentCreated, "eng", shared.SeverityLow, map[string]any{"incident_id": "i"}),
		},
		{
			name:  "quality gate unscoped",
			rule:  ruleWithFilter(EventQualityGateFailed, ""),
			match: event(EventQualityGateFailed, "", "", map[string]any{"analysis_id": "a"}),
			miss:  event(EventFleetAgentOffline, "", "", map[string]any{"agent_id": "a"}),
		},
		{
			name:  "sla default lead time",
			rule:  ruleWithFilter(EventSLAApproaching, ""),
			match: event(EventSLAApproaching, "eng", "", map[string]any{"lead_time_seconds": 86400}),
			miss:  event(EventSLAApproaching, "eng", "", map[string]any{"lead_time_seconds": 3600}),
		},
		{
			name:  "ownership by team",
			rule:  ruleWithFilter(EventOwnershipChanged, FilterTeams),
			match: event(EventOwnershipChanged, "eng", "", OwnershipChanged{DecisionID: "d", FindingID: "f", EngagementID: "eng", NewTeamID: "team"}),
			miss:  event(EventOwnershipChanged, "eng", "", OwnershipChanged{DecisionID: "d", FindingID: "f", EngagementID: "eng", NewTeamID: "other"}),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.rule.Normalize(); err != nil {
				t.Fatal(err)
			}
			if !tc.rule.Matches(tc.match) {
				t.Fatal("expected match")
			}
			if tc.rule.Matches(tc.miss) {
				t.Fatal("unexpected match")
			}
		})
	}
}

func TestEventFiltersValidateAndMatchImmutableEventData(t *testing.T) {
	now := time.Date(2026, 10, 12, 8, 0, 0, 0, time.UTC)
	rule := Rule{TenantID: "tenant", ID: "rule", Name: "finding status", Enabled: true, EventType: EventFindingStatusChanged, ChannelIDs: []shared.ID{"channel"}, Revision: 1, CreatedAt: now, UpdatedAt: now,
		EventFilters: EventFilters{FindingKinds: []string{"sast", "sast"}, FromStatuses: []string{"triage"}, ToStatuses: []string{"confirmed"}}}
	if err := rule.Normalize(); err != nil {
		t.Fatal(err)
	}
	if len(rule.FindingKinds) != 1 || rule.FindingKinds[0] != "sast" {
		t.Fatalf("finding kinds = %#v", rule.FindingKinds)
	}
	data := json.RawMessage(`{"finding_kind":"sast","from_status":"triage","to_status":"confirmed"}`)
	event := Event{TenantID: "tenant", Type: EventFindingStatusChanged, Data: data}
	if !rule.Matches(event) {
		t.Fatal("matching immutable event data did not match")
	}
	event.TenantID = "other"
	if rule.Matches(event) {
		t.Fatal("cross-tenant event matched")
	}
	rule.FindingKinds = []string{"not_a_kind"}
	if err := rule.Normalize(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unknown finding kind = %v, want validation error", err)
	}
	rule = Rule{TenantID: "tenant", ID: "rule2", Name: "run", Enabled: true, EventType: EventCSPMRunFinished, ChannelIDs: []shared.ID{"channel"}, Revision: 1, CreatedAt: now, UpdatedAt: now, EventFilters: EventFilters{ScanKinds: []string{"cspm"}}}
	if err := rule.Normalize(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("CSPM scan-kind selector = %v, want validation error", err)
	}
	rule = Rule{TenantID: "tenant", ID: "rule3", Name: "provider", Enabled: true, EventType: EventCSPMRunFinished, ChannelIDs: []shared.ID{"channel"}, Revision: 1, CreatedAt: now, UpdatedAt: now, EventFilters: EventFilters{Providers: []string{"aws"}}}
	if err := rule.Normalize(); err != nil {
		t.Fatal(err)
	}
	event = Event{TenantID: "tenant", Type: EventCSPMRunFinished, Data: json.RawMessage(`{"provider":"multiple","providers":["aws","azure"]}`)}
	if !rule.Matches(event) {
		t.Fatal("provider array did not match captured provider")
	}
}

func TestLifecycleAllTeamsIncludesUnassignedFindings(t *testing.T) {
	for _, eventType := range []EventType{EventSLABreached, EventRiskAcceptanceCreated, EventRiskAcceptanceExpiring, EventRiskAcceptanceExpired} {
		t.Run(string(eventType), func(t *testing.T) {
			rule := ruleWithFilter(eventType, FilterTeams)
			rule.TeamIDs, rule.AllTeams = nil, true
			if err := rule.Normalize(); err != nil {
				t.Fatal(err)
			}
			event := Event{TenantID: "tenant", Type: eventType, Data: json.RawMessage(`{"finding_id":"finding","lead_time_seconds":86400}`)}
			if !rule.Matches(event) {
				t.Fatal("tenant-wide lifecycle rule excluded an unassigned finding")
			}
			rule.TeamIDs, rule.AllTeams = []shared.ID{"team"}, false
			if rule.Matches(event) {
				t.Fatal("team-specific lifecycle rule included an unassigned finding")
			}
		})
	}
}
