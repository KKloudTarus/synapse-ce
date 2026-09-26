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
	}
	return r
}

func TestRuleAcceptsOnlyDeclaredFilters(t *testing.T) {
	filters := []Filter{FilterMinSeverity, FilterActionTypes, FilterEngagements, FilterTeams, FilterLeadTime}
	for _, spec := range EventCatalog() {
		if spec.OperatorOnly {
			continue
		}
		for _, filter := range filters {
			r := ruleWithFilter(spec.Type, filter)
			if spec.Type == EventOwnershipChanged && filter != FilterTeams {
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
