package notification

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestOwnershipRuleScope(t *testing.T) {
	for _, tc := range []struct {
		name  string
		teams []shared.ID
		all   bool
		event EventType
		valid bool
	}{
		{"old team", []shared.ID{"pay"}, false, EventOwnershipChanged, true},
		{"both teams deduplicated", []shared.ID{"pay", "ops", "pay"}, false, EventOwnershipChanged, true},
		{"explicit tenant subscription", nil, true, EventOwnershipChanged, true},
		{"missing scope", nil, false, EventOwnershipChanged, false},
		{"blank is not all teams", []shared.ID{""}, false, EventOwnershipChanged, false},
		{"whitespace", []shared.ID{" pay "}, false, EventOwnershipChanged, false},
		{"conflicting scope", []shared.ID{"pay"}, true, EventOwnershipChanged, false},
		{"too many IDs", make([]shared.ID, 201), false, EventOwnershipChanged, false},
		{"unrelated event", []shared.ID{"pay"}, false, EventScanCompleted, false},
		{"all teams unrelated event", nil, true, EventScanCompleted, false},
		{"existing event", nil, false, EventScanCompleted, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Rule{TenantID: "tenant", ID: "rule", Name: "Ownership", Enabled: true, EventType: tc.event,
				TeamIDs: tc.teams, AllTeams: tc.all, ChannelIDs: []shared.ID{"channel"}, Revision: 1,
				CreatedAt: time.Now(), UpdatedAt: time.Now()}
			if err := r.Normalize(); (err == nil) != tc.valid {
				t.Fatalf("Normalize=%v valid=%v", err, tc.valid)
			}
			if tc.name == "both teams deduplicated" && (len(r.TeamIDs) != 2 || r.TeamIDs[0] != "ops") {
				t.Fatalf("unstable normalized scope: %v", r.TeamIDs)
			}
		})
	}
}

func TestOwnershipRuleMatchesAffectedTeams(t *testing.T) {
	data, _ := json.Marshal(OwnershipChanged{DecisionID: "decision", FindingID: "finding", EngagementID: "eng", OldTeamID: "pay", NewTeamID: "ops"})
	e := Event{TenantID: "tenant", EngagementID: "eng", Type: EventOwnershipChanged, Data: data}
	for _, tc := range []struct {
		name  string
		teams []shared.ID
		all   bool
		match bool
	}{
		{"losing team", []shared.ID{"pay"}, false, true},
		{"gaining team", []shared.ID{"ops"}, false, true},
		{"OR filter", []shared.ID{"other", "pay"}, false, true},
		{"unaffected team", []shared.ID{"other"}, false, false},
		{"no accidental subscription", nil, false, false},
		{"explicit all", nil, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Rule{TenantID: "tenant", Enabled: true, EventType: EventOwnershipChanged, TeamIDs: tc.teams, AllTeams: tc.all}
			if r.Matches(e) != tc.match {
				t.Fatal("wrong affected-team match")
			}
			r.TenantID = "other"
			if r.Matches(e) {
				t.Fatal("cross-tenant event matched")
			}
			r.TenantID = "tenant"
			r.EngagementIDs = []shared.ID{"other"}
			if r.Matches(e) {
				t.Fatal("engagement filter was bypassed")
			}
			r.EngagementIDs = nil
			r.Enabled = false
			if r.Matches(e) {
				t.Fatal("disabled rule matched")
			}
		})
	}
	all := Rule{TenantID: "tenant", Enabled: true, EventType: EventOwnershipChanged, AllTeams: true}
	for _, raw := range []string{`null`, `{}`, `{"decision_id":"d","finding_id":"f","engagement_id":"other"}`} {
		e.Data = json.RawMessage(raw)
		if all.Matches(e) {
			t.Fatal("malformed event matched", raw)
		}
	}
	e.Data, _ = json.Marshal(OwnershipChanged{DecisionID: "d", FindingID: "f", EngagementID: "eng"})
	if !all.Matches(e) {
		t.Fatal("all-teams subscription must include unowned findings")
	}
}
