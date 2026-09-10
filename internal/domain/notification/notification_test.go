package notification

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestRuleMatchesFilters(t *testing.T) {
	now := time.Now()
	data, _ := json.Marshal(map[string]any{"action_type": "escalation"})
	e := Event{TenantID: "tenant", ID: "event", Type: EventVulnerabilityAction, SourceKind: "risk", SourceID: "source", EngagementID: "eng", Severity: shared.SeverityHigh, SchemaVersion: 1, OccurredAt: now, Data: data}
	r := Rule{TenantID: "tenant", ID: "rule", Name: "high escalation", Enabled: true, EventType: EventVulnerabilityAction, MinSeverity: shared.SeverityHigh, ActionTypes: []string{"escalation"}, EngagementIDs: []shared.ID{"eng"}, ChannelIDs: []shared.ID{"channel"}, Revision: 1, CreatedAt: now, UpdatedAt: now}
	if err := r.Normalize(); err != nil {
		t.Fatal(err)
	}
	if !r.Matches(e) {
		t.Fatal("expected matching event")
	}
	e.Severity = shared.SeverityMedium
	if r.Matches(e) {
		t.Fatal("severity below threshold matched")
	}
	e.Severity = shared.SeverityHigh
	e.EngagementID = "other"
	if r.Matches(e) {
		t.Fatal("other engagement matched")
	}
}

func TestSLARuleMatchesOnlyItsLeadTime(t *testing.T) {
	now := time.Now()
	r := Rule{TenantID: "tenant", ID: "rule", Name: "24h", Enabled: true, EventType: EventSLAApproaching, ChannelIDs: []shared.ID{"channel"}, LeadTimeSecs: 86400, Revision: 1, CreatedAt: now, UpdatedAt: now}
	if err := r.Normalize(); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(map[string]any{"lead_time_seconds": int64(86400)})
	e := Event{TenantID: "tenant", ID: "event", Type: EventSLAApproaching, SourceKind: "sla", SourceID: "source", SchemaVersion: 1, OccurredAt: now, Data: data}
	if !r.Matches(e) {
		t.Fatal("matching lead time rejected")
	}
	e.Data = json.RawMessage(`{"lead_time_seconds":3600}`)
	if r.Matches(e) {
		t.Fatal("different lead time matched")
	}
}

func TestChannelRequiresEmailRecipients(t *testing.T) {
	now := time.Now()
	c := Channel{TenantID: "tenant", ID: "channel", Name: "mail", Type: ChannelEmail, Enabled: true, Revision: 1, SecretVersion: 1, CreatedAt: now, UpdatedAt: now}
	if c.Validate() == nil {
		t.Fatal("email channel without recipients accepted")
	}
}
