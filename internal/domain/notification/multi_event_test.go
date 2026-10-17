package notification

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestRuleSelectedEventTypesMatchesEachSelectedType(t *testing.T) {
	now := time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)
	rule := Rule{
		TenantID: "tenant", ID: "rule", Name: "finding changes", Enabled: true,
		EventType:  EventFindingCreated,
		EventTypes: []EventType{EventFindingCreated, EventFindingStatusChanged},
		ChannelIDs: []shared.ID{"channel"}, Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
	if err := rule.Normalize(); err != nil {
		t.Fatal(err)
	}
	if got := rule.SelectedEventTypes(); len(got) != 2 || got[0] != EventFindingCreated || got[1] != EventFindingStatusChanged {
		t.Fatalf("selected event types = %v", got)
	}
	for _, eventType := range rule.SelectedEventTypes() {
		event := Event{TenantID: "tenant", ID: shared.ID("event-" + string(eventType)), Type: eventType, SourceKind: "source", SourceID: string(eventType), SchemaVersion: 1, OccurredAt: now, Data: json.RawMessage(`{"finding_kind":"sast"}`)}
		if !rule.MatchesEventType(eventType) || !rule.Matches(event) {
			t.Fatalf("rule did not match selected type %s", eventType)
		}
	}
	if rule.MatchesEventType(EventScanCompleted) {
		t.Fatal("rule matched an unselected event type")
	}
}

func TestRuleMultiEventSelectionRejectsUnsafeOrInconsistentValues(t *testing.T) {
	now := time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)
	base := Rule{TenantID: "tenant", ID: "rule", Name: "rule", Enabled: true, EventType: EventFindingCreated, ChannelIDs: []shared.ID{"channel"}, Revision: 1, CreatedAt: now, UpdatedAt: now}
	for name, mutate := range map[string]func(*Rule){
		"primary differs from first selection": func(r *Rule) { r.EventTypes = []EventType{EventFindingStatusChanged, EventFindingCreated} },
		"duplicate selection":                  func(r *Rule) { r.EventTypes = []EventType{EventFindingCreated, EventFindingCreated} },
		"operator-only selection":              func(r *Rule) { r.EventTypes = []EventType{EventFindingCreated, EventTest} },
		"mention cannot fan out with another event": func(r *Rule) {
			r.EventTypes = []EventType{EventFindingCreated, EventFindingMentioned}
		},
		"shared filter unsupported by member": func(r *Rule) {
			r.EventTypes = []EventType{EventFindingCreated, EventEngagementCreated}
			r.MinSeverity = shared.SeverityHigh
		},
		"team scope unsupported by member": func(r *Rule) {
			r.EventType = EventOwnershipChanged
			r.EventTypes = []EventType{EventOwnershipChanged, EventEngagementCreated}
			r.AllTeams = true
		},
		"recipient role unsupported by member": func(r *Rule) {
			r.EventType = EventApprovalRequested
			r.EventTypes = []EventType{EventApprovalRequested, EventScanCompleted}
			r.RecipientRoles = []string{RoleApprover}
		},
		"lead time default unsupported by member": func(r *Rule) {
			r.EventType = EventSLAApproaching
			r.EventTypes = []EventType{EventSLAApproaching, EventEngagementCreated}
		},
		"more than eight selections": func(r *Rule) {
			r.EventTypes = []EventType{EventFindingCreated, EventFindingStatusChanged, EventFindingCommented, EventFindingRetestCompleted, EventScanCompleted, EventScanFailed, EventIncidentCreated, EventIncidentUpdated, EventEngagementCreated}
		},
	} {
		t.Run(name, func(t *testing.T) {
			rule := base
			mutate(&rule)
			if err := rule.Normalize(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("Normalize() error = %v, want validation", err)
			}
		})
	}
}

func TestRuleMixedTeamSelectionsCannotOmitOrWeakenTeamScope(t *testing.T) {
	now := time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)
	for _, selected := range [][]EventType{
		{EventOwnershipChanged, EventEngagementCreated},
		{EventEngagementCreated, EventOwnershipChanged},
	} {
		t.Run(string(selected[0]), func(t *testing.T) {
			rule := Rule{
				TenantID: "tenant", ID: "rule", Name: "mixed team scope", Enabled: true,
				EventType: selected[0], EventTypes: selected, ChannelIDs: []shared.ID{"channel"},
				Revision: 1, CreatedAt: now, UpdatedAt: now,
			}
			if err := rule.Normalize(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("blank mixed team scope Normalize() error = %v, want validation", err)
			}
			rule.AllTeams = true
			if err := rule.Normalize(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("scoped mixed team selection Normalize() error = %v, want validation", err)
			}
		})
	}
}

func TestRuleLegacySelectionOmitsEventTypes(t *testing.T) {
	now := time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)
	rule := Rule{TenantID: "tenant", ID: "rule", Name: "single", Enabled: true, EventType: EventScanCompleted, ChannelIDs: []shared.ID{"channel"}, Revision: 1, CreatedAt: now, UpdatedAt: now}
	if err := rule.Normalize(); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) == "" || jsonContainsField(encoded, "event_types") {
		t.Fatalf("legacy rule JSON unexpectedly contains event_types: %s", encoded)
	}
}

func jsonContainsField(raw []byte, field string) bool {
	var object map[string]json.RawMessage
	return json.Unmarshal(raw, &object) == nil && object[field] != nil
}
