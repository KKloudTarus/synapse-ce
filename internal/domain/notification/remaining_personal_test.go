package notification

import (
	"encoding/json"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"testing"
	"time"
)

func TestMentionRecipientIsOnlyValidatedIdentity(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{"engagement_id": "eng", "finding_id": "f", "mentioned_user_id": "user", "lead_user_id": "lead"})
	subject, err := SubjectFromEvent(Event{Type: EventFindingMentioned, EngagementID: "eng", Data: raw})
	if err != nil || len(subject.MentionedIDs) != 1 || subject.MentionedIDs[0] != "user" || len(subject.AssigneeIDs) > 0 || len(subject.TeamIDs) > 0 {
		t.Fatalf("subject=%+v err=%v", subject, err)
	}
	for _, role := range []string{RoleAssignee, RoleTeamMember, RoleEngagementLead, RoleApprover} {
		if RuleRoleSupported(EventFindingMentioned, role) == nil {
			t.Fatalf("mention admitted %s", role)
		}
	}
	if RuleRoleSupported(EventFindingMentioned, RoleMentionedUser) != nil {
		t.Fatal("validated mention role unavailable")
	}
	raw = json.RawMessage(`{"engagement_id":"eng","finding_id":"f","mentioned_user_id":""}`)
	if _, err := SubjectFromEvent(Event{Type: EventFindingMentioned, EngagementID: "eng", Data: raw}); err == nil {
		t.Fatal("empty mention identity accepted")
	}
}
func TestMentionRuleRejectsChannelFanout(t *testing.T) {
	at := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	r := Rule{TenantID: "t", ID: "r", Name: "mention", EventType: EventFindingMentioned, ChannelIDs: []shared.ID{"channel"}, Revision: 1, CreatedAt: at, UpdatedAt: at}
	if r.Normalize() == nil {
		t.Fatal("channel mention admitted")
	}
	r.ChannelIDs = nil
	r.RecipientRoles = []string{RoleMentionedUser}
	if err := r.Normalize(); err != nil {
		t.Fatal(err)
	}
}
func TestBrokenChainHasMandatoryAdministratorFloor(t *testing.T) {
	raw := json.RawMessage(`{"engagement_id":"eng","evidence_chain_id":"eng","reason_code":"hash_mismatch"}`)
	subject, err := SubjectFromEvent(Event{Type: EventEvidenceChainBroken, EngagementID: "eng", Data: raw})
	if err != nil || !subject.Admins || !subject.Active() {
		t.Fatalf("subject=%+v err=%v", subject, err)
	}
	if !InAppMandatory(EventEvidenceChainBroken) || !Deliver(true, PreferenceDisabled, false) {
		t.Fatal("broken-chain floor can be muted")
	}
	if PersonalRoleSupported(EventEvidenceChainBroken, RoleTenantAdmin) != nil {
		t.Fatal("missing admin role")
	}
	spec, _ := LookupEvent(EventEvidenceChainBroken)
	if !spec.Mandatory || len(spec.Filters) > 0 {
		t.Fatal("broken-chain catalog contract")
	}
}
func TestApprovalSubjectUsesRelationalRosterAndBindsEngagement(t *testing.T) {
	raw := json.RawMessage(`{"engagement_id":"eng","approver_count":1000}`)
	subject, err := SubjectFromEvent(Event{Type: EventApprovalRequested, EngagementID: "eng", Data: raw})
	if err != nil || !subject.ApprovalRecipients || len(subject.ApproverIDs) != 0 {
		t.Fatalf("approval recipient subject=%+v err=%v", subject, err)
	}
	raw = json.RawMessage(`{"engagement_id":"foreign","approver_count":1}`)
	if _, err := SubjectFromEvent(Event{Type: EventApprovalRequested, EngagementID: "eng", Data: raw}); err == nil {
		t.Fatal("foreign engagement subject accepted")
	}
}
func TestRemainingRulesMatchKindsAndResponseOutcomes(t *testing.T) {
	at := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	r := Rule{TenantID: "t", ID: "r", Name: "approval", Enabled: true, EventType: EventApprovalRequested, RecipientRoles: []string{RoleApprover}, EventFilters: EventFilters{Kinds: []string{"response"}}, Revision: 1, CreatedAt: at, UpdatedAt: at}
	if err := r.Normalize(); err != nil {
		t.Fatal(err)
	}
	e := Event{TenantID: "t", Type: EventApprovalRequested, Data: json.RawMessage(`{"kind":"agent"}`)}
	if r.Matches(e) {
		t.Fatal("agent matched response-only rule")
	}
	e.Data = json.RawMessage(`{"kind":"response"}`)
	if !r.Matches(e) {
		t.Fatal("response failed kind rule")
	}
	e.TenantID = "foreign"
	if r.Matches(e) {
		t.Fatal("foreign event matched")
	}
	for _, outcome := range []string{"applied", "verified", "failed", "reverted", "halted"} {
		if !validEventOutcome(EventResponseFinished, outcome) {
			t.Fatalf("response outcome %s missing", outcome)
		}
	}
}

func TestResponseOutcomesDoNotChangeRunFilterVocabulary(t *testing.T) {
	r := ruleWithFilter(EventScanFailed, FilterOutcomes)
	r.Outcomes = []string{"applied"}
	if r.Normalize() == nil {
		t.Fatal("applied admitted for scan rule")
	}
	r = ruleWithFilter(EventResponseFinished, FilterOutcomes)
	r.Outcomes = []string{"succeeded"}
	if r.Normalize() == nil {
		t.Fatal("succeeded admitted for response rule")
	}
}

func TestPersonalPreferencesIncludeEveryRoutableEvent(t *testing.T) {
	for _, spec := range EventCatalog() {
		if !spec.OperatorOnly && !PersonalEventConfigurable(spec.Type) {
			t.Fatalf("%s absent from preferences", spec.Type)
		}
	}
}
