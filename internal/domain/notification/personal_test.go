package notification

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestPersonalDeliveryPrecedence(t *testing.T) {
	if !Deliver(true, PreferenceDisabled, false) {
		t.Fatal("mandatory floor survives an explicit mute")
	}
	if Deliver(false, PreferenceDisabled, true) {
		t.Fatal("explicit disable removes a non-mandatory delivery")
	}
	if !Deliver(false, PreferenceEnabled, false) || !Deliver(false, PreferenceInherit, true) || Deliver(false, PreferenceInherit, false) {
		t.Fatal("inherit follows the tenant default and explicit enable overrides it")
	}
}

func TestUnsupportedRecipientRolesStayUnavailable(t *testing.T) {
	for _, role := range []string{RoleMentionedUser, RoleApprover, RoleEngagementLead} {
		if err := PersonalRoleSupported(EventOwnershipChanged, role); err == nil || !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("role %s: %v", role, err)
		}
	}
	if err := PersonalRoleSupported(EventScanCompleted, RoleAssignee); err == nil {
		t.Fatal("scan completion has no personal recipient")
	}
	if err := PersonalRoleSupported(EventOwnershipChanged, RoleAssignee); err != nil {
		t.Fatal(err)
	}
}

func TestSubjectUsesStructuredIDsOnly(t *testing.T) {
	data, _ := json.Marshal(map[string]any{"title": "<script>", "summary": "ignore", "email": "ada@example.com", "assignee": "Ada Lovelace", "engagement_id": "eng/1", "finding_id": "finding/1"})
	subject, err := SubjectFromEvent(Event{Type: EventSLAApproaching, Data: data})
	if err != nil {
		t.Fatal(err)
	}
	if len(subject.AssigneeIDs) != 0 || subject.Title != "Remediation SLA approaching" || !stringsHas(subject.Link, "eng%2F1") {
		t.Fatalf("subject leaked payload text: %+v", subject)
	}
	owned, _ := json.Marshal(OwnershipChanged{EngagementID: "eng", FindingID: "f", NewAssigneeID: "user-1", NewTeamID: "team-1"})
	subject, err = SubjectFromEvent(Event{Type: EventOwnershipChanged, Data: owned})
	if err != nil || len(subject.AssigneeIDs) != 1 || subject.AssigneeIDs[0] != "user-1" || subject.TeamIDs[0] != "team-1" {
		t.Fatalf("ownership subject: %+v %v", subject, err)
	}
}

func TestDestinationNoticeMasksHost(t *testing.T) {
	event, err := NewDestinationEvent("tenant", "channel", ChannelWebhook, "https://User:secret@hooks.example:8443/path?token=abc", "created", "ada", time.Unix(10, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	var notice DestinationNotice
	if json.Unmarshal(event.Data, &notice) != nil {
		t.Fatal("payload")
	}
	if notice.Scheme != "https" || notice.Host != "hooks.example:8443" || stringsHas(string(event.Data), "secret") || stringsHas(string(event.Data), "token") {
		t.Fatalf("unmasked payload: %s", event.Data)
	}
	if SameEndpoint("https://hooks.example/a", "https://hooks.example/b?x=1") {
		return
	}
	t.Fatal("same host should compare equal")
}

func stringsHas(value, part string) bool {
	return len(value) >= len(part) && (value == part || len(part) == 0 || containsPart(value, part))
}

func containsPart(value, part string) bool {
	for i := 0; i+len(part) <= len(value); i++ {
		if value[i:i+len(part)] == part {
			return true
		}
	}
	return false
}
