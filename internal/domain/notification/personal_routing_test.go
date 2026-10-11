package notification

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// The precedence table of #1418: a mandatory notice beats everything, a person's choice beats the
// tenant default, and the tenant default beats the built-in one.
func TestPersonalPrecedenceTable(t *testing.T) {
	defaults := PersonalDefaults{{EventOwnershipChanged, PersonalSlack}: true, {EventOwnershipChanged, PersonalEmail}: false}
	cases := []struct {
		name      string
		mandatory bool
		choice    Preference
		channel   string
		want      bool
	}{
		{"mandatory wins over a mute", true, PreferenceDisabled, PersonalInApp, true},
		{"user enables over a tenant off", false, PreferenceEnabled, PersonalEmail, true},
		{"user mutes over a tenant on", false, PreferenceDisabled, PersonalSlack, false},
		{"inherit follows the tenant default on", false, PreferenceInherit, PersonalSlack, true},
		{"inherit follows the tenant default off", false, PreferenceInherit, PersonalEmail, false},
		{"inherit falls back to the built-in default", false, PreferenceInherit, PersonalTeams, false},
		{"the inbox is on by default", false, PreferenceInherit, PersonalInApp, true},
	}
	for _, tc := range cases {
		if got := Deliver(tc.mandatory, tc.choice, defaults.Enabled(EventOwnershipChanged, tc.channel)); got != tc.want {
			t.Errorf("%s: got %v", tc.name, got)
		}
	}
}

func TestPersonalDefaultValidation(t *testing.T) {
	for _, channel := range ExternalPersonalChannels() {
		if err := ValidatePersonalDefault(EventOwnershipChanged, channel, true); err != nil {
			t.Errorf("%s: %v", channel, err)
		}
	}
	for name, err := range map[string]error{
		"inbox":         ValidatePersonalDefault(EventOwnershipChanged, PersonalInApp, false),
		"unknown":       ValidatePersonalDefault(EventOwnershipChanged, "pager", true),
		"test event":    ValidatePersonalDefault(EventTest, PersonalEmail, true),
		"unknown event": ValidatePersonalDefault("nope.unknown", PersonalEmail, true),
	} {
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if !ValidPersonalChannels() {
		t.Fatal("channel list is inconsistent")
	}
}

// ValidPersonalChannels checks that every external channel is a personal channel and the inbox is
// not one of them.
func ValidPersonalChannels() bool {
	for _, channel := range ExternalPersonalChannels() {
		if !PersonalChannelValid(channel) || channel == PersonalInApp {
			return false
		}
	}
	return PersonalChannelValid(PersonalInApp) && !PersonalChannelValid("sms")
}

func TestRuleRecipientRoles(t *testing.T) {
	ok := []struct {
		event EventType
		role  string
	}{
		{EventOwnershipChanged, RoleAssignee},
		{EventOwnershipChanged, RoleTeamMember},
		{EventOwnershipChanged, RoleEngagementLead},
		{EventSLAApproaching, RoleAssignee},
		{EventScanCompleted, RoleEngagementLead},
	}
	for _, tc := range ok {
		if err := RuleRoleSupported(tc.event, tc.role); err != nil {
			t.Errorf("%s/%s: %v", tc.event, tc.role, err)
		}
	}
	refused := []struct {
		event EventType
		role  string
		want  string
	}{
		{EventOwnershipChanged, RoleMentionedUser, "no verified producer"},
		{EventOwnershipChanged, RoleApprover, "no verified producer"},
		{EventScanCompleted, RoleAssignee, "not available"},
		{EventSLAApproaching, RoleTeamMember, "not available"},
		{EventFleetAgentOffline, RoleEngagementLead, "not available"},
		{EventOwnershipChanged, "owner", "unknown recipient role"},
		{EventTest, RoleAssignee, "unknown event"},
	}
	for _, tc := range refused {
		err := RuleRoleSupported(tc.event, tc.role)
		if !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s/%s: err = %v, want %q", tc.event, tc.role, err, tc.want)
		}
	}
}

func validRule() Rule {
	at := time.Unix(1700000000, 0).UTC()
	return Rule{TenantID: "t", ID: "r", Name: "Leads", Enabled: true, EventType: EventScanCompleted, Revision: 1, CreatedAt: at, UpdatedAt: at}
}

func TestRuleNeedsAChannelOrARole(t *testing.T) {
	r := validRule()
	if err := r.Normalize(); err == nil || !strings.Contains(err.Error(), "channel or a recipient role") {
		t.Fatalf("a rule with neither: %v", err)
	}
	r = validRule()
	r.RecipientRoles = []string{RoleEngagementLead, RoleEngagementLead}
	if err := r.Normalize(); err != nil || len(r.RecipientRoles) != 1 {
		t.Fatalf("a role-only rule: %v %v", err, r.RecipientRoles)
	}
	r = validRule()
	r.RecipientRoles = []string{RoleAssignee}
	if err := r.Normalize(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("assignee on a scan event: %v", err)
	}
	r = validRule()
	r.ChannelIDs = []shared.ID{"c1"}
	if err := r.Normalize(); err != nil || r.RecipientRoles != nil {
		t.Fatalf("a channel-only rule: %v", err)
	}
}

func TestMergeRoleRecipientsDedupesAcrossRoles(t *testing.T) {
	got := MergeRoleRecipients([]RoleRecipients{
		{Role: RoleAssignee, Users: []shared.ID{"ada", ""}},
		{Role: RoleTeamMember, Users: []shared.ID{"bob", "ada"}},
		{Role: RoleEngagementLead, Users: []shared.ID{"ada", "cy"}},
	})
	if len(got) != 3 || got[0].UserID != "ada" || strings.Join(got[0].Roles, ",") != "assignee,team_member,engagement_lead" || got[1].UserID != "bob" || got[2].UserID != "cy" {
		t.Fatalf("merged = %+v", got)
	}
}

func TestGenericPersonalSubject(t *testing.T) {
	// The raw data still holds what the scanner wrote; only the scrubbed snapshot may be used.
	data, _ := json.Marshal(map[string]string{"title": "RAW-ONLY password=hunter2raw", "summary": "RAW-ONLY"})
	snapshot, _ := json.Marshal(map[string]any{"vars": map[string]string{
		"title":   "Scan\ncompleted\tnow",
		"summary": "key AKIAIOSFODNN7EXAMPLE password=hunter2secret " + strings.Repeat("x", 600),
	}})
	subject := GenericPersonalSubject(Event{Type: EventScanCompleted, EngagementID: "eng/1", Data: data, Context: snapshot})
	if subject.Title != "Scan completed now" || len([]rune(subject.Summary)) != 500 || subject.Link != "/engagements/eng%2F1" {
		t.Fatalf("subject = %+v", subject)
	}
	for _, leaked := range []string{"RAW-ONLY", "hunter2", "AKIAIOSFODNN7EXAMPLE"} {
		if strings.Contains(subject.Title+subject.Summary, leaked) {
			t.Fatalf("subject leaks %q: %+v", leaked, subject)
		}
	}
	empty := GenericPersonalSubject(Event{Type: EventScanCompleted, Data: data})
	if empty.Title != "Scan completed" || empty.Summary != "" || empty.Link != "/inbox" {
		t.Fatalf("subject without a snapshot = %+v", empty)
	}
}

func TestSlackContactValue(t *testing.T) {
	value, err := SlackContactValue(" T0123ABC ", " U04XYZ ")
	if err != nil || value != "T0123ABC:U04XYZ" {
		t.Fatalf("value = %q %v", value, err)
	}
	team, member, ok := ParseSlackContact(value)
	if !ok || team != "T0123ABC" || member != "U04XYZ" {
		t.Fatalf("parse = %q %q %v", team, member, ok)
	}
	for _, bad := range [][2]string{{"t0123", "U1234"}, {"T0123", "ada@example.com"}, {"T0123", "D0123"}, {"", "U1234"}} {
		if _, err := SlackContactValue(bad[0], bad[1]); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%v accepted", bad)
		}
	}
	if _, _, ok := ParseSlackContact("ada@example.com"); ok {
		t.Error("an email parsed as a Slack contact")
	}
}
