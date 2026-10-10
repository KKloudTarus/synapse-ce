package notification

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Personal channels (#1418): where one person receives a notification about their own work. The
// inbox is inside Synapse; email, a Slack direct message (#1419) and a Microsoft Teams personal chat
// (#1420) leave it, so they need a verified contact and obey the engagement's external override.
const (
	PersonalSlack = "slack"
	PersonalTeams = "teams"
)

// PersonalChannels lists every personal channel in display order.
func PersonalChannels() []string {
	return []string{PersonalInApp, PersonalEmail, PersonalSlack, PersonalTeams}
}

// ExternalPersonalChannels are the personal channels that leave Synapse, each through a verified
// contact of the same kind.
func ExternalPersonalChannels() []string {
	return []string{PersonalEmail, PersonalSlack, PersonalTeams}
}

// PersonalChannelValid reports whether c is a personal channel.
func PersonalChannelValid(c string) bool {
	for _, known := range PersonalChannels() {
		if c == known {
			return true
		}
	}
	return false
}

// BuiltinPersonalDefault is the tenant default a tenant has not changed: the inbox is on, and
// nothing leaves Synapse until someone asks for it.
func BuiltinPersonalDefault(channel string) bool { return channel == PersonalInApp }

// PersonalDefaults are a tenant's defaults per (event type, personal channel) (#1418). A missing
// entry falls back to BuiltinPersonalDefault.
type PersonalDefaults map[PersonalDefaultKey]bool

// PersonalDefaultKey names one tenant default.
type PersonalDefaultKey struct {
	Event   EventType
	Channel string
}

// Enabled returns the tenant default for one event and channel.
func (d PersonalDefaults) Enabled(event EventType, channel string) bool {
	if enabled, ok := d[PersonalDefaultKey{event, channel}]; ok {
		return enabled
	}
	return BuiltinPersonalDefault(channel)
}

// PersonalDefault is one stored tenant default, as the API shows it.
type PersonalDefault struct {
	EventType EventType `json:"event_type"`
	Channel   string    `json:"channel"`
	Enabled   bool      `json:"enabled"`
	// Builtin is true when the tenant has not changed the default; Revision is then 0.
	Builtin  bool `json:"builtin"`
	Revision int  `json:"revision"`
}

// ValidatePersonalDefault checks a tenant default before it is stored. Only the channels that leave
// Synapse have a tenant default.
func ValidatePersonalDefault(event EventType, channel string, enabled bool) error {
	if !PersonalChannelValid(channel) {
		return fmt.Errorf("%w: unknown personal channel", shared.ErrValidation)
	}
	// Every personal message is sent from its inbox row, so the inbox stays on for the tenant and
	// only a person can mute it for themselves.
	if channel == PersonalInApp {
		return fmt.Errorf("%w: the in-app inbox has no tenant default to change", shared.ErrValidation)
	}
	if !PersonalEventConfigurable(event) {
		return fmt.Errorf("%w: personal delivery is not configurable for this event", shared.ErrValidation)
	}
	return nil
}

// PersonalEventConfigurable reports whether people may choose how they receive an event: every
// event a rule can route, and the administrator notices.
func PersonalEventConfigurable(event EventType) bool {
	if InAppMandatory(event) {
		return true
	}
	for _, candidate := range ConfigurableEvents() {
		if candidate == event {
			return true
		}
	}
	return false
}

// Rule recipient roles (#1415). A rule may address people by their relation to the event, in
// addition to its channels. Each role is resolved by its own resolver at projection time, filtered
// to enabled, same-tenant people whose role can view, and checked again at send time.
var ruleRecipientRoles = []string{RoleAssignee, RoleTeamMember, RoleEngagementLead}

// RuleRecipientRoles lists the roles a rule may name.
func RuleRecipientRoles() []string { return append([]string(nil), ruleRecipientRoles...) }

// RuleRoleSupported reports whether a rule for event may name role. Assignee and team member come
// from a finding the event is about; the engagement lead from the event's engagement. Mention and
// approver roles have no producer that records a verified identity yet, so they are refused rather
// than matched against free text.
func RuleRoleSupported(event EventType, role string) error {
	spec, known := catalog[event]
	if !known || spec.OperatorOnly {
		return fmt.Errorf("%w: unknown event type", shared.ErrValidation)
	}
	switch role {
	case RoleMentionedUser, RoleApprover:
		return fmt.Errorf("%w: recipient role %s has no verified producer yet", shared.ErrValidation, role)
	case RoleEngagementLead:
		if spec.HasEngagement {
			return nil
		}
	case RoleAssignee:
		if event == EventOwnershipChanged || event == EventSLAApproaching {
			return nil
		}
	case RoleTeamMember:
		if event == EventOwnershipChanged {
			return nil
		}
	default:
		return fmt.Errorf("%w: unknown recipient role %q", shared.ErrValidation, role)
	}
	return fmt.Errorf("%w: recipient role %s is not available for %s events", shared.ErrValidation, role, event)
}

// normalizeRecipientRoles dedupes and checks a rule's roles.
func (r *Rule) normalizeRecipientRoles() error {
	r.RecipientRoles = uniqueStrings(r.RecipientRoles)
	if len(r.RecipientRoles) > len(ruleRecipientRoles) {
		return fmt.Errorf("%w: too many recipient roles", shared.ErrValidation)
	}
	for _, role := range r.RecipientRoles {
		if err := RuleRoleSupported(r.EventType, role); err != nil {
			return err
		}
	}
	return nil
}

// HasRole reports whether role is among roles.
func HasRole(roles []string, role string) bool {
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

// GenericPersonalSubject is the personal subject of an event that names no person itself: a rule
// recipient role addresses the people. Its title and summary come from the event's own built-in
// text, its link from its engagement.
func GenericPersonalSubject(e Event) PersonalSubject {
	var data struct {
		Title   string `json:"title"`
		Summary string `json:"summary"`
	}
	_ = json.Unmarshal(e.Data, &data)
	title := cleanLine(data.Title, 200)
	if title == "" {
		if spec, ok := catalog[e.Type]; ok {
			title = spec.Label
		}
	}
	link := "/inbox"
	if safeID(e.EngagementID) {
		link = "/engagements/" + url.PathEscape(e.EngagementID.String())
	}
	return PersonalSubject{EngagementID: e.EngagementID, Title: title, Summary: cleanLine(data.Summary, 500), Link: link}
}

// MergeRoleRecipients merges people found by role into one list with their roles, keeping the
// first-seen order. It extends MergePersonalRecipients to any set of roles.
func MergeRoleRecipients(byRole []RoleRecipients) []ResolvedRecipient {
	roles := map[shared.ID][]string{}
	var order []shared.ID
	for _, group := range byRole {
		for _, id := range group.Users {
			if id.IsZero() {
				continue
			}
			current, seen := roles[id]
			if !seen {
				order = append(order, id)
			}
			if !HasRole(current, group.Role) {
				roles[id] = append(current, group.Role)
			}
		}
	}
	out := make([]ResolvedRecipient, 0, len(order))
	for _, id := range order {
		out = append(out, ResolvedRecipient{UserID: id, Roles: roles[id]})
	}
	return out
}

// RoleRecipients are the people one role resolved to.
type RoleRecipients struct {
	Role  string
	Users []shared.ID
}

func cleanLine(value string, max int) string {
	value = strings.Join(strings.FieldsFunc(value, func(r rune) bool { return r == '\n' || r == '\r' || r == '\t' }), " ")
	value = strings.TrimSpace(value)
	if utf8.RuneCountInString(value) <= max {
		return value
	}
	return string([]rune(value)[:max])
}

var (
	slackTeamID   = regexp.MustCompile(`^T[A-Z0-9]{2,30}$`)
	slackMemberID = regexp.MustCompile(`^[UW][A-Z0-9]{2,30}$`)
)

// SlackContactValue is the stored value of a Slack contact (#1419): <workspace>:<member>. A person
// gives their member ID; Synapse never looks one up by email or name.
func SlackContactValue(team, member string) (string, error) {
	team, member = strings.TrimSpace(team), strings.TrimSpace(member)
	if !slackTeamID.MatchString(team) {
		return "", fmt.Errorf("%w: Slack workspace must be a team ID such as T0123ABC", shared.ErrValidation)
	}
	if !slackMemberID.MatchString(member) {
		return "", fmt.Errorf("%w: Slack member ID must look like U0123ABC (Profile, then More, then Copy member ID)", shared.ErrValidation)
	}
	return team + ":" + member, nil
}

// ParseSlackContact splits a stored Slack contact value.
func ParseSlackContact(value string) (team, member string, ok bool) {
	team, member, ok = strings.Cut(value, ":")
	return team, member, ok && slackTeamID.MatchString(team) && slackMemberID.MatchString(member)
}
