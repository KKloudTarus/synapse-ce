package notification

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	RoleAssignee       = "assignee"
	RoleTeamMember     = "team_member"
	RoleEngagementLead = "engagement_lead"
	RoleMentionedUser  = "mentioned_user"
	RoleApprover       = "approver"
	RoleTenantAdmin    = "tenant_admin"

	PersonalInApp = "in_app"
	PersonalEmail = "email"
)

type Preference string

const (
	PreferenceInherit  Preference = "inherit"
	PreferenceEnabled  Preference = "enabled"
	PreferenceDisabled Preference = "disabled"
)

func (p Preference) Valid() bool {
	return p == PreferenceInherit || p == PreferenceEnabled || p == PreferenceDisabled
}

// Deliver applies mandatory > explicit user choice > tenant default.
// A mandatory floor does not create a verified contact or grant a permission.
func Deliver(mandatory bool, choice Preference, tenantDefault bool) bool {
	if mandatory {
		return true
	}
	switch choice {
	case PreferenceEnabled:
		return true
	case PreferenceDisabled:
		return false
	default:
		return tenantDefault
	}
}

func InAppMandatory(event EventType) bool { return event == EventDestinationChanged }

// PersonalRoleSupported reports whether a shipped event can grant that role.
// Mention, approver and engagement-lead producers are not in this baseline, so
// those roles stay unsupported instead of matching free text.
func PersonalRoleSupported(event EventType, role string) error {
	switch role {
	case RoleMentionedUser, RoleApprover, RoleEngagementLead:
		return fmt.Errorf("%w: recipient role %s has no verified producer", shared.ErrValidation, role)
	}
	switch event {
	case EventOwnershipChanged:
		if role == RoleAssignee || role == RoleTeamMember {
			return nil
		}
	case EventSLAApproaching:
		if role == RoleAssignee {
			return nil
		}
	case EventDestinationChanged:
		if role == RoleTenantAdmin {
			return nil
		}
	default:
		if event.Valid() && event != EventTest {
			return fmt.Errorf("%w: %s has no personal recipients", shared.ErrValidation, event)
		}
	}
	return fmt.Errorf("%w: recipient role %s is not supported for %s", shared.ErrValidation, role, event)
}

type PersonalSubject struct {
	AssigneeIDs   []shared.ID
	TeamIDs       []shared.ID
	LookupFinding bool
	EngagementID  shared.ID
	FindingID     shared.ID
	Admins        bool
	Title         string
	Summary       string
	Link          string
}

func (s PersonalSubject) Active() bool {
	return len(s.AssigneeIDs) > 0 || len(s.TeamIDs) > 0 || s.LookupFinding || s.Admins
}

type actorContextKey struct{}

func WithActor(ctx context.Context, actor string) context.Context {
	return context.WithValue(ctx, actorContextKey{}, strings.TrimSpace(actor))
}

func ActorFrom(ctx context.Context) string {
	actor, _ := ctx.Value(actorContextKey{}).(string)
	if actor == "" {
		return "system"
	}
	return actor
}

func SubjectFromEvent(e Event) (PersonalSubject, error) {
	switch e.Type {
	case EventOwnershipChanged:
		var data OwnershipChanged
		if json.Unmarshal(e.Data, &data) != nil {
			return PersonalSubject{}, fmt.Errorf("%w: ownership event payload", shared.ErrValidation)
		}
		return PersonalSubject{
			AssigneeIDs:  compactIDs(data.NewAssigneeID, data.OldAssigneeID),
			TeamIDs:      compactIDs(data.NewTeamID, data.OldTeamID),
			EngagementID: data.EngagementID,
			FindingID:    data.FindingID,
			Title:        "Finding ownership changed",
			Summary:      "A finding's team or assignee changed.",
			Link:         FindingLink(data.EngagementID, data.FindingID),
		}, nil
	case EventSLAApproaching:
		var data struct {
			EngagementID shared.ID `json:"engagement_id"`
			FindingID    shared.ID `json:"finding_id"`
		}
		if json.Unmarshal(e.Data, &data) != nil || !safeID(data.EngagementID) || !safeID(data.FindingID) {
			return PersonalSubject{}, nil
		}
		return PersonalSubject{
			LookupFinding: true,
			EngagementID:  data.EngagementID,
			FindingID:     data.FindingID,
			Title:         "Remediation SLA approaching",
			Summary:       "A finding is approaching its remediation deadline.",
			Link:          FindingLink(data.EngagementID, data.FindingID),
		}, nil
	case EventDestinationChanged:
		var data DestinationNotice
		if json.Unmarshal(e.Data, &data) != nil || (data.Action != "created" && data.Action != "host_changed") {
			return PersonalSubject{}, fmt.Errorf("%w: destination notice payload", shared.ErrValidation)
		}
		return PersonalSubject{
			Admins:  true,
			Title:   data.Title,
			Summary: data.Summary,
			Link:    "/settings/alerting",
		}, nil
	default:
		return PersonalSubject{}, nil
	}
}

type DestinationNotice struct {
	Title   string `json:"title"`
	Summary string `json:"summary"`
	Actor   string `json:"actor"`
	Action  string `json:"action"`
	Class   string `json:"class"`
	Scheme  string `json:"scheme"`
	Host    string `json:"host"`
}

func NewDestinationEvent(tenant, channel shared.ID, channelType ChannelType, destination, action, actor string, at time.Time) (Event, error) {
	scheme, host, ok := MaskedEndpoint(destination)
	if !ok || (channelType != ChannelWebhook && channelType != ChannelSlack) {
		return Event{}, fmt.Errorf("%w: destination notice requires an HTTP host", shared.ErrValidation)
	}
	if action != "created" && action != "host_changed" {
		return Event{}, fmt.Errorf("%w: invalid destination action", shared.ErrValidation)
	}
	title := "Notification destination created"
	if action == "host_changed" {
		title = "Notification destination host changed"
	}
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "system"
	}
	notice := DestinationNotice{Title: title, Summary: fmt.Sprintf("%s %s the %s destination %s://%s.", actor, verb(action), channelType, scheme, host), Actor: actor, Action: action, Class: string(channelType), Scheme: scheme, Host: host}
	raw, err := json.Marshal(notice)
	if err != nil {
		return Event{}, err
	}
	source := "dest:" + channel.String() + ":" + action + ":" + host
	return Event{TenantID: tenant, Type: EventDestinationChanged, SourceKind: "notification_destination", SourceID: source, SchemaVersion: 1, OccurredAt: at.UTC(), Data: raw}, nil
}

func verb(action string) string {
	if action == "host_changed" {
		return "changed"
	}
	return "created"
}

func MaskedEndpoint(raw string) (scheme, host string, ok bool) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Hostname() == "" {
		return "", "", false
	}
	scheme = strings.ToLower(parsed.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", "", false
	}
	host = strings.ToLower(parsed.Hostname())
	if port := parsed.Port(); port != "" {
		host += ":" + port
	}
	if strings.ContainsAny(host, "\r\n/?#") {
		return "", "", false
	}
	return scheme, host, true
}

func SameEndpoint(previous, next string) bool {
	leftScheme, leftHost, leftOK := MaskedEndpoint(previous)
	rightScheme, rightHost, rightOK := MaskedEndpoint(next)
	return leftOK && rightOK && leftScheme == rightScheme && leftHost == rightHost
}

func FindingLink(engagement, finding shared.ID) string {
	if !safeID(engagement) || !safeID(finding) {
		return "/inbox"
	}
	return "/engagements/" + url.PathEscape(engagement.String()) + "/findings#finding-" + url.PathEscape(finding.String())
}

func safeID(id shared.ID) bool {
	value := id.String()
	if value == "" || len(value) > 200 {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func compactIDs(ids ...shared.ID) []shared.ID {
	return uniqueIDs(ids)
}

// ResolvedRecipient is one person selected for an event. Roles explain why.
// Contact addresses are not part of this result.
type ResolvedRecipient struct {
	UserID shared.ID
	Roles  []string
}

// MergePersonalRecipients dedupes one person who matches more than one role.
// The first matching role wins the order; later roles are recorded on that person.
func MergePersonalRecipients(assignees, members, admins []shared.ID) []ResolvedRecipient {
	roles := map[shared.ID][]string{}
	var order []shared.ID
	add := func(id shared.ID, role string) {
		if id.IsZero() {
			return
		}
		current, seen := roles[id]
		if !seen {
			order = append(order, id)
		}
		for _, existing := range current {
			if existing == role {
				return
			}
		}
		roles[id] = append(current, role)
	}
	for _, id := range assignees {
		add(id, RoleAssignee)
	}
	for _, id := range members {
		add(id, RoleTeamMember)
	}
	for _, id := range admins {
		add(id, RoleTenantAdmin)
	}
	out := make([]ResolvedRecipient, 0, len(order))
	for _, id := range order {
		out = append(out, ResolvedRecipient{UserID: id, Roles: roles[id]})
	}
	return out
}

func ConfigurableEvents() []EventType {
	return []EventType{EventVulnerabilityAction, EventScanCompleted, EventQualityGateFailed, EventSLAApproaching, EventFleetAgentOffline, EventIncidentCreated, EventOwnershipChanged}
}
