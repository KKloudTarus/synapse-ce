package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	inboxAge          = 90 * 24 * time.Hour
	inboxPerUserCap   = 1000
	inboxRetainBatch  = 200
	personalMailKind  = "personal.email"
	personalSlackKind = "personal.slack"
	personalTeamsKind = "personal.teams"
)

var humanNotificationRoles = []string{"admin", "consultant", "reviewer", "member", "readonly", "integration_admin"}

var _ ports.RecipientResolver = (*NotificationRepository)(nil)

func (r *NotificationRepository) ResolvePersonalRecipients(ctx context.Context, tenant shared.ID, event notification.Event) ([]notification.ResolvedRecipient, error) {
	event.TenantID = tenant
	var out []notification.ResolvedRecipient
	err := WithTenant(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		var resolveErr error
		out, resolveErr = resolvePersonalRecipients(ctx, tx, event, nil)
		return resolveErr
	})
	return out, err
}

func queryUserIDs(ctx context.Context, tx pgx.Tx, query string, args ...any) ([]shared.ID, error) {
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var id shared.ID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

type prefKey struct {
	user    shared.ID
	channel string
}

func personalPreferences(ctx context.Context, tx pgx.Tx, tenant shared.ID, event notification.EventType, users []shared.ID) (map[prefKey]notification.Preference, error) {
	out := map[prefKey]notification.Preference{}
	rows, err := tx.Query(ctx, `SELECT user_id, channel, state FROM user_notification_preferences WHERE tenant_id=$1 AND event_type=$2 AND user_id = ANY($3)`, tenant, event, idStrings(users))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var user shared.ID
		var channel, state string
		if err := rows.Scan(&user, &channel, &state); err != nil {
			return nil, err
		}
		out[prefKey{user, channel}] = notification.Preference(state)
	}
	return out, rows.Err()
}

func idStrings(ids []shared.ID) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if !id.IsZero() {
			out = append(out, id.String())
		}
	}
	return out
}

func limitText(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}

func retainPersonalInbox(ctx context.Context, tx pgx.Tx, tenant shared.ID, now time.Time) error {
	if err := deleteInbox(ctx, tx, `SELECT user_id, id FROM user_notifications
		WHERE tenant_id=$1 AND created_at < $2 ORDER BY created_at, id LIMIT $3`, tenant, now.Add(-inboxAge), inboxRetainBatch); err != nil {
		return err
	}
	// Each EXISTS probe stops at the cap using the feed index. This avoids a
	// tenant-wide GROUP BY over every inbox row on each source poll.
	rows, err := tx.Query(ctx, `SELECT u.id FROM users u WHERE u.ownership_tenant_id=$1
		AND EXISTS (SELECT 1 FROM user_notifications n
			WHERE n.tenant_id=$1 AND n.user_id=u.id
			ORDER BY n.created_at DESC,n.id DESC OFFSET $2 LIMIT 1)
		ORDER BY u.id LIMIT 20`, tenant, inboxPerUserCap)
	if err != nil {
		return err
	}
	var users []shared.ID
	for rows.Next() {
		var id shared.ID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		users = append(users, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, userID := range users {
		if err := deleteInbox(ctx, tx, `SELECT user_id, id FROM user_notifications
			WHERE tenant_id=$1 AND user_id=$2
			ORDER BY created_at DESC,id DESC OFFSET $3 LIMIT $4`, tenant, userID, inboxPerUserCap, inboxRetainBatch); err != nil {
			return err
		}
	}
	return nil
}

func deleteInbox(ctx context.Context, tx pgx.Tx, query string, args ...any) error {
	// The deleted rows and their replay fences are one SQL statement within the
	// caller's transaction. A failure cannot leave deletion without a tombstone.
	_, err := tx.Exec(ctx, `WITH doomed AS (`+query+`), removed AS (
		DELETE FROM user_notifications n USING doomed d
		WHERE n.tenant_id=$1 AND n.user_id=d.user_id AND n.id=d.id
		RETURNING n.tenant_id,n.user_id,n.event_id
	) INSERT INTO user_notification_tombstones(tenant_id,user_id,event_id)
	SELECT tenant_id,user_id,event_id FROM removed ON CONFLICT DO NOTHING`, args...)
	return err
}

func (r *NotificationRepository) EnableDestinationNotices() { r.destinationNotices = true }

func (r *NotificationRepository) maybeDestinationNotice(ctx context.Context, tx pgx.Tx, channel notification.Channel, action string) error {
	if !r.destinationNotices || !channel.Type.HTTPEndpoint() {
		return nil
	}
	event, err := notification.NewDestinationEvent(channel.TenantID, channel.ID, channel.Type, channel.Destination, action, notification.ActorFrom(ctx), channel.UpdatedAt)
	if err != nil {
		return err
	}
	if channel.Revision < 1 {
		return fmt.Errorf("%w: destination notice requires a channel revision", shared.ErrValidation)
	}
	// The revision distinguishes a later return to a previous host from a retry
	// of the same save. Secret-only rotation never reaches this function.
	event.SourceID = event.SourceID + ":rev:" + strconv.Itoa(channel.Revision)
	event.ID = stableID(channel.TenantID.String(), event.SourceKind, event.SourceID)
	_, err = r.publishTx(ctx, tx, event, "")
	return err
}

// LoadPersonalMail is LoadPersonalDelivery for email: the recipient, title and summary of a queued
// personal email, or ok=false when it must not be sent any more.
func (s *InboxStore) LoadPersonalMail(ctx context.Context, tenant, user, event, contact shared.ID, version int) (recipient, title, summary string, ok bool, err error) {
	message, ok, err := s.LoadPersonalDelivery(ctx, tenant, user, event, contact, version, notification.PersonalEmail)
	return message.Recipient, message.Title, message.Summary, ok, err
}

type InboxStore struct{ pool *pgxpool.Pool }

func NewInboxStore(pool *pgxpool.Pool) *InboxStore { return &InboxStore{pool: pool} }

// personalJobKinds maps each personal channel that leaves Synapse to the contact kind it needs and
// the job that sends it (#1418, #1419, #1420). Each job carries only IDs; the sender reloads the
// inbox row, the preference and the contact when it runs.
var personalJobKinds = map[string]string{
	notification.PersonalEmail: personalMailKind,
	notification.PersonalSlack: personalSlackKind,
	notification.PersonalTeams: personalTeamsKind,
}

// projectPersonal writes the inbox rows of one event and queues its personal messages. ruleRoles
// are the recipient roles of the rules that matched it (#1415).
func (r *NotificationRepository) projectPersonal(ctx context.Context, tx pgx.Tx, e notification.Event, ruleRoles []string) error {
	subject, err := personalSubject(e, ruleRoles)
	if err != nil || !subject.ok {
		return err
	}
	recipients, err := resolvePersonalRecipients(ctx, tx, e, ruleRoles)
	if err != nil || len(recipients) == 0 {
		return err
	}
	users := make([]shared.ID, len(recipients))
	for i, recipient := range recipients {
		users[i] = recipient.UserID
	}
	prefs, err := personalPreferences(ctx, tx, e.TenantID, e.Type, users)
	if err != nil {
		return err
	}
	defaults, err := loadPersonalDefaults(ctx, tx, e.TenantID, e.Type)
	if err != nil {
		return err
	}
	type inboxRow struct {
		User     string          `json:"user_id"`
		ID       string          `json:"id"`
		External map[string]bool `json:"-"`
	}
	rows := make([]inboxRow, 0, len(users))
	for _, userID := range users {
		if !notification.Deliver(notification.InAppMandatory(e.Type), prefs[prefKey{userID, notification.PersonalInApp}], true) {
			continue
		}
		external := map[string]bool{}
		for _, channel := range notification.ExternalPersonalChannels() {
			external[channel] = notification.Deliver(false, prefs[prefKey{userID, channel}], defaults.Enabled(e.Type, channel))
		}
		rows = append(rows, inboxRow{User: userID.String(), ID: stableID(e.TenantID.String(), userID.String(), e.ID.String()).String(), External: external})
	}
	if len(rows) == 0 {
		return nil
	}
	encoded, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	title := limitText(subject.Title, 200)
	if title == "" {
		title = "Notification"
	}
	inserted, err := tx.Query(ctx, `INSERT INTO user_notifications(tenant_id,user_id,id,event_id,event_type,title,summary,link_path,created_at)
		SELECT $1, item->>'user_id', item->>'id', $2, $3, $4, $5, $6, now()
		FROM jsonb_array_elements($7::jsonb) AS item
		WHERE NOT EXISTS (
			SELECT 1 FROM user_notification_tombstones t
			WHERE t.tenant_id=$1 AND t.user_id=item->>'user_id' AND t.event_id=$2
		)
		ON CONFLICT(tenant_id,user_id,event_id) DO NOTHING
		RETURNING user_id`, e.TenantID, e.ID, e.Type, title, limitText(subject.Summary, 500), subject.Link, string(encoded))
	if err != nil {
		return fmt.Errorf("project personal inbox: %w", err)
	}
	created := map[string]struct{}{}
	for inserted.Next() {
		var userID string
		if err := inserted.Scan(&userID); err != nil {
			inserted.Close()
			return err
		}
		created[userID] = struct{}{}
	}
	if err := inserted.Err(); err != nil {
		inserted.Close()
		return err
	}
	inserted.Close()
	// A personal message goes with a newly created inbox row; a replayed or tombstoned row sends
	// nothing again.
	byChannel := map[string][]string{}
	for _, row := range rows {
		if _, ok := created[row.User]; !ok {
			continue
		}
		for _, channel := range notification.ExternalPersonalChannels() {
			if row.External[channel] {
				byChannel[channel] = append(byChannel[channel], row.User)
			}
		}
	}
	if len(byChannel) == 0 {
		return nil
	}
	// These messages leave Synapse, so an engagement set to none gets no personal job (#1360); the
	// in-app rows above stay, because the inbox is inside Synapse.
	engagement := e.EngagementID.String()
	if suppressed, err := engagementSuppressed(ctx, tx, e.TenantID, &engagement); err != nil || suppressed {
		return err
	}
	for _, channel := range notification.ExternalPersonalChannels() {
		if len(byChannel[channel]) == 0 {
			continue
		}
		if err := queuePersonalJobs(ctx, tx, e, channel, byChannel[channel]); err != nil {
			return err
		}
	}
	return nil
}

// queuePersonalJobs queues one job per person who has a verified contact of the channel's kind.
// The newest verified contact wins; a person without one gets nothing on that channel.
func queuePersonalJobs(ctx context.Context, tx pgx.Tx, e notification.Event, channel string, users []string) error {
	contacts, err := tx.Query(ctx, `SELECT DISTINCT ON (user_id) user_id, id, version
		FROM user_contacts
		WHERE tenant_id=$1 AND user_id = ANY($2) AND kind=$3 AND verified_at IS NOT NULL
		ORDER BY user_id, verified_at DESC, id`, e.TenantID, users, channel)
	if err != nil {
		return err
	}
	type jobRow struct {
		ID      string `json:"id"`
		Payload string `json:"payload"`
	}
	var jobs []jobRow
	for contacts.Next() {
		var userID, contactID shared.ID
		var version int
		if err := contacts.Scan(&userID, &contactID, &version); err != nil {
			contacts.Close()
			return err
		}
		payload, err := json.Marshal(map[string]any{"event_id": e.ID, "user_id": userID, "contact_id": contactID, "contact_version": version})
		if err != nil {
			contacts.Close()
			return err
		}
		inboxID := stableID(e.TenantID.String(), userID.String(), e.ID.String())
		jobs = append(jobs, jobRow{ID: "personal-" + channel + "-" + inboxID.String(), Payload: string(payload)})
	}
	if err := contacts.Err(); err != nil {
		contacts.Close()
		return err
	}
	contacts.Close()
	if len(jobs) == 0 {
		return nil
	}
	encodedJobs, err := json.Marshal(jobs)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO jobs(id,tenant_id,kind,payload,status,available_at)
		SELECT item->>'id', $1, $2, convert_to(item->>'payload', 'UTF8'), 'queued', now()
		FROM jsonb_array_elements($3::jsonb) AS item
		ON CONFLICT(id) DO NOTHING`, e.TenantID, personalJobKinds[channel], string(encodedJobs))
	return err
}

type projectedSubject struct {
	notification.PersonalSubject
	ok bool
}

// personalSubject is what a person is told about an event: the event's own structured subject, or,
// for an event that names nobody, a generic one when a rule's recipient roles address people.
func personalSubject(e notification.Event, ruleRoles []string) (projectedSubject, error) {
	subject, err := notification.SubjectFromEvent(e)
	if err != nil {
		return projectedSubject{}, err
	}
	if subject.Active() {
		return projectedSubject{PersonalSubject: subject, ok: true}, nil
	}
	if len(ruleRoles) == 0 {
		return projectedSubject{}, nil
	}
	generic := notification.GenericPersonalSubject(e)
	generic.AssigneeIDs, generic.TeamIDs, generic.LookupFinding, generic.FindingID = subject.AssigneeIDs, subject.TeamIDs, subject.LookupFinding, subject.FindingID
	return projectedSubject{PersonalSubject: generic, ok: true}, nil
}

// roleResolver finds the people one recipient role names for an event (#1415). Every resolver
// keeps only enabled people of the event's tenant whose role can view; the send-time load checks
// the same again.
type roleResolver func(ctx context.Context, tx pgx.Tx, e notification.Event, subject notification.PersonalSubject) ([]shared.ID, error)

var roleResolvers = map[string]roleResolver{
	notification.RoleAssignee:       resolveAssignees,
	notification.RoleTeamMember:     resolveTeamMembers,
	notification.RoleEngagementLead: resolveEngagementLead,
	notification.RoleTenantAdmin:    resolveTenantAdmins,
}

// personalRoleOrder is the order roles are merged in: the first role that selects a person is the
// first role listed for them.
var personalRoleOrder = []string{notification.RoleAssignee, notification.RoleTeamMember, notification.RoleEngagementLead, notification.RoleTenantAdmin}

func resolvePersonalRecipients(ctx context.Context, tx pgx.Tx, e notification.Event, ruleRoles []string) ([]notification.ResolvedRecipient, error) {
	projected, err := personalSubject(e, ruleRoles)
	if err != nil || !projected.ok {
		return nil, err
	}
	subject := projected.PersonalSubject
	// The event's own subject names its assignees, teams and administrators; a rule adds roles on
	// top. A rule cannot take away the people the event itself addresses.
	wanted := map[string]bool{
		notification.RoleAssignee:    len(subject.AssigneeIDs) > 0 || subject.LookupFinding,
		notification.RoleTeamMember:  len(subject.TeamIDs) > 0,
		notification.RoleTenantAdmin: subject.Admins,
	}
	for _, role := range ruleRoles {
		wanted[role] = true
	}
	var groups []notification.RoleRecipients
	for _, role := range personalRoleOrder {
		if !wanted[role] {
			continue
		}
		users, err := roleResolvers[role](ctx, tx, e, subject)
		if err != nil {
			return nil, err
		}
		groups = append(groups, notification.RoleRecipients{Role: role, Users: users})
	}
	return notification.MergeRoleRecipients(groups), nil
}

func resolveAssignees(ctx context.Context, tx pgx.Tx, e notification.Event, subject notification.PersonalSubject) ([]shared.ID, error) {
	ids := append([]shared.ID(nil), subject.AssigneeIDs...)
	if subject.LookupFinding {
		var assignee *string
		err := tx.QueryRow(ctx, `SELECT assignee_user_id FROM findings WHERE tenant_id=$1 AND engagement_id=$2 AND id=$3`, e.TenantID, subject.EngagementID, subject.FindingID).Scan(&assignee)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		if assignee != nil && *assignee != "" {
			ids = append(ids, shared.ID(*assignee))
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	return queryUserIDs(ctx, tx, `SELECT id FROM users WHERE ownership_tenant_id=$1 AND id = ANY($2) AND NOT disabled AND role = ANY($3) ORDER BY id`, e.TenantID, idStrings(ids), humanNotificationRoles)
}

func resolveTeamMembers(ctx context.Context, tx pgx.Tx, e notification.Event, subject notification.PersonalSubject) ([]shared.ID, error) {
	if len(subject.TeamIDs) == 0 {
		return nil, nil
	}
	return queryUserIDs(ctx, tx, `SELECT m.user_id FROM ownership_memberships m
		JOIN ownership_teams t ON t.tenant_id=m.tenant_id AND t.id=m.team_id AND NOT t.archived
		JOIN users u ON u.ownership_tenant_id=m.tenant_id AND u.id=m.user_id AND NOT u.disabled AND u.role = ANY($3)
		WHERE m.tenant_id=$1 AND m.team_id = ANY($2)
		ORDER BY m.user_id`, e.TenantID, idStrings(subject.TeamIDs), humanNotificationRoles)
}

// resolveEngagementLead reads the lead an administrator set on the engagement's notification
// settings. An event without an engagement, or an engagement without a lead, names nobody.
func resolveEngagementLead(ctx context.Context, tx pgx.Tx, e notification.Event, _ notification.PersonalSubject) ([]shared.ID, error) {
	if e.EngagementID.IsZero() {
		return nil, nil
	}
	return queryUserIDs(ctx, tx, `SELECT u.id FROM notification_engagement_settings s
		JOIN users u ON u.ownership_tenant_id=s.tenant_id AND u.id=s.lead_user_id AND NOT u.disabled AND u.role = ANY($3)
		WHERE s.tenant_id=$1 AND s.engagement_id=$2`, e.TenantID, e.EngagementID, humanNotificationRoles)
}

func resolveTenantAdmins(ctx context.Context, tx pgx.Tx, e notification.Event, _ notification.PersonalSubject) ([]shared.ID, error) {
	return queryUserIDs(ctx, tx, `SELECT id FROM users WHERE ownership_tenant_id=$1 AND role='admin' AND NOT disabled ORDER BY id`, e.TenantID)
}

// loadPersonalDefaults reads a tenant's defaults for one event type (#1418).
func loadPersonalDefaults(ctx context.Context, tx pgx.Tx, tenant shared.ID, event notification.EventType) (notification.PersonalDefaults, error) {
	rows, err := tx.Query(ctx, `SELECT channel, enabled FROM notification_personal_defaults WHERE tenant_id=$1 AND event_type=$2`, tenant, event)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := notification.PersonalDefaults{}
	for rows.Next() {
		var channel string
		var enabled bool
		if err := rows.Scan(&channel, &enabled); err != nil {
			return nil, err
		}
		out[notification.PersonalDefaultKey{Event: event, Channel: channel}] = enabled
	}
	return out, rows.Err()
}
