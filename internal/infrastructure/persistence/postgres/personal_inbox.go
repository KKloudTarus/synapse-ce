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
	inboxAge         = 90 * 24 * time.Hour
	inboxPerUserCap  = 1000
	inboxRetainBatch = 200
	personalMailKind = "personal.email"
)

var humanNotificationRoles = []string{"admin", "consultant", "reviewer", "member", "readonly", "integration_admin"}

var _ ports.RecipientResolver = (*NotificationRepository)(nil)

func (r *NotificationRepository) ResolvePersonalRecipients(ctx context.Context, tenant shared.ID, event notification.Event) ([]notification.ResolvedRecipient, error) {
	event.TenantID = tenant
	var out []notification.ResolvedRecipient
	err := WithTenant(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		var resolveErr error
		out, resolveErr = resolvePersonalRecipients(ctx, tx, event)
		return resolveErr
	})
	return out, err
}

func (r *NotificationRepository) projectPersonal(ctx context.Context, tx pgx.Tx, e notification.Event) error {
	subject, err := notification.SubjectFromEvent(e)
	if err != nil || !subject.Active() {
		return err
	}
	recipients, err := resolvePersonalRecipients(ctx, tx, e)
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
	type inboxRow struct {
		User  string `json:"user_id"`
		ID    string `json:"id"`
		Email bool   `json:"-"`
	}
	rows := make([]inboxRow, 0, len(users))
	for _, userID := range users {
		if !notification.Deliver(notification.InAppMandatory(e.Type), prefs[prefKey{userID, notification.PersonalInApp}], true) {
			continue
		}
		rows = append(rows, inboxRow{
			User:  userID.String(),
			ID:    stableID(e.TenantID.String(), userID.String(), e.ID.String()).String(),
			Email: notification.Deliver(false, prefs[prefKey{userID, notification.PersonalEmail}], false),
		})
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
	var mailUsers []string
	for _, row := range rows {
		if _, ok := created[row.User]; ok && row.Email {
			mailUsers = append(mailUsers, row.User)
		}
	}
	if len(mailUsers) == 0 {
		return nil
	}
	// Email leaves Synapse, so an engagement set to none gets no personal email job (#1360); the
	// in-app rows above stay, because the inbox is inside Synapse.
	engagement := e.EngagementID.String()
	if suppressed, err := engagementSuppressed(ctx, tx, e.TenantID, &engagement); err != nil || suppressed {
		return err
	}
	contacts, err := tx.Query(ctx, `SELECT DISTINCT ON (user_id) user_id, id, version
		FROM user_contacts
		WHERE tenant_id=$1 AND user_id = ANY($2) AND kind='email' AND verified_at IS NOT NULL
		ORDER BY user_id, verified_at DESC, id`, e.TenantID, mailUsers)
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
		jobs = append(jobs, jobRow{ID: "personal-email-" + inboxID.String(), Payload: string(payload)})
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
		ON CONFLICT(id) DO NOTHING`, e.TenantID, personalMailKind, string(encodedJobs))
	return err
}

func resolvePersonalRecipients(ctx context.Context, tx pgx.Tx, e notification.Event) ([]notification.ResolvedRecipient, error) {
	subject, err := notification.SubjectFromEvent(e)
	if err != nil || !subject.Active() {
		return nil, err
	}
	if subject.LookupFinding {
		var assignee *string
		err := tx.QueryRow(ctx, `SELECT assignee_user_id FROM findings WHERE tenant_id=$1 AND engagement_id=$2 AND id=$3`, e.TenantID, subject.EngagementID, subject.FindingID).Scan(&assignee)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		if assignee != nil && *assignee != "" {
			subject.AssigneeIDs = append(subject.AssigneeIDs, shared.ID(*assignee))
		}
	}
	var assignees, members, admins []shared.ID
	if len(subject.AssigneeIDs) > 0 {
		assignees, err = queryUserIDs(ctx, tx, `SELECT id FROM users WHERE ownership_tenant_id=$1 AND id = ANY($2) AND NOT disabled AND role = ANY($3) ORDER BY id`, e.TenantID, idStrings(subject.AssigneeIDs), humanNotificationRoles)
		if err != nil {
			return nil, err
		}
	}
	if len(subject.TeamIDs) > 0 {
		members, err = queryUserIDs(ctx, tx, `SELECT m.user_id FROM ownership_memberships m
			JOIN ownership_teams t ON t.tenant_id=m.tenant_id AND t.id=m.team_id AND NOT t.archived
			JOIN users u ON u.ownership_tenant_id=m.tenant_id AND u.id=m.user_id AND NOT u.disabled AND u.role = ANY($3)
			WHERE m.tenant_id=$1 AND m.team_id = ANY($2)
			ORDER BY m.user_id`, e.TenantID, idStrings(subject.TeamIDs), humanNotificationRoles)
		if err != nil {
			return nil, err
		}
	}
	if subject.Admins {
		admins, err = queryUserIDs(ctx, tx, `SELECT id FROM users WHERE ownership_tenant_id=$1 AND role='admin' AND NOT disabled ORDER BY id`, e.TenantID)
		if err != nil {
			return nil, err
		}
	}
	return notification.MergePersonalRecipients(assignees, members, admins), nil
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

// LoadPersonalMail rechecks the recipient at send time. A changed contact
// version or an explicit mute returns ok=false and must not retarget the job.
// It is also where personal email is admitted: an engagement set to none
// (#1360) returns ok=false, read under the lock its setting writes take.
func (s *InboxStore) LoadPersonalMail(ctx context.Context, tenant, user, event, contact shared.ID, version int) (recipient, title, summary string, ok bool, err error) {
	err = WithTenant(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
		var state *string
		var eventType string
		scanErr := tx.QueryRow(ctx, `SELECT n.title, n.summary, n.event_type, p.state
			FROM user_notifications n
			JOIN users u ON u.ownership_tenant_id=n.tenant_id AND u.id=n.user_id AND NOT u.disabled AND u.role = ANY($4)
			LEFT JOIN user_notification_preferences p ON p.tenant_id=n.tenant_id AND p.user_id=n.user_id AND p.event_type=n.event_type AND p.channel='email'
			WHERE n.tenant_id=$1 AND n.user_id=$2 AND n.event_id=$3`, tenant, user, event, humanNotificationRoles).Scan(&title, &summary, &eventType, &state)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return nil
		}
		if scanErr != nil {
			return scanErr
		}
		choice := notification.PreferenceInherit
		if state != nil {
			choice = notification.Preference(*state)
		}
		if !notification.Deliver(false, choice, false) {
			return nil
		}
		var engagement *string
		if scanErr = tx.QueryRow(ctx, `SELECT engagement_id FROM notification_events WHERE tenant_id=$1 AND id=$2`, tenant, event).Scan(&engagement); scanErr != nil && !errors.Is(scanErr, pgx.ErrNoRows) {
			return scanErr
		}
		if suppressed, err := engagementSuppressed(ctx, tx, tenant, engagement); err != nil || suppressed {
			return err
		}
		scanErr = tx.QueryRow(ctx, `SELECT value FROM user_contacts WHERE tenant_id=$1 AND user_id=$2 AND id=$3 AND version=$4 AND kind='email' AND verified_at IS NOT NULL`, tenant, user, contact, version).Scan(&recipient)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return nil
		}
		if scanErr != nil {
			return scanErr
		}
		ok = true
		return nil
	})
	return recipient, title, summary, ok, err
}

type InboxStore struct{ pool *pgxpool.Pool }

func NewInboxStore(pool *pgxpool.Pool) *InboxStore { return &InboxStore{pool: pool} }
