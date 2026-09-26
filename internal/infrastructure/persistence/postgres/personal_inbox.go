package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	inboxAge         = 90 * 24 * time.Hour
	inboxPerUserCap  = 1000
	inboxRetainBatch = 200
	personalMailKind = "personal.email"
)

var humanNotificationRoles = []string{"admin", "consultant", "reviewer", "member", "readonly"}

func (r *NotificationRepository) projectPersonal(ctx context.Context, tx pgx.Tx, e notification.Event) error {
	subject, err := notification.SubjectFromEvent(e)
	if err != nil || !subject.Active() {
		return err
	}
	if subject.LookupFinding {
		var assignee *string
		err := tx.QueryRow(ctx, `SELECT assignee_user_id FROM findings WHERE tenant_id=$1 AND engagement_id=$2 AND id=$3`, e.TenantID, subject.EngagementID, subject.FindingID).Scan(&assignee)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if assignee != nil && *assignee != "" {
			subject.AssigneeIDs = append(subject.AssigneeIDs, shared.ID(*assignee))
		}
	}
	users, err := eligiblePersonalUsers(ctx, tx, e.TenantID, subject)
	if err != nil || len(users) == 0 {
		return err
	}
	prefs, err := personalPreferences(ctx, tx, e.TenantID, e.Type, users)
	if err != nil {
		return err
	}
	for _, userID := range users {
		if !notification.Deliver(notification.InAppMandatory(e.Type), prefs[prefKey{userID, notification.PersonalInApp}], true) {
			continue
		}
		id := stableID(e.TenantID.String(), userID.String(), e.ID.String())
		tag, err := tx.Exec(ctx, `INSERT INTO user_notifications(tenant_id,user_id,id,event_id,event_type,title,summary,link_path,created_at)
			SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9
			WHERE NOT EXISTS (SELECT 1 FROM user_notification_tombstones t WHERE t.tenant_id=$1 AND t.user_id=$2 AND t.event_id=$4)
			ON CONFLICT(tenant_id,user_id,event_id) DO NOTHING`, e.TenantID, userID, id, e.ID, e.Type, subject.Title, limitText(subject.Summary, 500), subject.Link, e.OccurredAt)
		if err != nil {
			return fmt.Errorf("project personal inbox: %w", err)
		}
		if tag.RowsAffected() == 0 || !notification.Deliver(false, prefs[prefKey{userID, notification.PersonalEmail}], false) {
			continue
		}
		var contactID shared.ID
		var version int
		err = tx.QueryRow(ctx, `SELECT id, version FROM user_contacts WHERE tenant_id=$1 AND user_id=$2 AND kind='email' AND verified_at IS NOT NULL ORDER BY verified_at DESC, id LIMIT 1`, e.TenantID, userID).Scan(&contactID, &version)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		payload, _ := json.Marshal(map[string]any{"event_id": e.ID, "user_id": userID, "contact_id": contactID, "contact_version": version})
		if _, err := tx.Exec(ctx, `INSERT INTO jobs(id,tenant_id,kind,payload,status,available_at) VALUES($1,$2,$3,$4,'queued',$5) ON CONFLICT(id) DO NOTHING`, "personal-email-"+id.String(), e.TenantID, personalMailKind, payload, e.OccurredAt); err != nil {
			return err
		}
	}
	return nil
}

func eligiblePersonalUsers(ctx context.Context, tx pgx.Tx, tenant shared.ID, subject notification.PersonalSubject) ([]shared.ID, error) {
	found := map[shared.ID]struct{}{}
	var out []shared.ID
	add := func(id shared.ID) {
		if id.IsZero() {
			return
		}
		if _, ok := found[id]; ok {
			return
		}
		found[id] = struct{}{}
		out = append(out, id)
	}
	if subject.Admins {
		rows, err := tx.Query(ctx, `SELECT id FROM users WHERE ownership_tenant_id=$1 AND role='admin' AND NOT disabled ORDER BY id`, tenant)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id shared.ID
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return nil, err
			}
			add(id)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	if len(subject.AssigneeIDs) > 0 {
		rows, err := tx.Query(ctx, `SELECT id FROM users WHERE ownership_tenant_id=$1 AND id = ANY($2) AND NOT disabled AND role = ANY($3)`, tenant, idStrings(subject.AssigneeIDs), humanNotificationRoles)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id shared.ID
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return nil, err
			}
			add(id)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	if len(subject.TeamIDs) > 0 {
		rows, err := tx.Query(ctx, `SELECT m.user_id FROM ownership_memberships m
			JOIN ownership_teams t ON t.tenant_id=m.tenant_id AND t.id=m.team_id AND NOT t.archived
			JOIN users u ON u.ownership_tenant_id=m.tenant_id AND u.id=m.user_id AND NOT u.disabled AND u.role = ANY($3)
			WHERE m.tenant_id=$1 AND m.team_id = ANY($2)`, tenant, idStrings(subject.TeamIDs), humanNotificationRoles)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id shared.ID
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return nil, err
			}
			add(id)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	return out, nil
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
	if err := deleteInbox(ctx, tx, `SELECT tenant_id, user_id, id, event_id FROM user_notifications WHERE tenant_id=$1 AND created_at < $2 ORDER BY created_at, id LIMIT $3`, tenant, now.Add(-inboxAge), inboxRetainBatch); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT user_id FROM user_notifications WHERE tenant_id=$1 GROUP BY user_id HAVING count(*) > $2 ORDER BY user_id LIMIT 20`, tenant, inboxPerUserCap)
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
		if err := deleteInbox(ctx, tx, `SELECT tenant_id, user_id, id, event_id FROM (
			SELECT tenant_id, user_id, id, event_id, row_number() OVER (ORDER BY created_at DESC, id DESC) AS n
			FROM user_notifications WHERE tenant_id=$1 AND user_id=$2
		) ranked WHERE n > $3 ORDER BY n DESC LIMIT $4`, tenant, userID, inboxPerUserCap, inboxRetainBatch); err != nil {
			return err
		}
	}
	return nil
}

func deleteInbox(ctx context.Context, tx pgx.Tx, query string, args ...any) error {
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return err
	}
	type row struct{ tenant, user, id, event shared.ID }
	var doomed []row
	for rows.Next() {
		var item row
		if err := rows.Scan(&item.tenant, &item.user, &item.id, &item.event); err != nil {
			rows.Close()
			return err
		}
		doomed = append(doomed, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, item := range doomed {
		if _, err := tx.Exec(ctx, `INSERT INTO user_notification_tombstones(tenant_id,user_id,event_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, item.tenant, item.user, item.event); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM user_notifications WHERE tenant_id=$1 AND user_id=$2 AND id=$3`, item.tenant, item.user, item.id); err != nil {
			return err
		}
	}
	return nil
}

func (r *NotificationRepository) EnableDestinationNotices() { r.destinationNotices = true }

func (r *NotificationRepository) maybeDestinationNotice(ctx context.Context, tx pgx.Tx, channel notification.Channel, action string) error {
	if !r.destinationNotices || (channel.Type != notification.ChannelWebhook && channel.Type != notification.ChannelSlack) {
		return nil
	}
	event, err := notification.NewDestinationEvent(channel.TenantID, channel.ID, channel.Type, channel.Destination, action, notification.ActorFrom(ctx), channel.UpdatedAt)
	if err != nil {
		return err
	}
	event.ID = stableID(channel.TenantID.String(), event.SourceKind, event.SourceID)
	_, err = r.publishTx(ctx, tx, event, "")
	return err
}

// LoadPersonalMail rechecks the recipient at send time. A changed contact
// version or an explicit mute returns ok=false and must not retarget the job.
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
