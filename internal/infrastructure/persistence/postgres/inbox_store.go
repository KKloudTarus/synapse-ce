package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.InboxStore = (*InboxStore)(nil)

func (s *InboxStore) ListInbox(ctx context.Context, tenant, user shared.ID, before time.Time, beforeID shared.ID, unreadOnly bool, limit int) ([]ports.InboxItem, error) {
	var out []ports.InboxItem
	err := WithTenant(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, event_id, event_type, title, summary, link_path, created_at, read_at
			FROM user_notifications
			WHERE tenant_id=$1 AND user_id=$2
			AND ($3::bool = false OR read_at IS NULL)
			AND ($4::text = '' OR (created_at, id) < ($5::timestamptz, $4::text))
			ORDER BY created_at DESC, id DESC
			LIMIT $6`, tenant, user, unreadOnly, beforeID.String(), before, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item ports.InboxItem
			if err := rows.Scan(&item.ID, &item.EventID, &item.EventType, &item.Title, &item.Summary, &item.LinkPath, &item.CreatedAt, &item.ReadAt); err != nil {
				return err
			}
			out = append(out, item)
		}
		return rows.Err()
	})
	return out, err
}

func (s *InboxStore) UnreadInbox(ctx context.Context, tenant, user shared.ID) (int, error) {
	var count int
	err := WithTenant(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM (SELECT 1 FROM user_notifications WHERE tenant_id=$1 AND user_id=$2 AND read_at IS NULL LIMIT 100) capped`, tenant, user).Scan(&count)
	})
	return count, err
}

func (s *InboxStore) MarkInboxRead(ctx context.Context, tenant, user, id shared.ID, at time.Time) error {
	return WithTenant(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE user_notifications SET read_at=COALESCE(read_at,$4) WHERE tenant_id=$1 AND user_id=$2 AND id=$3`, tenant, user, id, at)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("inbox notification %s: %w", id, shared.ErrNotFound)
		}
		return nil
	})
}

func (s *InboxStore) MarkInboxAllRead(ctx context.Context, tenant, user shared.ID, cutoff time.Time) error {
	return WithTenant(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE user_notifications SET read_at=$4 WHERE tenant_id=$1 AND user_id=$2 AND read_at IS NULL AND created_at <= $3`, tenant, user, cutoff, cutoff)
		return err
	})
}

func (s *InboxStore) ListInboxPreferences(ctx context.Context, tenant, user shared.ID) ([]ports.InboxPreference, error) {
	saved := map[string]ports.InboxPreference{}
	err := WithTenant(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT event_type, channel, state, revision FROM user_notification_preferences WHERE tenant_id=$1 AND user_id=$2`, tenant, user)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item ports.InboxPreference
			if err := rows.Scan(&item.EventType, &item.Channel, &item.State, &item.Revision); err != nil {
				return err
			}
			saved[item.EventType+"|"+item.Channel] = item
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	var out []ports.InboxPreference
	add := func(event notification.EventType, channel string, mandatory bool, reason string) {
		item := saved[string(event)+"|"+channel]
		if item.EventType == "" {
			item = ports.InboxPreference{EventType: string(event), Channel: channel, State: notification.PreferenceInherit}
		}
		item.Mandatory = mandatory
		item.Available = reason == ""
		item.Reason = reason
		out = append(out, item)
	}
	for _, event := range notification.ConfigurableEvents() {
		add(event, notification.PersonalInApp, false, "")
		add(event, notification.PersonalEmail, false, "")
	}
	add(notification.EventDestinationChanged, notification.PersonalInApp, true, "")
	add(notification.EventDestinationChanged, notification.PersonalEmail, false, "")
	out = append(out, ports.InboxPreference{EventType: string(notification.EventOwnershipChanged), Channel: "slack", State: notification.PreferenceDisabled, Available: false, Reason: "Slack direct messages are not available yet."})
	out = append(out, ports.InboxPreference{EventType: string(notification.EventOwnershipChanged), Channel: "teams", State: notification.PreferenceDisabled, Available: false, Reason: "Teams personal delivery is not available yet."})
	return out, nil
}

func (s *InboxStore) SaveInboxPreference(ctx context.Context, tenant, user shared.ID, event notification.EventType, channel string, state notification.Preference, revision int, at time.Time) (ports.InboxPreference, error) {
	item := ports.InboxPreference{EventType: string(event), Channel: channel, State: state, Mandatory: notification.InAppMandatory(event) && channel == notification.PersonalInApp, Available: true}
	err := WithTenant(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
		if revision < 1 {
			err := tx.QueryRow(ctx, `INSERT INTO user_notification_preferences(tenant_id,user_id,event_type,channel,state,revision,updated_at) VALUES($1,$2,$3,$4,$5,1,$6) ON CONFLICT DO NOTHING RETURNING revision`, tenant, user, event, channel, state, at).Scan(&item.Revision)
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("%w: preference revision is stale", shared.ErrConflict)
			}
			return err
		}
		err := tx.QueryRow(ctx, `UPDATE user_notification_preferences SET state=$5, revision=revision+1, updated_at=$6 WHERE tenant_id=$1 AND user_id=$2 AND event_type=$3 AND channel=$4 AND revision=$7 RETURNING revision`, tenant, user, event, channel, state, at, revision).Scan(&item.Revision)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: preference revision is stale", shared.ErrConflict)
		}
		return err
	})
	return item, err
}
