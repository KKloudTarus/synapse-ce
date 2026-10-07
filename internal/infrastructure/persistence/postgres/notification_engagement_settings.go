package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Engagement notification overrides (#1360, migration 0222). A missing row means inherit.

func (r *NotificationRepository) GetEngagementNotificationSetting(ctx context.Context, tenant, engagement shared.ID) (notification.EngagementNotificationSetting, error) {
	out := notification.EngagementNotificationSetting{TenantID: tenant, EngagementID: engagement, ExternalNotifications: notification.EngagementNotificationsInherit}
	err := WithTenant(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		if err := requireEngagement(ctx, tx, tenant, engagement); err != nil {
			return err
		}
		var value string
		err := tx.QueryRow(ctx, `SELECT external_notifications,revision,updated_at,updated_by FROM notification_engagement_settings WHERE tenant_id=$1 AND engagement_id=$2`, tenant, engagement).
			Scan(&value, &out.Revision, &out.UpdatedAt, &out.UpdatedBy)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		out.ExternalNotifications = notification.EngagementNotifications(value)
		return err
	})
	return out, err
}

func (r *NotificationRepository) PutEngagementNotificationSetting(ctx context.Context, s notification.EngagementNotificationSetting) (notification.EngagementNotificationSetting, error) {
	if err := s.Validate(); err != nil {
		return notification.EngagementNotificationSetting{}, err
	}
	err := WithTenant(ctx, r.pool, s.TenantID.String(), func(tx pgx.Tx) error {
		if err := lockEngagementSetting(ctx, tx, s.TenantID, s.EngagementID, true); err != nil {
			return err
		}
		if err := requireEngagement(ctx, tx, s.TenantID, s.EngagementID); err != nil {
			return err
		}
		// Revision 1 creates the row; any later revision replaces exactly the one before it. Either
		// way a concurrent writer that got there first leaves this statement without a row.
		query := `UPDATE notification_engagement_settings SET external_notifications=$3,revision=$4,updated_at=$5,updated_by=$6
			WHERE tenant_id=$1 AND engagement_id=$2 AND revision=$4-1`
		if s.Revision == 1 {
			query = `INSERT INTO notification_engagement_settings(tenant_id,engagement_id,external_notifications,revision,updated_at,updated_by)
				VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,engagement_id) DO NOTHING`
		}
		tag, err := tx.Exec(ctx, query, s.TenantID, s.EngagementID, s.ExternalNotifications, s.Revision, s.UpdatedAt, s.UpdatedBy)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("engagement notification setting revision is stale: %w", shared.ErrConflict)
		}
		if s.ExternalNotifications != notification.EngagementNotificationsNone {
			return nil
		}
		// Queued deliveries about the engagement are cancelled now rather than at their next load.
		// One whose attempt already started is in flight and is left to finish.
		_, err = tx.Exec(ctx, `UPDATE notification_deliveries d SET state='cancelled',last_error=$3,next_attempt_at=NULL,updated_at=$4
			WHERE d.tenant_id=$1 AND d.state IN ('pending','retrying')
			AND EXISTS(SELECT 1 FROM notification_events e WHERE e.tenant_id=d.tenant_id AND e.id=d.event_id AND e.engagement_id=$2)
			AND NOT EXISTS(SELECT 1 FROM notification_delivery_attempts a WHERE a.tenant_id=d.tenant_id AND a.delivery_id=d.id AND a.outcome='started')`,
			s.TenantID, s.EngagementID, notification.CodeEngagementSuppressed, s.UpdatedAt)
		return err
	})
	if err != nil {
		return notification.EngagementNotificationSetting{}, err
	}
	return s, nil
}

// lockEngagementSetting serializes setting writes with attempt admission for one engagement. A
// write takes the lock exclusively and an admission shares it, so an attempt is admitted either
// before a write commits, and the write then sees its started attempt, or after, and the admission
// reads the committed setting. A transaction lock also covers the first write, when there is no
// settings row to lock yet.
func lockEngagementSetting(ctx context.Context, tx pgx.Tx, tenant, engagement shared.ID, write bool) error {
	lock := "pg_advisory_xact_lock_shared"
	if write {
		lock = "pg_advisory_xact_lock"
	}
	_, err := tx.Exec(ctx, `SELECT `+lock+`(hashtextextended('notification-engagement-setting:' || $1 || ':' || $2, 0))`, tenant, engagement)
	return err
}

// admitEngagement refuses an attempt while the delivery's engagement allows no external
// notification. The refusal is retryable, as for a channel paused after LoadWork: the retry
// reloads the work and cancels the delivery with engagement_suppressed.
func admitEngagement(ctx context.Context, tx pgx.Tx, tenant, delivery shared.ID) error {
	var engagement *string
	if err := tx.QueryRow(ctx, `SELECT e.engagement_id FROM notification_deliveries d JOIN notification_events e ON e.tenant_id=d.tenant_id AND e.id=d.event_id WHERE d.tenant_id=$1 AND d.id=$2`, tenant, delivery).Scan(&engagement); err != nil {
		return err
	}
	suppressed, err := engagementSuppressed(ctx, tx, tenant, engagement)
	if err != nil {
		return err
	}
	if suppressed {
		return fmt.Errorf("%w: engagement suppressed", ports.ErrRetryable)
	}
	return nil
}

// engagementSuppressed reports whether the engagement allows no external notification. It takes
// the shared side of lockEngagementSetting first, so it reads the setting a concurrent write
// commits rather than the one before it. An event without an engagement is never suppressed.
// Channel deliveries and personal email both admit through it.
func engagementSuppressed(ctx context.Context, tx pgx.Tx, tenant shared.ID, engagement *string) (bool, error) {
	if engagement == nil || *engagement == "" {
		return false, nil
	}
	if err := lockEngagementSetting(ctx, tx, tenant, shared.ID(*engagement), false); err != nil {
		return false, err
	}
	var value string
	err := tx.QueryRow(ctx, `SELECT external_notifications FROM notification_engagement_settings WHERE tenant_id=$1 AND engagement_id=$2`, tenant, *engagement).Scan(&value)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return notification.EngagementNotifications(value) == notification.EngagementNotificationsNone, nil
}

// requireEngagement reports ErrNotFound for an engagement the tenant does not have.
func requireEngagement(ctx context.Context, tx pgx.Tx, tenant, engagement shared.ID) error {
	var found bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM engagements WHERE tenant_id=$1 AND id=$2)`, tenant, engagement).Scan(&found); err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("engagement %s: %w", engagement, shared.ErrNotFound)
	}
	return nil
}
