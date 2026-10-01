package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
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
		return nil
	})
	if err != nil {
		return notification.EngagementNotificationSetting{}, err
	}
	return s, nil
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
