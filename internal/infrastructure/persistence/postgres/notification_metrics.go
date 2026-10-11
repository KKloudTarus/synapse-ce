package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// NotificationOldestPending aggregates every tenant's pending/retrying backlog
// while reading each RLS partition inside its own tenant-scoped transaction.
// Neither the result nor any Prometheus label exposes a tenant or destination.
func (r *NotificationRepository) NotificationOldestPending(ctx context.Context) (map[notification.ChannelType]time.Time, error) {
	tenants, err := listTenantIDs(ctx, r.pool, "notification metrics")
	if err != nil {
		return nil, err
	}
	oldest := make(map[notification.ChannelType]time.Time)
	for _, tenant := range logicalQueueTenantIDs(tenants) {
		err := WithTenant(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT channel_type, MIN(created_at)
				FROM notification_deliveries
				WHERE tenant_id=$1 AND state IN ('pending','retrying')
				GROUP BY channel_type`, tenant)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var rawType string
				var at time.Time
				if err := rows.Scan(&rawType, &at); err != nil {
					return err
				}
				typ := notification.ChannelType(rawType)
				if prev, ok := oldest[typ]; !ok || at.Before(prev) {
					oldest[typ] = at
				}
			}
			return rows.Err()
		})
		if err != nil {
			// A partial aggregate must never be published as healthy metrics.
			return nil, fmt.Errorf("read notification pending age: %w", err)
		}
	}
	return oldest, nil
}

var _ ports.NotificationPendingMetricsReader = (*NotificationRepository)(nil)
