package postgres

import (
	"context"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/jackc/pgx/v5"
	"time"
)

func (s *NotificationSource) pollCaptured(ctx context.Context, tx pgx.Tx, tenant shared.ID, kind string, now time.Time, limit int, enabled bool) (int, error) {
	rows, err := tx.Query(ctx, `SELECT source_id,event_type,engagement_id,severity,occurred_at,data FROM notification_source_records WHERE tenant_id=$1 AND source_kind=$2 AND processed_at IS NULL ORDER BY occurred_at,source_id LIMIT $3 FOR UPDATE SKIP LOCKED`, tenant, kind, limit)
	if err != nil {
		return 0, err
	}
	var events []notification.Event
	for rows.Next() {
		e := notification.Event{TenantID: tenant, SourceKind: kind, SchemaVersion: 1}
		if err := rows.Scan(&e.SourceID, &e.Type, &e.EngagementID, &e.Severity, &e.OccurredAt, &e.Data); err != nil {
			rows.Close()
			return 0, err
		}
		e.ID = stableID(tenant.String(), kind, e.SourceID)
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()
	for _, e := range events {
		if enabled {
			if _, err := s.repo.publishTx(ctx, tx, e, ""); err != nil {
				return 0, err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE notification_source_records SET processed_at=$4 WHERE tenant_id=$1 AND source_kind=$2 AND source_id=$3`, tenant, kind, e.SourceID, now); err != nil {
			return 0, err
		}
	}
	return len(events), nil
}
