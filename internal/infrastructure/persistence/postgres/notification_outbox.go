package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// NotificationOutbox appends notification source records inside the caller's tenant transaction.
type NotificationOutbox struct{ pool *pgxpool.Pool }

var _ ports.NotificationOutbox = (*NotificationOutbox)(nil)

func NewNotificationOutbox(pool *pgxpool.Pool) *NotificationOutbox {
	return &NotificationOutbox{pool: pool}
}

// appendSourceRecord keeps the activation gate of notification_capture_source() (migration 0163):
// a record dated before the tenant activated notifications is not written, so enabling the
// framework never replays history.
const appendSourceRecord = `INSERT INTO notification_source_records
	(tenant_id,source_kind,source_id,event_type,engagement_id,severity,occurred_at,data,schema_version,subject_kind,subject_id,context)
	SELECT $1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11,$12::jsonb
	WHERE EXISTS (SELECT 1 FROM notification_source_state s
		WHERE s.tenant_id=$1 AND s.source_kind='framework' AND s.source_id='activation' AND s.observed_at<=$7)
	ON CONFLICT (tenant_id,source_kind,source_id) DO NOTHING`

// Append writes record in the ambient transaction started by TenantTransactionRunner.Run. It does
// not open a transaction of its own: an append outside the producer's business transaction is a
// bug that would decouple the notification from the write, so it fails instead.
func (o *NotificationOutbox) Append(ctx context.Context, record notification.SourceRecord) error {
	if err := record.Normalize(); err != nil {
		return err
	}
	bound, ok := ctx.Value(tenantTransactionKey{}).(tenantTransaction)
	if !ok {
		return fmt.Errorf("%w: notification outbox append requires a tenant transaction", shared.ErrValidation)
	}
	if bound.tenantID != record.TenantID.String() {
		return fmt.Errorf("%w: notification outbox record belongs to another tenant", shared.ErrValidation)
	}
	return WithTenant(ctx, o.pool, record.TenantID.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, appendSourceRecord,
			record.TenantID.String(), record.SourceKind, record.SourceID, string(record.EventType),
			record.EngagementID.String(), string(record.Severity), record.OccurredAt, string(record.Data),
			record.SchemaVersion, record.SubjectKind, record.SubjectID, string(record.Context))
		if err != nil {
			return fmt.Errorf("append notification source record: %w", err)
		}
		return nil
	})
}
