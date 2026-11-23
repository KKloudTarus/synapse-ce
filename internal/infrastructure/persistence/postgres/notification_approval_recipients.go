package postgres

import (
	"context"
	"fmt"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ApprovalNotificationRecipients provides the private relational recipient
// snapshot used by approval notification projection. The rows are keyed by the
// source record rather than an event ID because the source record is the
// producer's idempotency boundary.
type ApprovalNotificationRecipients struct{ pool *pgxpool.Pool }

var _ ports.ApprovalNotificationRecipientReader = (*ApprovalNotificationRecipients)(nil)

func NewApprovalNotificationRecipients(pool *pgxpool.Pool) *ApprovalNotificationRecipients {
	return &ApprovalNotificationRecipients{pool: pool}
}

func (r *ApprovalNotificationRecipients) ApprovalNotificationRecipients(ctx context.Context, tenant shared.ID, sourceKind, sourceID string) ([]shared.ID, error) {
	var ids []shared.ID
	err := WithTenant(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT user_id FROM notification_approval_recipients
			WHERE tenant_id=$1 AND source_kind=$2 AND source_id=$3 ORDER BY user_id`, tenant, sourceKind, sourceID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id shared.ID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	})
	return ids, err
}

func approvalRecipientIDs(ids []shared.ID) []string {
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if !id.IsZero() {
			seen[id.String()] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// appendApprovalSourceTx inserts both the source and its roster in the ambient
// transaction. A conflicting source has already fixed the roster, so a retry
// must not add new identities.
func appendApprovalSourceTx(ctx context.Context, tx pgx.Tx, record notification.SourceRecord, recipients []shared.ID) error {
	tag, err := tx.Exec(ctx, appendSourceRecord,
		record.TenantID.String(), record.SourceKind, record.SourceID, string(record.EventType),
		record.EngagementID.String(), string(record.Severity), record.OccurredAt, string(record.Data),
		record.SchemaVersion, record.SubjectKind, record.SubjectID, string(record.Context), record.CaptureVersion, record.PagerLifecycle.Episode, record.PagerLifecycle.Revision, record.PagerLifecycle.Terminal)
	if err != nil {
		return fmt.Errorf("append approval notification source: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil
	}
	ids := approvalRecipientIDs(recipients)
	if len(ids) == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, `INSERT INTO notification_approval_recipients(tenant_id,source_kind,source_id,user_id)
		SELECT $1,$2,$3,unnest($4::text[])`, record.TenantID, record.SourceKind, record.SourceID, ids); err != nil {
		return fmt.Errorf("append approval notification recipients: %w", err)
	}
	return nil
}
