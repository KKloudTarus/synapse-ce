package postgres

import (
	"context"
	"errors"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
)

var _ ports.DocumentScheduleHistoryReader = (*DocumentStore)(nil)

func (s *DocumentStore) ListDocumentScheduleRuns(ctx context.Context, tenant, scheduleID shared.ID, limit int) ([]ports.DocumentScheduleRunView, error) {
	if tenant.IsZero() || scheduleID.IsZero() || limit < 1 || limit > 50 {
		return nil, shared.ErrValidation
	}
	out := make([]ports.DocumentScheduleRunView, 0, limit)
	err := requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		// Limit occurrences before joining deliveries. A long-lived weekly schedule
		// can otherwise aggregate every historical delivery just to return 20 rows.
		rows, err := tx.Query(ctx, `WITH recent AS (
			SELECT id,tenant_id,due_at,state,artifact_digest,remote_page_id,remote_version,updated_at
			FROM document_schedule_occurrences
			WHERE tenant_id=$1 AND schedule_id=$2
			ORDER BY due_at DESC,id DESC
			LIMIT $3
		)
			SELECT o.id,o.due_at,o.state,o.artifact_digest,o.remote_page_id,o.remote_version,
			COUNT(d.id) FILTER (WHERE d.state='done'),
			COUNT(d.id) FILTER (WHERE d.state='uncertain'),
			COUNT(d.id) FILTER (WHERE d.state IN ('failed','rejected')),o.updated_at
			FROM recent o
			LEFT JOIN document_schedule_deliveries d ON d.tenant_id=o.tenant_id AND d.occurrence_id=o.id
			GROUP BY o.id,o.due_at,o.state,o.artifact_digest,o.remote_page_id,o.remote_version,o.updated_at
			ORDER BY o.due_at DESC,o.id DESC`, tenant.String(), scheduleID.String(), limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item ports.DocumentScheduleRunView
			if err := rows.Scan(&item.ID, &item.DueAt, &item.State, &item.ContentHash, &item.RemotePageID, &item.RemoteVersion, &item.DeliveredCount, &item.UncertainCount, &item.FailedCount, &item.UpdatedAt); err != nil {
				return err
			}
			item.DueAt = item.DueAt.UTC()
			item.UpdatedAt = item.UpdatedAt.UTC()
			out = append(out, item)
		}
		return rows.Err()
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	return out, err
}
