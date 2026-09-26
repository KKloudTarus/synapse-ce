package postgres

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AssigneeReviewReader struct{ pool *pgxpool.Pool }

func NewAssigneeReviewReader(pool *pgxpool.Pool) *AssigneeReviewReader {
	return &AssigneeReviewReader{pool: pool}
}

var _ ports.AssigneeReviewReader = (*AssigneeReviewReader)(nil)

func (r *AssigneeReviewReader) ListAssigneeReview(ctx context.Context, tenantID, engCursor, findCursor shared.ID, limit int) ([]ports.AssigneeReviewItem, error) {
	if limit < 1 || limit > 100 {
		limit = 50
	}
	out := make([]ports.AssigneeReviewItem, 0)
	err := WithTenant(ctx, r.pool, shared.TenantOrDefault(tenantID).String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT r.engagement_id,r.finding_id,r.legacy_assignee,r.reason FROM finding_assignee_backfill_review r JOIN findings f ON f.tenant_id=r.tenant_id AND f.engagement_id=r.engagement_id AND f.id=r.finding_id WHERE r.tenant_id=$1 AND f.assignee_user_id IS NULL AND ($2='' OR (r.engagement_id,r.finding_id)>($2,$3)) ORDER BY r.engagement_id,r.finding_id LIMIT $4`, shared.TenantOrDefault(tenantID), engCursor, findCursor, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item ports.AssigneeReviewItem
			if err := rows.Scan(&item.EngagementID, &item.FindingID, &item.LegacyAssignee, &item.Reason); err != nil {
				return err
			}
			out = append(out, item)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list canonical assignee review: %w", err)
	}
	return out, nil
}
