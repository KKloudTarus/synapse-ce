package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// CommentRepository persists the per-finding comment thread to PostgreSQL.
type CommentRepository struct{ pool *pgxpool.Pool }

// NewCommentRepository returns a repository backed by the given pool.
func NewCommentRepository(pool *pgxpool.Pool) *CommentRepository {
	return &CommentRepository{pool: pool}
}

var _ ports.CommentRepository = (*CommentRepository)(nil)

// Add inserts a comment (append-only; comments are not edited or deleted in app code).
func (r *CommentRepository) Add(ctx context.Context, c finding.Comment) error {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	return WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO finding_comments (id, tenant_id, engagement_id, finding_id, author, body, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`, c.ID.String(), tenantID.String(), c.EngagementID.String(), c.FindingID.String(), c.Author, c.Body, c.CreatedAt)
		return err
	})
}

// ListByEngagementFinding returns a finding's comments oldest-first, scoped to the
// engagement (no cross-engagement read).
func (r *CommentRepository) ListByEngagementFinding(ctx context.Context, engagementID, findingID shared.ID) (out []finding.Comment, err error) {
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, engagement_id, finding_id, author, body, created_at
		 FROM finding_comments WHERE finding_id=$1 AND engagement_id=$2 ORDER BY created_at ASC, id ASC`,
			findingID.String(), engagementID.String())
		if err != nil {
			return fmt.Errorf("list comments: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				c            finding.Comment
				id, eid, fid string
			)
			if err := rows.Scan(&id, &eid, &fid, &c.Author, &c.Body, &c.CreatedAt); err != nil {
				return fmt.Errorf("scan comment: %w", err)
			}
			c.ID, c.EngagementID, c.FindingID = shared.ID(id), shared.ID(eid), shared.ID(fid)
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}
