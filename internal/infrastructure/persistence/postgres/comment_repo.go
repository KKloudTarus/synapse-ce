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
var _ ports.CommentMentionRepository = (*CommentRepository)(nil)

// Add inserts a comment (append-only; comments are not edited or deleted in app code).
func (r *CommentRepository) Add(ctx context.Context, c finding.Comment) error {
	return r.add(ctx, c, nil)
}

// AddWithMentions creates the comment and immutable canonical mention relation
// in the caller's ambient tenant transaction.
func (r *CommentRepository) AddWithMentions(ctx context.Context, c finding.Comment, mentioned []shared.ID) error {
	return r.add(ctx, c, mentioned)
}

func (r *CommentRepository) add(ctx context.Context, c finding.Comment, mentioned []shared.ID) error {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	return WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO finding_comments (id, tenant_id, engagement_id, finding_id, author, body, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`, c.ID.String(), tenantID.String(), c.EngagementID.String(), c.FindingID.String(), c.Author, c.Body, c.CreatedAt); err != nil {
			return err
		}
		for _, userID := range mentioned {
			if _, err := tx.Exec(ctx, `INSERT INTO finding_comment_mentions (tenant_id, comment_id, user_id) VALUES ($1,$2,$3)`, tenantID.String(), c.ID.String(), userID.String()); err != nil {
				return err
			}
		}
		return nil
	})
}

// ListByEngagementFinding returns a finding's comments oldest-first, scoped to the
// engagement (no cross-engagement read).
func (r *CommentRepository) ListByEngagementFinding(ctx context.Context, engagementID, findingID shared.ID) (out []finding.Comment, err error) {
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT c.id, c.engagement_id, c.finding_id, c.author, c.body, c.created_at,
			        COALESCE(array_agg(m.user_id) FILTER (WHERE m.user_id IS NOT NULL), '{}')
		 FROM finding_comments c
		 LEFT JOIN finding_comment_mentions m ON m.tenant_id=c.tenant_id AND m.comment_id=c.id
		 WHERE c.finding_id=$1 AND c.engagement_id=$2
		 GROUP BY c.id, c.tenant_id, c.engagement_id, c.finding_id, c.author, c.body, c.created_at
		 ORDER BY c.created_at ASC, c.id ASC`,
			findingID.String(), engagementID.String())
		if err != nil {
			return fmt.Errorf("list comments: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				c            finding.Comment
				id, eid, fid string
				mentioned    []string
			)
			if err := rows.Scan(&id, &eid, &fid, &c.Author, &c.Body, &c.CreatedAt, &mentioned); err != nil {
				return fmt.Errorf("scan comment: %w", err)
			}
			c.ID, c.EngagementID, c.FindingID = shared.ID(id), shared.ID(eid), shared.ID(fid)
			for _, userID := range mentioned {
				c.MentionUserIDs = append(c.MentionUserIDs, shared.ID(userID))
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}
