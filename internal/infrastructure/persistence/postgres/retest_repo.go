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

// RetestRepository persists the per-finding retest history to PostgreSQL.
type RetestRepository struct{ pool *pgxpool.Pool }

// NewRetestRepository returns a repository backed by the given pool.
func NewRetestRepository(pool *pgxpool.Pool) *RetestRepository {
	return &RetestRepository{pool: pool}
}

var _ ports.RetestRepository = (*RetestRepository)(nil)

// Add inserts a retest (append-only; retests are not edited or deleted in app code).
func (r *RetestRepository) Add(ctx context.Context, rt finding.Retest) error {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return fmt.Errorf("tenant context is required")
	}
	return WithTenantTx(ctx, r.pool, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO finding_retests (id, tenant_id, engagement_id, finding_id, outcome, note, tester, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, rt.ID.String(), tenantID.String(), rt.EngagementID.String(), rt.FindingID.String(), string(rt.Outcome), rt.Note, rt.Tester, rt.At); err != nil {
			return fmt.Errorf("insert retest: %w", err)
		}
		return nil
	})
}

// ListByEngagementFinding returns a finding's retests oldest-first, scoped to the
// engagement (no cross-engagement read).
func (r *RetestRepository) ListByEngagementFinding(ctx context.Context, engagementID, findingID shared.ID) (out []finding.Retest, err error) {
	err = WithContextTenantTx(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, engagement_id, finding_id, outcome, note, tester, created_at FROM finding_retests WHERE finding_id=$1 AND engagement_id=$2 ORDER BY created_at ASC, id ASC`, findingID.String(), engagementID.String())
		if err != nil {
			return fmt.Errorf("list retests: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var rt finding.Retest
			var id, eid, fid, outcome string
			if err := rows.Scan(&id, &eid, &fid, &outcome, &rt.Note, &rt.Tester, &rt.At); err != nil {
				return fmt.Errorf("scan retest: %w", err)
			}
			rt.ID, rt.EngagementID, rt.FindingID, rt.Outcome = shared.ID(id), shared.ID(eid), shared.ID(fid), finding.RetestOutcome(outcome)
			out = append(out, rt)
		}
		return rows.Err()
	})
	return out, err
}
