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
		return fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	return WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO finding_retests (id, tenant_id, engagement_id, finding_id, outcome, note, tester, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, rt.ID.String(), tenantID.String(), rt.EngagementID.String(), rt.FindingID.String(), string(rt.Outcome), rt.Note, rt.Tester, rt.At)
		return err
	})
}

// ListByEngagementFinding returns a finding's retests oldest-first, scoped to the
// engagement (no cross-engagement read).
func (r *RetestRepository) ListByEngagementFinding(ctx context.Context, engagementID, findingID shared.ID) (out []finding.Retest, err error) {
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, engagement_id, finding_id, outcome, note, tester, created_at
		 FROM finding_retests WHERE finding_id=$1 AND engagement_id=$2 ORDER BY created_at ASC, id ASC`,
			findingID.String(), engagementID.String())
		if err != nil {
			return fmt.Errorf("list retests: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				rt           finding.Retest
				id, eid, fid string
				outcome      string
			)
			if err := rows.Scan(&id, &eid, &fid, &outcome, &rt.Note, &rt.Tester, &rt.At); err != nil {
				return fmt.Errorf("scan retest: %w", err)
			}
			rt.ID, rt.EngagementID, rt.FindingID = shared.ID(id), shared.ID(eid), shared.ID(fid)
			rt.Outcome = finding.RetestOutcome(outcome)
			out = append(out, rt)
		}
		return rows.Err()
	})
	return out, err
}

// LatestByEngagementFindings projects only the effective decision, not arbitrary notes.
func (r *RetestRepository) LatestByEngagementFindings(ctx context.Context, engagementID shared.ID, findingIDs []shared.ID) (map[shared.ID]finding.Retest, error) {
	if len(findingIDs) > 1000 || engagementID.IsZero() {
		return nil, shared.ErrValidation
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() {
		return nil, shared.ErrValidation
	}
	out := make(map[shared.ID]finding.Retest)
	if len(findingIDs) == 0 {
		return out, nil
	}
	ids := make([]string, len(findingIDs))
	for index, id := range findingIDs {
		if id.IsZero() {
			return nil, shared.ErrValidation
		}
		ids[index] = id.String()
	}
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT DISTINCT ON (finding_id) id, finding_id, outcome, created_at
   FROM finding_retests WHERE tenant_id=$1 AND engagement_id=$2 AND finding_id=ANY($3::text[])
   ORDER BY finding_id, created_at DESC, id DESC`, tenantID.String(), engagementID.String(), ids)
		if err != nil {
			return fmt.Errorf("latest comparison verifications: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			decision := finding.Retest{EngagementID: engagementID}
			if err := rows.Scan(&decision.ID, &decision.FindingID, &decision.Outcome, &decision.At); err != nil {
				return err
			}
			out[decision.FindingID] = decision
		}
		return rows.Err()
	})
	return out, err
}

var _ ports.RetestLatestReader = (*RetestRepository)(nil)
