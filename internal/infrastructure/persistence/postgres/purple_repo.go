package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	pcdom "github.com/KKloudTarus/synapse-ce/internal/domain/purplecoverage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// PurpleRepository persists purple-team coverage (migration 0077), tenant-scoped via WithTenant/RLS so
// one tenant's coverage is never visible to another.
type PurpleRepository struct{ pool *pgxpool.Pool }

var _ ports.PurpleCoverageStore = (*PurpleRepository)(nil)

// NewPurpleRepository constructs the repository.
func NewPurpleRepository(pool *pgxpool.Pool) *PurpleRepository {
	return &PurpleRepository{pool: pool}
}

// SaveCoverage upserts a run's coverage under the authenticated tenant, keyed (run, technique), in one
// transaction so a re-computation of a run is atomic.
func (r *PurpleRepository) SaveCoverage(ctx context.Context, records []pcdom.Coverage) error {
	// The written tenant is the AUTHENTICATED tenant on the context, never the record's self-declared
	// TenantID: a record must not be able to write into another tenant's partition by claiming a
	// different id. RLS WITH CHECK is the backstop, but this makes the store correct on its own (the
	// same defense-in-depth the memory store applies), so a misconfigured/superuser role cannot silently
	// write a foreign tenant_id.
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant == "" {
		return fmt.Errorf("purple coverage: no tenant in context: %w", shared.ErrValidation)
	}
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		for _, c := range records {
			if c.TenantID != "" && c.TenantID != tenant {
				return fmt.Errorf("purple coverage: record tenant %q does not match context: %w", c.TenantID, shared.ErrForbidden)
			}
			if err := c.Validate(); err != nil {
				return err
			}
			actual, err := json.Marshal(c.Actual)
			if err != nil {
				return fmt.Errorf("marshal actual for %s: %w", c.TechniqueID, err)
			}
			_, err = tx.Exec(ctx, `
				INSERT INTO purple_coverage
				  (tenant_id, run_id, technique_id, engagement_id, asset_id, taxonomy_ref, expected, actual, verdict, computed_at)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
				ON CONFLICT (tenant_id, run_id, technique_id) DO UPDATE SET
				  engagement_id = EXCLUDED.engagement_id, asset_id = EXCLUDED.asset_id,
				  taxonomy_ref = EXCLUDED.taxonomy_ref, expected = EXCLUDED.expected,
				  actual = EXCLUDED.actual, verdict = EXCLUDED.verdict, computed_at = EXCLUDED.computed_at`,
				tenant.String(), c.RunID.String(), c.TechniqueID, c.EngagementID.String(),
				c.AssetID.String(), c.TaxonomyRef, c.Expected, actual, string(c.Verdict), c.ComputedAt.UTC())
			if err != nil {
				return fmt.Errorf("upsert coverage %s/%s: %w", c.RunID, c.TechniqueID, err)
			}
		}
		return nil
	})
}

// ListByRun returns one run's coverage in the ctx tenant, ordered by technique.
func (r *PurpleRepository) ListByRun(ctx context.Context, runID shared.ID) ([]pcdom.Coverage, error) {
	return r.query(ctx, `
		SELECT tenant_id, run_id, technique_id, engagement_id, asset_id, taxonomy_ref, expected, actual, verdict, computed_at
		FROM purple_coverage WHERE run_id = $1 ORDER BY technique_id ASC`, runID.String())
}

// ListByEngagement returns all coverage for an engagement in the ctx tenant, oldest first, so a trend
// across runs is queryable.
func (r *PurpleRepository) ListByEngagement(ctx context.Context, engagementID shared.ID) ([]pcdom.Coverage, error) {
	return r.query(ctx, `
		SELECT tenant_id, run_id, technique_id, engagement_id, asset_id, taxonomy_ref, expected, actual, verdict, computed_at
		FROM purple_coverage WHERE engagement_id = $1 ORDER BY computed_at ASC, run_id ASC, technique_id ASC`, engagementID.String())
}

func (r *PurpleRepository) query(ctx context.Context, sql string, arg string) ([]pcdom.Coverage, error) {
	var out []pcdom.Coverage
	err := WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, sql, arg)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, err := scanCoverage(rows)
			if err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

func scanCoverage(row rowScanner) (pcdom.Coverage, error) {
	var (
		tenant, run, tech, eng, asset, tax, expected, verdict string
		actual                                                []byte
		c                                                     pcdom.Coverage
	)
	if err := row.Scan(&tenant, &run, &tech, &eng, &asset, &tax, &expected, &actual, &verdict, &c.ComputedAt); err != nil {
		return pcdom.Coverage{}, err
	}
	var actualSlice []string
	if len(actual) > 0 {
		if err := json.Unmarshal(actual, &actualSlice); err != nil {
			return pcdom.Coverage{}, fmt.Errorf("unmarshal actual: %w", err)
		}
	}
	c.TenantID = shared.ID(tenant)
	c.RunID = shared.ID(run)
	c.TechniqueID = tech
	c.EngagementID = shared.ID(eng)
	c.AssetID = shared.ID(asset)
	c.TaxonomyRef = tax
	c.Expected = expected
	c.Actual = actualSlice
	c.Verdict = pcdom.Verdict(verdict)
	return c, nil
}
