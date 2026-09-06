package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	demu "github.com/KKloudTarus/synapse-ce/internal/domain/emulation"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// EmulationRunRepository persists emulation runs and coverage (migration 0073), tenant-scoped via
// WithTenant so RLS isolates one tenant's coverage from another's.
type EmulationRunRepository struct{ pool *pgxpool.Pool }

// NewEmulationRunRepository constructs the repository.
func NewEmulationRunRepository(pool *pgxpool.Pool) *EmulationRunRepository {
	return &EmulationRunRepository{pool: pool}
}

// SaveRun writes the run and all its coverage rows in one transaction, so a partially-written run can
// never present as complete coverage.
func (r *EmulationRunRepository) SaveRun(ctx context.Context, run demu.Run) error {
	if run.ID == "" {
		return fmt.Errorf("%w: emulation run requires an id", shared.ErrValidation)
	}
	// The written tenant is the AUTHENTICATED tenant on the context, never the run's self-declared
	// TenantID: a run must not be able to write into another tenant's partition by claiming a different
	// id. RLS WITH CHECK is the backstop, but binding the session variable to run.TenantID would make it
	// self-referential, so derive it from the context and reject a mismatch here (the same defense the
	// sibling coverage store applies).
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant == "" {
		return fmt.Errorf("emulation run: no tenant in context: %w", shared.ErrValidation)
	}
	if run.TenantID != "" && run.TenantID != tenant {
		return fmt.Errorf("emulation run: run tenant %q does not match context: %w", run.TenantID, shared.ErrForbidden)
	}
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO emulation_runs (tenant_id, id, engagement_id, target, actor)
			VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT (tenant_id, id) DO UPDATE SET target = EXCLUDED.target, actor = EXCLUDED.actor`,
			tenant.String(), run.ID.String(), run.EngagementID.String(), run.Target.String(), run.Actor); err != nil {
			return fmt.Errorf("upsert emulation run: %w", err)
		}
		for _, rec := range run.Coverage {
			var actual *string
			if rec.Actual != "" {
				a := rec.Actual
				actual = &a
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO emulation_coverage
				  (tenant_id, run_id, technique_id, taxonomy_ref, executed, expected_detection, actual_detection, gap)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
				ON CONFLICT (tenant_id, run_id, technique_id) DO UPDATE SET
				  executed = EXCLUDED.executed, actual_detection = EXCLUDED.actual_detection, gap = EXCLUDED.gap`,
				tenant.String(), run.ID.String(), rec.TechniqueID, rec.TaxonomyRef,
				rec.Executed, rec.Expected, actual, rec.Gap); err != nil {
				return fmt.Errorf("upsert coverage %s: %w", rec.TechniqueID, err)
			}
		}
		return nil
	})
}
