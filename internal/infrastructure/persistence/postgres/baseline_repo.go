package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/baseline"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// BaselineRepository is the Postgres tier for the behavioral-baseline projection (Phase D / D5). A
// baseline is a MUTABLE projection keyed by (tenant, group), upserted in place; integrity is enforced by
// the domain (baseline.NewBaselineFrom validates the accumulators on load) and the usecase. Every method
// runs under the authenticated ctx tenant via WithContextTenant (RLS) with an explicit tenant_id predicate
// as defense-in-depth. Reached only through ports.BaselineStore.
type BaselineRepository struct {
	pool *pgxpool.Pool
}

var _ ports.BaselineStore = (*BaselineRepository)(nil)

// NewBaselineRepository constructs the baseline store over a pgx pool.
func NewBaselineRepository(pool *pgxpool.Pool) *BaselineRepository {
	return &BaselineRepository{pool: pool}
}

func requireBaselineRepoTenant(ctx context.Context) (shared.ID, error) {
	if t, ok := shared.TenantFrom(ctx); ok && t != "" {
		return t, nil
	}
	return "", fmt.Errorf("%w: baseline store operation requires a tenant in context", shared.ErrValidation)
}

// Save upserts a baseline record for its (tenant, group) key.
func (r *BaselineRepository) Save(ctx context.Context, rec ports.BaselineRecord) error {
	tenant, err := requireBaselineRepoTenant(ctx)
	if err != nil {
		return err
	}
	if err := rec.Key.Validate(); err != nil {
		return err
	}
	if rec.Key.Tenant != tenant {
		return fmt.Errorf("%w: baseline key tenant %q does not match context tenant %q", shared.ErrValidation, rec.Key.Tenant, tenant)
	}
	if !rec.State.Valid() {
		return fmt.Errorf("%w: unknown baseline state %q", shared.ErrValidation, rec.State)
	}
	// Rehydrate to validate accumulator integrity before persisting (same gate as the memory twin + load).
	if _, err := baseline.NewBaselineFrom(rec.Key, rec.State, rec.Summaries); err != nil {
		return err
	}
	if rec.DriftRun < 0 {
		return fmt.Errorf("%w: drift run must be non-negative", shared.ErrValidation)
	}
	summaries, err := json.Marshal(rec.Summaries)
	if err != nil {
		return fmt.Errorf("marshal baseline summaries: %w", err)
	}
	return WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO baselines
			(tenant_id, group_id, state, summaries, drift_run, drifted, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (tenant_id, group_id) DO UPDATE SET
				state = EXCLUDED.state,
				summaries = EXCLUDED.summaries,
				drift_run = EXCLUDED.drift_run,
				drifted = EXCLUDED.drifted,
				updated_at = EXCLUDED.updated_at`,
			tenant.String(), rec.Key.Group, string(rec.State), summaries, rec.DriftRun, rec.Drifted, rec.UpdatedAt.UTC())
		if err != nil {
			return fmt.Errorf("upsert baseline: %w", err)
		}
		return nil
	})
}

// Load returns the record for a key, or shared.ErrNotFound.
func (r *BaselineRepository) Load(ctx context.Context, key baseline.Key) (ports.BaselineRecord, error) {
	tenant, err := requireBaselineRepoTenant(ctx)
	if err != nil {
		return ports.BaselineRecord{}, err
	}
	if err := key.Validate(); err != nil {
		return ports.BaselineRecord{}, err
	}
	if key.Tenant != tenant {
		return ports.BaselineRecord{}, fmt.Errorf("%w: baseline key tenant %q does not match context tenant %q", shared.ErrValidation, key.Tenant, tenant)
	}
	var rec ports.BaselineRecord
	err = WithContextTenant(ctx, r.pool, func(tx pgx.Tx) error {
		var state string
		var summaries []byte
		var driftRun int
		var drifted bool
		row := tx.QueryRow(ctx, `SELECT state, summaries, drift_run, drifted, updated_at
			FROM baselines WHERE tenant_id=$1 AND group_id=$2`, tenant.String(), key.Group)
		if err := row.Scan(&state, &summaries, &driftRun, &drifted, &rec.UpdatedAt); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("%w: baseline %s/%s", shared.ErrNotFound, key.Tenant, key.Group)
			}
			return fmt.Errorf("load baseline: %w", err)
		}
		var sums []baseline.FeatureSummary
		if err := json.Unmarshal(summaries, &sums); err != nil {
			return fmt.Errorf("unmarshal baseline summaries: %w", err)
		}
		// Re-validate the stored row on read (defense-in-depth): a tampered/corrupt DB row must fail closed
		// here rather than reach the scorer, mirroring the Save-side gate.
		if _, err := baseline.NewBaselineFrom(key, baseline.State(state), sums); err != nil {
			return err
		}
		rec.Key = key
		rec.State = baseline.State(state)
		rec.Summaries = sums
		rec.DriftRun = driftRun
		rec.Drifted = drifted
		return nil
	})
	if err != nil {
		return ports.BaselineRecord{}, err
	}
	return rec, nil
}
