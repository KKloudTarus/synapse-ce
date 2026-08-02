package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/recon"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const reconRunCols = `id, tenant_id, engagement_id, tool, target, status, stage, error, result_count, evidence_id, started_at, finished_at, containment`

type ReconRunStore struct{ pool *pgxpool.Pool }

func NewReconRunStore(pool *pgxpool.Pool) *ReconRunStore { return &ReconRunStore{pool: pool} }

var _ ports.ReconRunStore = (*ReconRunStore)(nil)

func (r *ReconRunStore) Save(ctx context.Context, run recon.Run) error {
	return WithContextTenantTx(ctx, r.pool, func(tx pgx.Tx) error {
		tenantID, _ := shared.TenantFrom(ctx)
		_, err := tx.Exec(ctx, `INSERT INTO recon_runs (`+reconRunCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT (id) DO UPDATE SET status=EXCLUDED.status, stage=EXCLUDED.stage, error=EXCLUDED.error, result_count=EXCLUDED.result_count, evidence_id=EXCLUDED.evidence_id, finished_at=EXCLUDED.finished_at, containment=EXCLUDED.containment`, run.ID.String(), tenantID.String(), run.EngagementID.String(), run.Tool, run.Target, string(run.Status), run.Stage, run.Error, run.ResultCount, run.EvidenceID.String(), run.StartedAt, run.FinishedAt, run.Containment)
		if err != nil {
			return fmt.Errorf("save recon run: %w", err)
		}
		return nil
	})
}

func (r *ReconRunStore) Get(ctx context.Context, id shared.ID) (recon.Run, error) {
	var out recon.Run
	err := WithContextTenantTx(ctx, r.pool, func(tx pgx.Tx) error {
		var err error
		out, err = scanReconRun(tx.QueryRow(ctx, `SELECT `+reconRunCols+` FROM recon_runs WHERE id=$1`, id.String()))
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("recon run %s: %w", id, shared.ErrNotFound)
		}
		if err != nil {
			return fmt.Errorf("get recon run: %w", err)
		}
		return nil
	})
	if err != nil {
		return recon.Run{}, err
	}
	return out, nil
}

func (r *ReconRunStore) ListByEngagement(ctx context.Context, engagementID shared.ID) ([]recon.Run, error) {
	var out []recon.Run
	err := WithContextTenantTx(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+reconRunCols+` FROM recon_runs WHERE engagement_id=$1 ORDER BY started_at DESC`, engagementID.String())
		if err != nil {
			return fmt.Errorf("list recon runs: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			run, err := scanReconRun(rows)
			if err != nil {
				return fmt.Errorf("scan recon run: %w", err)
			}
			out = append(out, run)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ListStaleRunning enumerates tenant identities from the registry, then queries
// each tenant's rows in an RLS-bound transaction.
func (r *ReconRunStore) ListStaleRunning(ctx context.Context, olderThan time.Time, limit int) ([]recon.Run, error) {
	if limit <= 0 {
		limit = 100
	}
	tenantRows, err := r.pool.Query(ctx, `SELECT id FROM tenants ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list recon tenants: %w", err)
	}
	tenantIDs := []shared.ID{}
	for tenantRows.Next() {
		var tenant string
		if err := tenantRows.Scan(&tenant); err != nil {
			tenantRows.Close()
			return nil, fmt.Errorf("scan recon tenant: %w", err)
		}
		tenantIDs = append(tenantIDs, shared.ID(tenant))
	}
	if err := tenantRows.Err(); err != nil {
		tenantRows.Close()
		return nil, fmt.Errorf("list recon tenants: %w", err)
	}
	tenantRows.Close()
	out := []recon.Run{}
	for _, tenantID := range tenantIDs {
		if len(out) == limit {
			break
		}
		if err := WithTenantTx(ctx, r.pool, tenantID, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT `+reconRunCols+` FROM recon_runs WHERE status='running' AND started_at < $1 ORDER BY started_at LIMIT $2`, olderThan, limit-len(out))
			if err != nil {
				return fmt.Errorf("list stale recon runs: %w", err)
			}
			defer rows.Close()
			for rows.Next() {
				run, err := scanReconRun(rows)
				if err != nil {
					return fmt.Errorf("scan recon run: %w", err)
				}
				out = append(out, run)
			}
			return rows.Err()
		}); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func scanReconRun(row rowScanner) (recon.Run, error) {
	var run recon.Run
	var id, tenant, eng, evID, status string
	var finishedAt *time.Time
	if err := row.Scan(&id, &tenant, &eng, &run.Tool, &run.Target, &status, &run.Stage, &run.Error, &run.ResultCount, &evID, &run.StartedAt, &finishedAt, &run.Containment); err != nil {
		return recon.Run{}, err
	}
	run.ID, run.TenantID, run.EngagementID, run.EvidenceID, run.Status, run.FinishedAt = shared.ID(id), shared.ID(tenant), shared.ID(eng), shared.ID(evID), recon.Status(status), finishedAt
	return run, nil
}
