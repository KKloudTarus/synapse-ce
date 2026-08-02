package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ScanRunStore persists scan-run manifests + finding keys in tenant-bound transactions.
type ScanRunStore struct{ pool *pgxpool.Pool }

func NewScanRunStore(pool *pgxpool.Pool) *ScanRunStore { return &ScanRunStore{pool: pool} }

var _ ports.ScanRunStore = (*ScanRunStore)(nil)

func (r *ScanRunStore) Save(ctx context.Context, run ports.ScanRun) error {
	manifest, err := json.Marshal(run.Manifest)
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	keys, err := json.Marshal(run.FindingKeys)
	if err != nil {
		return fmt.Errorf("marshal finding keys: %w", err)
	}
	return WithContextTenantTx(ctx, r.pool, func(tx pgx.Tx) error {
		tenantID, _ := shared.TenantFrom(ctx)
		if _, err := tx.Exec(ctx, `INSERT INTO scan_runs (id, tenant_id, engagement_id, created_at, manifest, finding_keys) VALUES ($1,$2,$3,$4,$5,$6)`, run.ID, tenantID.String(), run.EngagementID, run.CreatedAt, manifest, keys); err != nil {
			return fmt.Errorf("insert scan run: %w", err)
		}
		return nil
	})
}

func (r *ScanRunStore) List(ctx context.Context, engagementID shared.ID) ([]ports.ScanRun, error) {
	var out []ports.ScanRun
	err := WithContextTenantTx(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, tenant_id, engagement_id, created_at, manifest, finding_keys FROM scan_runs WHERE engagement_id=$1 ORDER BY created_at DESC`, engagementID.String())
		if err != nil {
			return fmt.Errorf("list scan runs: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			run, err := scanRunRow(rows)
			if err != nil {
				return err
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

func (r *ScanRunStore) Get(ctx context.Context, runID string) (ports.ScanRun, error) {
	var out ports.ScanRun
	err := WithContextTenantTx(ctx, r.pool, func(tx pgx.Tx) error {
		var err error
		out, err = scanRunRow(tx.QueryRow(ctx, `SELECT id, tenant_id, engagement_id, created_at, manifest, finding_keys FROM scan_runs WHERE id=$1`, runID))
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("scan run %s: %w", runID, shared.ErrNotFound)
		}
		return err
	})
	if err != nil {
		return ports.ScanRun{}, err
	}
	return out, nil
}

func scanRunRow(row rowScanner) (ports.ScanRun, error) {
	var run ports.ScanRun
	var tenant string
	var manifest, keys []byte
	if err := row.Scan(&run.ID, &tenant, &run.EngagementID, &run.CreatedAt, &manifest, &keys); err != nil {
		return ports.ScanRun{}, err
	}
	run.TenantID = shared.ID(tenant)
	if err := json.Unmarshal(manifest, &run.Manifest); err != nil {
		return ports.ScanRun{}, fmt.Errorf("decode manifest: %w", err)
	}
	if err := json.Unmarshal(keys, &run.FindingKeys); err != nil {
		return ports.ScanRun{}, fmt.Errorf("decode finding keys: %w", err)
	}
	return run, nil
}
