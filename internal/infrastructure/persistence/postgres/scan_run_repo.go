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

// ScanRunStore persists scan-run manifests + finding keys.
type ScanRunStore struct{ pool *pgxpool.Pool }

// NewScanRunStore returns a store backed by the given pool.
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
	if _, err := r.pool.Exec(ctx,
		`INSERT INTO scan_runs (id, engagement_id, created_at, manifest, finding_keys) VALUES ($1,$2,$3,$4,$5)`,
		run.ID, run.EngagementID, run.CreatedAt, manifest, keys); err != nil {
		return fmt.Errorf("insert scan run: %w", err)
	}
	return nil
}

func (r *ScanRunStore) List(ctx context.Context, engagementID shared.ID) ([]ports.ScanRun, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, engagement_id, created_at, manifest, finding_keys
		 FROM scan_runs WHERE engagement_id=$1 ORDER BY created_at DESC`, engagementID.String())
	if err != nil {
		return nil, fmt.Errorf("list scan runs: %w", err)
	}
	defer rows.Close()
	var out []ports.ScanRun
	for rows.Next() {
		run, err := scanRunRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, run)
	}
	return out, rows.Err()
}

func (r *ScanRunStore) Get(ctx context.Context, runID string) (ports.ScanRun, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT id, engagement_id, created_at, manifest, finding_keys FROM scan_runs WHERE id=$1`, runID)
	run, err := scanRunRow(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return ports.ScanRun{}, fmt.Errorf("scan run %s: %w", runID, shared.ErrNotFound)
	}
	if err != nil {
		return ports.ScanRun{}, fmt.Errorf("get scan run: %w", err)
	}
	return run, nil
}

func scanRunRow(row rowScanner) (ports.ScanRun, error) {
	var (
		run            ports.ScanRun
		manifest, keys []byte
	)
	if err := row.Scan(&run.ID, &run.EngagementID, &run.CreatedAt, &manifest, &keys); err != nil {
		return ports.ScanRun{}, err
	}
	if err := json.Unmarshal(manifest, &run.Manifest); err != nil {
		return ports.ScanRun{}, fmt.Errorf("decode manifest: %w", err)
	}
	if err := json.Unmarshal(keys, &run.FindingKeys); err != nil {
		return ports.ScanRun{}, fmt.Errorf("decode finding keys: %w", err)
	}
	return run, nil
}
