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

const reconRunCols = `id, engagement_id, tool, target, status, stage, error, result_count, evidence_id, started_at, finished_at, containment`

// ReconRunStore persists recon-run records.
type ReconRunStore struct{ pool *pgxpool.Pool }

// NewReconRunStore returns a store backed by the given pool.
func NewReconRunStore(pool *pgxpool.Pool) *ReconRunStore { return &ReconRunStore{pool: pool} }

var _ ports.ReconRunStore = (*ReconRunStore)(nil)

// Save upserts a run (used on create and on every stage/status update).
func (r *ReconRunStore) Save(ctx context.Context, run recon.Run) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO recon_runs (`+reconRunCols+`)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		 ON CONFLICT (id) DO UPDATE SET status=EXCLUDED.status, stage=EXCLUDED.stage,
		     error=EXCLUDED.error, result_count=EXCLUDED.result_count,
		     evidence_id=EXCLUDED.evidence_id, finished_at=EXCLUDED.finished_at,
		     containment=EXCLUDED.containment`,
		run.ID.String(), run.EngagementID.String(), run.Tool, run.Target, string(run.Status),
		run.Stage, run.Error, run.ResultCount, run.EvidenceID.String(), run.StartedAt, run.FinishedAt, run.Containment)
	if err != nil {
		return fmt.Errorf("save recon run: %w", err)
	}
	return nil
}

// Get returns a run by id, or shared.ErrNotFound.
func (r *ReconRunStore) Get(ctx context.Context, id shared.ID) (recon.Run, error) {
	run, err := scanReconRun(r.pool.QueryRow(ctx, `SELECT `+reconRunCols+` FROM recon_runs WHERE id=$1`, id.String()))
	if errors.Is(err, pgx.ErrNoRows) {
		return recon.Run{}, fmt.Errorf("recon run %s: %w", id, shared.ErrNotFound)
	}
	if err != nil {
		return recon.Run{}, fmt.Errorf("get recon run: %w", err)
	}
	return run, nil
}

// ListByEngagement returns an engagement's runs, newest first.
func (r *ReconRunStore) ListByEngagement(ctx context.Context, engagementID shared.ID) ([]recon.Run, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+reconRunCols+` FROM recon_runs WHERE engagement_id=$1 ORDER BY started_at DESC`, engagementID.String())
	if err != nil {
		return nil, fmt.Errorf("list recon runs: %w", err)
	}
	defer rows.Close()
	out := []recon.Run{}
	for rows.Next() {
		run, err := scanReconRun(rows)
		if err != nil {
			return nil, fmt.Errorf("scan recon run: %w", err)
		}
		out = append(out, run)
	}
	return out, rows.Err()
}

// ListStaleRunning returns runs still 'running' that started before olderThan (≤ limit),
// oldest first – the stale-run sweeper's input.
func (r *ReconRunStore) ListStaleRunning(ctx context.Context, olderThan time.Time, limit int) ([]recon.Run, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.pool.Query(ctx,
		`SELECT `+reconRunCols+` FROM recon_runs WHERE status='running' AND started_at < $1 ORDER BY started_at LIMIT $2`,
		olderThan, limit)
	if err != nil {
		return nil, fmt.Errorf("list stale recon runs: %w", err)
	}
	defer rows.Close()
	out := []recon.Run{}
	for rows.Next() {
		run, err := scanReconRun(rows)
		if err != nil {
			return nil, fmt.Errorf("scan recon run: %w", err)
		}
		out = append(out, run)
	}
	return out, rows.Err()
}

func scanReconRun(row rowScanner) (recon.Run, error) {
	var (
		run        recon.Run
		id, eng    string
		evID       string
		status     string
		finishedAt *time.Time
	)
	if err := row.Scan(&id, &eng, &run.Tool, &run.Target, &status, &run.Stage, &run.Error, &run.ResultCount, &evID, &run.StartedAt, &finishedAt, &run.Containment); err != nil {
		return recon.Run{}, err
	}
	run.ID = shared.ID(id)
	run.EngagementID = shared.ID(eng)
	run.EvidenceID = shared.ID(evID)
	run.Status = recon.Status(status)
	run.FinishedAt = finishedAt
	return run, nil
}
