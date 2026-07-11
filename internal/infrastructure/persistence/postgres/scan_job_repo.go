package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ScanJobStore persists asynchronous scan-job status.
type ScanJobStore struct{ pool *pgxpool.Pool }

// NewScanJobStore returns a store backed by the given pool.
func NewScanJobStore(pool *pgxpool.Pool) *ScanJobStore { return &ScanJobStore{pool: pool} }

var _ ports.ScanJobStore = (*ScanJobStore)(nil)

// Save upserts a scan job (used on create and on every stage/status update).
func (r *ScanJobStore) Save(ctx context.Context, j ports.ScanJob) error {
	debugEvents, err := json.Marshal(j.DebugEvents)
	if err != nil {
		return fmt.Errorf("marshal scan job debug events: %w", err)
	}
	_, err = r.pool.Exec(ctx,
		`INSERT INTO scan_jobs (id, engagement_id, target, kind, status, stage, progress, error, started_at, finished_at, debug_events)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		 ON CONFLICT (id) DO UPDATE SET status=EXCLUDED.status, stage=EXCLUDED.stage,
		     progress=EXCLUDED.progress, error=EXCLUDED.error, finished_at=EXCLUDED.finished_at,
		     debug_events=EXCLUDED.debug_events`,
		j.ID, j.EngagementID, j.Target, j.Kind, string(j.Status), j.Stage, j.Progress, j.Error, j.StartedAt, j.FinishedAt, debugEvents)
	if err != nil {
		return fmt.Errorf("save scan job: %w", err)
	}
	return nil
}

// ListStaleRunning returns scan jobs still 'running' that started before olderThan (≤ limit),
// oldest first – the stale-scan sweeper's input.
func (r *ScanJobStore) ListStaleRunning(ctx context.Context, olderThan time.Time, limit int) ([]ports.ScanJob, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.pool.Query(ctx,
		`SELECT id, engagement_id, target, kind, status, stage, progress, COALESCE(error,''), started_at, finished_at, debug_events
		 FROM scan_jobs WHERE status='running' AND started_at < $1 ORDER BY started_at LIMIT $2`,
		olderThan, limit)
	if err != nil {
		return nil, fmt.Errorf("list stale scan jobs: %w", err)
	}
	defer rows.Close()
	out := []ports.ScanJob{}
	for rows.Next() {
		var (
			j        ports.ScanJob
			status   string
			finished *time.Time
		)
		var debugEvents []byte
		if err := rows.Scan(&j.ID, &j.EngagementID, &j.Target, &j.Kind, &status, &j.Stage, &j.Progress, &j.Error, &j.StartedAt, &finished, &debugEvents); err != nil {
			return nil, fmt.Errorf("scan scan job: %w", err)
		}
		j.Status = ports.ScanStatus(status)
		j.FinishedAt = finished
		if err := decodeScanDebugEvents(debugEvents, &j); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// GetJob returns a scan job by its own id, or ErrNotFound.
func (r *ScanJobStore) GetJob(ctx context.Context, id string) (ports.ScanJob, error) {
	var (
		j           ports.ScanJob
		status      string
		finished    *time.Time
		debugEvents []byte
	)
	err := r.pool.QueryRow(ctx,
		`SELECT id, engagement_id, target, kind, status, stage, progress, COALESCE(error,''), started_at, finished_at, debug_events
		 FROM scan_jobs WHERE id=$1`, id).
		Scan(&j.ID, &j.EngagementID, &j.Target, &j.Kind, &status, &j.Stage, &j.Progress, &j.Error, &j.StartedAt, &finished, &debugEvents)
	if errors.Is(err, pgx.ErrNoRows) {
		return ports.ScanJob{}, fmt.Errorf("scan job %s: %w", id, shared.ErrNotFound)
	}
	if err != nil {
		return ports.ScanJob{}, fmt.Errorf("load scan job: %w", err)
	}
	j.Status = ports.ScanStatus(status)
	j.FinishedAt = finished
	if err := decodeScanDebugEvents(debugEvents, &j); err != nil {
		return ports.ScanJob{}, err
	}
	return j, nil
}

// LatestForEngagement returns the engagement's most recent scan job, or ErrNotFound.
func (r *ScanJobStore) LatestForEngagement(ctx context.Context, engagementID shared.ID) (ports.ScanJob, error) {
	var (
		j           ports.ScanJob
		status      string
		finished    *time.Time
		debugEvents []byte
	)
	err := r.pool.QueryRow(ctx,
		`SELECT id, engagement_id, target, kind, status, stage, progress, COALESCE(error,''), started_at, finished_at, debug_events
		 FROM scan_jobs WHERE engagement_id=$1 ORDER BY started_at DESC LIMIT 1`, engagementID.String()).
		Scan(&j.ID, &j.EngagementID, &j.Target, &j.Kind, &status, &j.Stage, &j.Progress, &j.Error, &j.StartedAt, &finished, &debugEvents)
	if errors.Is(err, pgx.ErrNoRows) {
		return ports.ScanJob{}, fmt.Errorf("scan job for %s: %w", engagementID, shared.ErrNotFound)
	}
	if err != nil {
		return ports.ScanJob{}, fmt.Errorf("load scan job: %w", err)
	}
	j.Status = ports.ScanStatus(status)
	j.FinishedAt = finished
	if err := decodeScanDebugEvents(debugEvents, &j); err != nil {
		return ports.ScanJob{}, err
	}
	return j, nil
}

func decodeScanDebugEvents(data []byte, j *ports.ScanJob) error {
	if len(data) == 0 {
		j.DebugEvents = []ports.ScanDebugEvent{}
		return nil
	}
	if err := json.Unmarshal(data, &j.DebugEvents); err != nil {
		return fmt.Errorf("decode scan job debug events: %w", err)
	}
	if j.DebugEvents == nil {
		j.DebugEvents = []ports.ScanDebugEvent{}
	}
	return nil
}
