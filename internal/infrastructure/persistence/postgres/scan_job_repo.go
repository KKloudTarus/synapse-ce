package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ScanJobStore persists asynchronous scan-job status.
type ScanJobStore struct{ pool *pgxpool.Pool }

// NewScanJobStore returns a store backed by the given pool.
func NewScanJobStore(pool *pgxpool.Pool) *ScanJobStore { return &ScanJobStore{pool: pool} }

var _ ports.ScanJobStore = (*ScanJobStore)(nil)

func (r *ScanJobStore) CreateRunning(ctx context.Context, j ports.ScanJob) error {
	sourcePackage, err := encodeScanJobSource(j)
	if err != nil {
		return err
	}
	debugEvents, err := json.Marshal(j.DebugEvents)
	if err != nil {
		return fmt.Errorf("marshal scan job debug events: %w", err)
	}
	_, err = r.execSourceJob(ctx, j, `INSERT INTO scan_jobs (id, engagement_id, target, kind, status, stage, progress, error, started_at, finished_at, debug_events, source_package)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		j.ID, j.EngagementID, j.Target, j.Kind, string(j.Status), j.Stage, j.Progress, j.Error, j.StartedAt, j.FinishedAt, debugEvents, sourcePackage)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return shared.ErrConflict
		}
		return fmt.Errorf("create scan job: %w", err)
	}
	return nil
}

// Save upserts a scan job (used on create and on every stage/status update).
func (r *ScanJobStore) Save(ctx context.Context, j ports.ScanJob) error {
	sourcePackage, err := encodeScanJobSource(j)
	if err != nil {
		return err
	}
	debugEvents, err := json.Marshal(j.DebugEvents)
	if err != nil {
		return fmt.Errorf("marshal scan job debug events: %w", err)
	}
	_, err = r.execSourceJob(ctx, j,
		`INSERT INTO scan_jobs (id, engagement_id, target, kind, status, stage, progress, error, started_at, finished_at, debug_events, source_package)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		 ON CONFLICT (id) DO UPDATE SET status=EXCLUDED.status, stage=EXCLUDED.stage,
		     progress=EXCLUDED.progress, error=EXCLUDED.error, finished_at=EXCLUDED.finished_at,
		     debug_events=EXCLUDED.debug_events`,
		j.ID, j.EngagementID, j.Target, j.Kind, string(j.Status), j.Stage, j.Progress, j.Error, j.StartedAt, j.FinishedAt, debugEvents, sourcePackage)
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
		`SELECT id, engagement_id, target, kind, status, stage, progress, COALESCE(error,''), started_at, finished_at, debug_events, source_package
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
		var debugEvents, sourcePackage []byte
		if err := rows.Scan(&j.ID, &j.EngagementID, &j.Target, &j.Kind, &status, &j.Stage, &j.Progress, &j.Error, &j.StartedAt, &finished, &debugEvents, &sourcePackage); err != nil {
			return nil, fmt.Errorf("scan scan job: %w", err)
		}
		j.Status = ports.ScanStatus(status)
		j.FinishedAt = finished
		if err := decodeScanDebugEvents(debugEvents, &j); err != nil {
			return nil, err
		}
		if err := decodeScanJobSource(sourcePackage, &j); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// GetJob returns a scan job by its own id, or ErrNotFound.
func (r *ScanJobStore) GetJob(ctx context.Context, id string) (ports.ScanJob, error) {
	var (
		j             ports.ScanJob
		status        string
		finished      *time.Time
		debugEvents   []byte
		sourcePackage []byte
	)
	err := r.pool.QueryRow(ctx,
		`SELECT id, engagement_id, target, kind, status, stage, progress, COALESCE(error,''), started_at, finished_at, debug_events, source_package
		 FROM scan_jobs WHERE id=$1`, id).
		Scan(&j.ID, &j.EngagementID, &j.Target, &j.Kind, &status, &j.Stage, &j.Progress, &j.Error, &j.StartedAt, &finished, &debugEvents, &sourcePackage)
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
	if err := decodeScanJobSource(sourcePackage, &j); err != nil {
		return ports.ScanJob{}, err
	}
	return j, nil
}

// LatestForEngagement returns the engagement's most recent scan job, or ErrNotFound.
func (r *ScanJobStore) LatestForEngagements(ctx context.Context, engagementIDs []shared.ID) (map[shared.ID]ports.ScanJob, error) {
	ids := make([]string, len(engagementIDs))
	for i, id := range engagementIDs {
		ids[i] = id.String()
	}
	if len(ids) == 0 {
		return map[shared.ID]ports.ScanJob{}, nil
	}
	// A LATERAL top-1 per engagement walks idx_scan_jobs_engagement once per id; DISTINCT ON over every
	// job of every engagement sorted the whole set (an on-disk merge at tens of thousands of jobs).
	rows, err := r.pool.Query(ctx, `SELECT j.id, j.engagement_id, j.target, j.kind, j.status, j.stage, j.progress, COALESCE(j.error,''), j.started_at, j.finished_at, j.source_package
		FROM unnest($1::text[]) AS e(engagement_id)
		JOIN LATERAL (
			SELECT id, engagement_id, target, kind, status, stage, progress, error, started_at, finished_at, source_package
			FROM scan_jobs WHERE engagement_id = e.engagement_id
			ORDER BY started_at DESC, id DESC LIMIT 1
		) j ON true`, ids)
	if err != nil {
		return nil, fmt.Errorf("list latest scan jobs: %w", err)
	}
	defer rows.Close()
	out := map[shared.ID]ports.ScanJob{}
	for rows.Next() {
		var j ports.ScanJob
		var status string
		var finished *time.Time
		var sourcePackage []byte
		if err := rows.Scan(&j.ID, &j.EngagementID, &j.Target, &j.Kind, &status, &j.Stage, &j.Progress, &j.Error, &j.StartedAt, &finished, &sourcePackage); err != nil {
			return nil, fmt.Errorf("scan latest scan job: %w", err)
		}
		j.Status, j.FinishedAt, j.DebugEvents = ports.ScanStatus(status), finished, []ports.ScanDebugEvent{}
		if err := decodeScanJobSource(sourcePackage, &j); err != nil {
			return nil, err
		}
		out[shared.ID(j.EngagementID)] = j
	}
	return out, rows.Err()
}

func (r *ScanJobStore) LatestForEngagement(ctx context.Context, engagementID shared.ID) (ports.ScanJob, error) {
	var (
		j             ports.ScanJob
		status        string
		finished      *time.Time
		debugEvents   []byte
		sourcePackage []byte
	)
	err := r.pool.QueryRow(ctx,
		`SELECT id, engagement_id, target, kind, status, stage, progress, COALESCE(error,''), started_at, finished_at, debug_events, source_package
		 FROM scan_jobs WHERE engagement_id=$1 ORDER BY started_at DESC LIMIT 1`, engagementID.String()).
		Scan(&j.ID, &j.EngagementID, &j.Target, &j.Kind, &status, &j.Stage, &j.Progress, &j.Error, &j.StartedAt, &finished, &debugEvents, &sourcePackage)
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
	if err := decodeScanJobSource(sourcePackage, &j); err != nil {
		return ports.ScanJob{}, err
	}
	return j, nil
}

func encodeScanJobSource(job ports.ScanJob) ([]byte, error) {
	if job.SourcePackage == nil {
		return nil, nil
	}
	if err := job.SourcePackage.Validate(); err != nil {
		return nil, err
	}
	if job.Kind != ports.TargetUpload || job.SourcePackage.EngagementID.String() != job.EngagementID || job.SourcePackage.Target() != job.Target {
		return nil, fmt.Errorf("%w: scan source binding does not match the job", shared.ErrValidation)
	}
	return json.Marshal(job.SourcePackage)
}

func decodeScanJobSource(data []byte, job *ports.ScanJob) error {
	if len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, &job.SourcePackage); err != nil {
		return fmt.Errorf("decode scan source metadata: %w", err)
	}
	_, err := encodeScanJobSource(*job)
	return err
}

func (r *ScanJobStore) execSourceJob(ctx context.Context, job ports.ScanJob, query string, args ...any) (pgconn.CommandTag, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if job.SourcePackage == nil && (!ok || tenantID.IsZero()) {
		return r.pool.Exec(ctx, query, args...)
	}
	if job.SourcePackage != nil && (!ok || tenantID != job.SourcePackage.TenantID) {
		return pgconn.CommandTag{}, fmt.Errorf("%w: scan source tenant context does not match", shared.ErrValidation)
	}
	var result pgconn.CommandTag
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		var err error
		result, err = tx.Exec(ctx, query, args...)
		return err
	})
	return result, err
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
