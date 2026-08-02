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
	debugEvents, err := json.Marshal(j.DebugEvents)
	if err != nil {
		return fmt.Errorf("marshal scan job debug events: %w", err)
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return fmt.Errorf("create scan job: %w", shared.ErrValidation)
	}
	return WithTenantTx(ctx, r.pool, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO scan_jobs (id, tenant_id, engagement_id, target, kind, status, stage, progress, error, started_at, finished_at, debug_events)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
			j.ID, tenantID.String(), j.EngagementID, j.Target, j.Kind, string(j.Status), j.Stage, j.Progress, j.Error, j.StartedAt, j.FinishedAt, debugEvents)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return shared.ErrConflict
			}
			return fmt.Errorf("create scan job: %w", err)
		}
		return nil
	})
}

// Save upserts a scan job (used on create and on every stage/status update).
func (r *ScanJobStore) Save(ctx context.Context, j ports.ScanJob) error {
	debugEvents, err := json.Marshal(j.DebugEvents)
	if err != nil {
		return fmt.Errorf("marshal scan job debug events: %w", err)
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return fmt.Errorf("save scan job: %w", shared.ErrValidation)
	}
	return WithTenantTx(ctx, r.pool, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO scan_jobs (id, tenant_id, engagement_id, target, kind, status, stage, progress, error, started_at, finished_at, debug_events)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
			 ON CONFLICT (id) DO UPDATE SET status=EXCLUDED.status, stage=EXCLUDED.stage,
			     progress=EXCLUDED.progress, error=EXCLUDED.error, finished_at=EXCLUDED.finished_at,
			     debug_events=EXCLUDED.debug_events`,
			j.ID, tenantID.String(), j.EngagementID, j.Target, j.Kind, string(j.Status), j.Stage, j.Progress, j.Error, j.StartedAt, j.FinishedAt, debugEvents)
		if err != nil {
			return fmt.Errorf("save scan job: %w", err)
		}
		return nil
	})
}

// ListStaleRunning enumerates tenant identities before reading tenant-owned jobs.
func (r *ScanJobStore) ListStaleRunning(ctx context.Context, olderThan time.Time, limit int) ([]ports.ScanJob, error) {
	if limit <= 0 {
		limit = 100
	}
	tenantRows, err := r.pool.Query(ctx, `SELECT id FROM tenants ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list scan job tenants: %w", err)
	}
	tenantIDs := []shared.ID{}
	for tenantRows.Next() {
		var tenant string
		if err := tenantRows.Scan(&tenant); err != nil {
			tenantRows.Close()
			return nil, fmt.Errorf("scan scan job tenant: %w", err)
		}
		tenantIDs = append(tenantIDs, shared.ID(tenant))
	}
	if err := tenantRows.Err(); err != nil {
		tenantRows.Close()
		return nil, fmt.Errorf("list scan job tenants: %w", err)
	}
	tenantRows.Close()
	out := []ports.ScanJob{}
	for _, tenantID := range tenantIDs {
		if len(out) == limit {
			break
		}
		if err := WithTenantTx(ctx, r.pool, tenantID, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx,
				`SELECT id, tenant_id, engagement_id, target, kind, status, stage, progress, COALESCE(error,''), started_at, finished_at, debug_events
				 FROM scan_jobs WHERE status='running' AND started_at < $1 ORDER BY started_at LIMIT $2`,
				olderThan, limit-len(out))
			if err != nil {
				return fmt.Errorf("list stale scan jobs: %w", err)
			}
			defer rows.Close()
			for rows.Next() {
				var j ports.ScanJob
				var tenant, status string
				var finished *time.Time
				var debugEvents []byte
				if err := rows.Scan(&j.ID, &tenant, &j.EngagementID, &j.Target, &j.Kind, &status, &j.Stage, &j.Progress, &j.Error, &j.StartedAt, &finished, &debugEvents); err != nil {
					return fmt.Errorf("scan scan job: %w", err)
				}
				j.TenantID, j.Status, j.FinishedAt = shared.ID(tenant), ports.ScanStatus(status), finished
				if err := decodeScanDebugEvents(debugEvents, &j); err != nil {
					return err
				}
				out = append(out, j)
			}
			return rows.Err()
		}); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// GetJob returns a scan job by its own id, or ErrNotFound.
func (r *ScanJobStore) GetJob(ctx context.Context, id string) (ports.ScanJob, error) {
	var j ports.ScanJob
	err := WithContextTenantTx(ctx, r.pool, func(tx pgx.Tx) error {
		var tenant, status string
		var finished *time.Time
		var debugEvents []byte
		err := tx.QueryRow(ctx,
			`SELECT id, tenant_id, engagement_id, target, kind, status, stage, progress, COALESCE(error,''), started_at, finished_at, debug_events
			 FROM scan_jobs WHERE id=$1`, id).
			Scan(&j.ID, &tenant, &j.EngagementID, &j.Target, &j.Kind, &status, &j.Stage, &j.Progress, &j.Error, &j.StartedAt, &finished, &debugEvents)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("scan job %s: %w", id, shared.ErrNotFound)
		}
		if err != nil {
			return fmt.Errorf("load scan job: %w", err)
		}
		j.TenantID, j.Status, j.FinishedAt = shared.ID(tenant), ports.ScanStatus(status), finished
		return decodeScanDebugEvents(debugEvents, &j)
	})
	if err != nil {
		return ports.ScanJob{}, err
	}
	return j, nil
}
func (r *ScanJobStore) LatestForEngagements(ctx context.Context, engagementIDs []shared.ID) (map[shared.ID]ports.ScanJob, error) {
	ids := make([]string, len(engagementIDs))
	for i, id := range engagementIDs {
		ids[i] = id.String()
	}
	if len(ids) == 0 {
		return map[shared.ID]ports.ScanJob{}, nil
	}
	out := map[shared.ID]ports.ScanJob{}
	err := WithContextTenantTx(ctx, r.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT DISTINCT ON (engagement_id) id, tenant_id, engagement_id, target, kind, status, stage, progress, COALESCE(error,''), started_at, finished_at FROM scan_jobs WHERE engagement_id = ANY($1) ORDER BY engagement_id, started_at DESC, id DESC`, ids)
		if err != nil {
			return fmt.Errorf("list latest scan jobs: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var j ports.ScanJob
			var tenant, status string
			var finished *time.Time
			if err := rows.Scan(&j.ID, &tenant, &j.EngagementID, &j.Target, &j.Kind, &status, &j.Stage, &j.Progress, &j.Error, &j.StartedAt, &finished); err != nil {
				return fmt.Errorf("scan latest scan job: %w", err)
			}
			j.TenantID, j.Status, j.FinishedAt, j.DebugEvents = shared.ID(tenant), ports.ScanStatus(status), finished, []ports.ScanDebugEvent{}
			out[shared.ID(j.EngagementID)] = j
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (r *ScanJobStore) LatestForEngagement(ctx context.Context, engagementID shared.ID) (ports.ScanJob, error) {
	var j ports.ScanJob
	err := WithContextTenantTx(ctx, r.pool, func(tx pgx.Tx) error {
		var tenant, status string
		var finished *time.Time
		var debugEvents []byte
		err := tx.QueryRow(ctx,
			`SELECT id, tenant_id, engagement_id, target, kind, status, stage, progress, COALESCE(error,''), started_at, finished_at, debug_events
			 FROM scan_jobs WHERE engagement_id=$1 ORDER BY started_at DESC LIMIT 1`, engagementID.String()).
			Scan(&j.ID, &tenant, &j.EngagementID, &j.Target, &j.Kind, &status, &j.Stage, &j.Progress, &j.Error, &j.StartedAt, &finished, &debugEvents)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("scan job for %s: %w", engagementID, shared.ErrNotFound)
		}
		if err != nil {
			return fmt.Errorf("load scan job: %w", err)
		}
		j.TenantID, j.Status, j.FinishedAt = shared.ID(tenant), ports.ScanStatus(status), finished
		return decodeScanDebugEvents(debugEvents, &j)
	})
	if err != nil {
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
