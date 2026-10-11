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

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ScanJobStore persists asynchronous scan-job status.
type ScanJobStore struct{ pool *pgxpool.Pool }

const (
	scanPredecessorPageSize    = 128
	scanSnapshotSaveTimeout    = 30 * time.Second
	scanLegacyPredecessorQuery = `SELECT id,target,finished_at FROM scan_jobs
		WHERE engagement_id COLLATE "C"=$1 COLLATE "C" AND kind COLLATE "C"=$2 COLLATE "C"
			AND status='succeeded' AND id COLLATE "C"<>$3 COLLATE "C"
			AND (finished_at,id COLLATE "C") < ($4,$5 COLLATE "C")
			AND (NOT (notification_snapshot ? 'target_key')
				OR jsonb_typeof(notification_snapshot->'target_key')<>'string'
				OR notification_snapshot->>'target_key'='')
		ORDER BY finished_at DESC NULLS LAST,id COLLATE "C" DESC LIMIT $6`
)

// NewScanJobStore returns a store backed by the given pool.
func NewScanJobStore(pool *pgxpool.Pool) *ScanJobStore { return &ScanJobStore{pool: pool} }

var _ ports.ScanJobStore = (*ScanJobStore)(nil)

func (r *ScanJobStore) CreateRunning(ctx context.Context, j ports.ScanJob) error {
	outcomes, err := encodeScanJobEngineOutcomes(j)
	if err != nil {
		return err
	}
	sourcePackage, err := encodeScanJobSource(j)
	if err != nil {
		return err
	}
	debugEvents, err := json.Marshal(j.DebugEvents)
	if err != nil {
		return fmt.Errorf("marshal scan job debug events: %w", err)
	}
	// A notification snapshot is admission evidence for a successful terminal
	// transition only. Never let a caller seed it on a running job.
	snapshot := []byte("{}")
	_, err = r.execSourceJob(ctx, j, `INSERT INTO scan_jobs (id, engagement_id, target, kind, status, stage, progress, error, started_at, finished_at, debug_events, source_package, engine_outcomes, notification_snapshot)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		j.ID, j.EngagementID, j.Target, j.Kind, string(j.Status), j.Stage, j.Progress, j.Error, j.StartedAt, j.FinishedAt, debugEvents, sourcePackage, outcomes, snapshot)
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
	outcomes, err := encodeScanJobEngineOutcomes(j)
	if err != nil {
		return err
	}
	sourcePackage, err := encodeScanJobSource(j)
	if err != nil {
		return err
	}
	debugEvents, err := json.Marshal(j.DebugEvents)
	if err != nil {
		return fmt.Errorf("marshal scan job debug events: %w", err)
	}
	if j.Status == ports.ScanSucceeded && j.NotificationSnapshot.TargetKey != "" {
		return r.saveTerminalSnapshot(ctx, j, debugEvents, sourcePackage, outcomes)
	}
	// A failure may carry raw worker output, but it is not successful snapshot
	// evidence. Retain an already-frozen successful snapshot on later status
	// correction, while refusing to create one for a failed first write.
	snapshot := []byte("{}")
	_, err = r.execSourceJob(ctx, j,
		`INSERT INTO scan_jobs (id, engagement_id, target, kind, status, stage, progress, error, started_at, finished_at, debug_events, source_package, engine_outcomes, notification_snapshot)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		 ON CONFLICT (id) DO UPDATE SET status=EXCLUDED.status, stage=EXCLUDED.stage,
		     progress=EXCLUDED.progress, error=EXCLUDED.error,
		     finished_at=CASE WHEN scan_jobs.notification_snapshot <> '{}'::jsonb
			     THEN scan_jobs.finished_at ELSE EXCLUDED.finished_at END,
		     debug_events=EXCLUDED.debug_events, engine_outcomes=EXCLUDED.engine_outcomes,
		     notification_snapshot=CASE WHEN scan_jobs.notification_snapshot <> '{}'::jsonb
		         THEN scan_jobs.notification_snapshot ELSE EXCLUDED.notification_snapshot END`,
		j.ID, j.EngagementID, j.Target, j.Kind, string(j.Status), j.Stage, j.Progress, j.Error, j.StartedAt, j.FinishedAt, debugEvents, sourcePackage, outcomes, snapshot)
	if err != nil {
		return fmt.Errorf("save scan job: %w", err)
	}
	return nil
}

// saveTerminalSnapshot serializes completed jobs for one engagement/target so
// the prior successful snapshot and the terminal transition are one atomic
// decision. This avoids a delayed capture reading mutable findings or concurrent
// completions inventing a fixed/new delta from unrelated baselines.
func (r *ScanJobStore) saveTerminalSnapshot(ctx context.Context, j ports.ScanJob, debugEvents, sourcePackage, outcomes []byte) error {
	if j.FinishedAt == nil {
		return fmt.Errorf("%w: succeeded scan job must have finished_at", shared.ErrValidation)
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, scanSnapshotSaveTimeout)
		defer cancel()
	}
	tenant, hasTenant := shared.TenantFrom(ctx)
	if !hasTenant {
		return fmt.Errorf("%w: tenant context is required for scan notification snapshot", shared.ErrValidation)
	}
	if j.SourcePackage != nil && tenant != j.SourcePackage.TenantID {
		return fmt.Errorf("%w: scan source tenant context does not match", shared.ErrValidation)
	}
	save := func(tx pgx.Tx) error {
		var engagementExists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM engagements WHERE id=$1 AND tenant_id=$2
		)`, j.EngagementID, tenant).Scan(&engagementExists); err != nil {
			return err
		}
		if !engagementExists {
			return fmt.Errorf("scan engagement %s: %w", j.EngagementID, shared.ErrNotFound)
		}
		// Lock the row being saved before examining a predecessor. The stored
		// target/kind are authoritative for a job created by CreateRunning; a
		// completion update must not change the comparison identity it carries.
		var storedEngagement, storedTarget, storedKind string
		var storedSnapshot []byte
		var frozen bool
		err := tx.QueryRow(ctx, `SELECT engagement_id,target,kind,notification_snapshot,notification_snapshot <> '{}'::jsonb
			FROM scan_jobs WHERE id=$1 FOR UPDATE`, j.ID).Scan(&storedEngagement, &storedTarget, &storedKind, &storedSnapshot, &frozen)
		switch {
		case err == nil:
			if storedEngagement != j.EngagementID {
				return fmt.Errorf("%w: terminal scan job engagement does not match stored job", shared.ErrValidation)
			}
		case errors.Is(err, pgx.ErrNoRows):
			storedEngagement, storedTarget, storedKind = j.EngagementID, j.Target, j.Kind
		default:
			return err
		}
		// Completion metadata may be stale, but the created job owns the target
		// identity used for both predecessor lookup and persistence.
		j.Target, j.Kind = storedTarget, storedKind
		upsert := func(snapshot []byte) error {
			_, err = tx.Exec(ctx, `INSERT INTO scan_jobs (id, engagement_id, target, kind, status, stage, progress, error, started_at, finished_at, debug_events, source_package, engine_outcomes, notification_snapshot)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
				ON CONFLICT (id) DO UPDATE SET status=EXCLUDED.status, stage=EXCLUDED.stage,
				progress=EXCLUDED.progress, error=EXCLUDED.error,
				finished_at=CASE WHEN scan_jobs.notification_snapshot <> '{}'::jsonb
					THEN scan_jobs.finished_at ELSE EXCLUDED.finished_at END,
				debug_events=EXCLUDED.debug_events, engine_outcomes=EXCLUDED.engine_outcomes,
				notification_snapshot=CASE WHEN scan_jobs.notification_snapshot <> '{}'::jsonb
					THEN scan_jobs.notification_snapshot ELSE EXCLUDED.notification_snapshot END`,
				j.ID, j.EngagementID, j.Target, j.Kind, string(j.Status), j.Stage, j.Progress, j.Error, j.StartedAt, j.FinishedAt, debugEvents, sourcePackage, outcomes, snapshot)
			return err
		}
		if frozen {
			// A frozen successful snapshot is immutable evidence. Status corrections
			// may arrive with stale or oversized worker payloads; preserve the stored
			// bytes and finished time after the tenant and engagement binding check.
			return upsert(storedSnapshot)
		}
		expected := notification.NewScanSummary(notification.CanonicalScanTarget(storedTarget, storedKind), storedKind, false, nil)
		if j.NotificationSnapshot.TargetKey != expected.TargetKey || j.NotificationSnapshot.Kind != expected.Kind {
			return fmt.Errorf("%w: scan notification snapshot target or kind does not match stored job", shared.ErrValidation)
		}
		lockKey := fmt.Sprintf("%d:%s%d:%s%d:%s",
			len(j.EngagementID), j.EngagementID,
			len(j.NotificationSnapshot.Kind), j.NotificationSnapshot.Kind,
			len(j.NotificationSnapshot.TargetKey), j.NotificationSnapshot.TargetKey)
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey); err != nil {
			return err
		}
		baseline, baselineID, found, err := findScanNotificationPredecessor(ctx, tx, j)
		if err != nil {
			return err
		}
		if found {
			j.NotificationSnapshot = j.NotificationSnapshot.WithBaselineID(baseline, baselineID)
		}
		snapshot, err := encodeScanJobNotificationSnapshot(j)
		if err != nil {
			return err
		}
		return upsert(snapshot)
	}
	if err := WithTenant(ctx, r.pool, tenant.String(), save); err != nil {
		return fmt.Errorf("save terminal scan job: %w", err)
	}
	return nil
}

type scanPredecessorPosition struct {
	finishedAt time.Time
	id         string
}

// findScanNotificationPredecessor first obtains an indexed canonical snapshot.
// A fixed-size MD5 value narrows the index walk, but equality on target_key is
// retained as the identity check. Legacy and malformed rows are then read in
// keyset pages. The scan stops only when a matching legacy baseline is found or
// every legacy row newer than the modern candidate has been examined.
func findScanNotificationPredecessor(ctx context.Context, tx pgx.Tx, current ports.ScanJob) (notification.ScanSummary, string, bool, error) {
	currentPosition := scanPredecessorPosition{finishedAt: *current.FinishedAt, id: current.ID}
	var modernRaw []byte
	var modern notification.ScanSummary
	var modernID string
	var modernFinished time.Time
	err := tx.QueryRow(ctx, `SELECT id,notification_snapshot,finished_at FROM scan_jobs
		WHERE engagement_id COLLATE "C"=$1 COLLATE "C" AND kind COLLATE "C"=$2 COLLATE "C"
			AND status='succeeded' AND id COLLATE "C"<>$3 COLLATE "C"
			AND (finished_at,id COLLATE "C") < ($4,$5 COLLATE "C")
			AND notification_snapshot ? 'target_key'
			AND jsonb_typeof(notification_snapshot->'target_key')='string'
			AND notification_snapshot->>'target_key'<>''
			AND md5(notification_snapshot->>'target_key')=md5($6)
			AND notification_snapshot->>'target_key' COLLATE "C"=$6 COLLATE "C"
		ORDER BY finished_at DESC NULLS LAST,id COLLATE "C" DESC LIMIT 1`,
		current.EngagementID, current.Kind, current.ID, currentPosition.finishedAt, currentPosition.id, current.NotificationSnapshot.TargetKey).Scan(&modernID, &modernRaw, &modernFinished)
	modernFound := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return notification.ScanSummary{}, "", false, fmt.Errorf("read modern scan notification predecessor: %w", err)
	}
	if modernFound {
		var job ports.ScanJob
		if err := decodeScanJobNotificationSnapshot(modernRaw, &job); err != nil {
			// The closest matching predecessor is unusable. Preserve the current
			// successful scan with an explicitly unavailable delta instead of
			// searching past stored evidence for an older baseline.
			return notification.ScanSummary{}, "", false, nil
		}
		modern = job.NotificationSnapshot
	}
	if modernFound && (modern.TargetKey != current.NotificationSnapshot.TargetKey || modern.Kind != current.NotificationSnapshot.Kind) {
		return notification.ScanSummary{}, "", false, nil
	}
	var cursor *scanPredecessorPosition
	for {
		rows, err := tx.Query(ctx, scanLegacyPredecessorQuery,
			current.EngagementID, current.Kind, current.ID, predecessorCursorTime(cursor, currentPosition), predecessorCursorID(cursor, currentPosition), scanPredecessorPageSize)
		if err != nil {
			return notification.ScanSummary{}, "", false, fmt.Errorf("read legacy scan notification predecessors: %w", err)
		}
		var pageLast scanPredecessorPosition
		count := 0
		for rows.Next() {
			var id, target string
			var finished time.Time
			if err := rows.Scan(&id, &target, &finished); err != nil {
				rows.Close()
				return notification.ScanSummary{}, "", false, fmt.Errorf("scan legacy scan notification predecessor: %w", err)
			}
			count++
			pageLast = scanPredecessorPosition{finishedAt: finished, id: id}
			if modernFound && predecessorAtOrBefore(pageLast, scanPredecessorPosition{finishedAt: modernFinished, id: modernID}) {
				rows.Close()
				return modern, modernID, true, nil
			}
			if notification.CanonicalScanTarget(target, current.Kind) != current.NotificationSnapshot.TargetKey {
				continue
			}
			// The metadata page stays small. Close it before reading the one
			// matching payload so pgx does not issue a second statement while the
			// cursor still owns the connection.
			rows.Close()
			var raw []byte
			if err := tx.QueryRow(ctx, `SELECT notification_snapshot FROM scan_jobs
				WHERE id=$1 AND engagement_id COLLATE "C"=$2 COLLATE "C"`, id, current.EngagementID).Scan(&raw); err != nil {
				return notification.ScanSummary{}, "", false, fmt.Errorf("read matching legacy scan notification predecessor: %w", err)
			}
			var legacy ports.ScanJob
			if err := decodeScanJobNotificationSnapshot(raw, &legacy); err != nil {
				// A matching malformed row is evidence that comparison is unknown;
				// it must not prevent the terminal scan status from persisting or
				// allow selection of an older baseline.
				return notification.ScanSummary{}, "", false, nil
			}
			// An empty or inconsistent legacy snapshot is an explicit unknown
			// baseline and may not be skipped for an older modern candidate.
			if legacy.NotificationSnapshot.TargetKey == "" {
				return notification.ScanSummary{}, "", false, nil
			}
			return notification.ScanSummary{}, "", false, nil
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return notification.ScanSummary{}, "", false, fmt.Errorf("iterate legacy scan notification predecessors: %w", err)
		}
		rows.Close()
		if count == 0 {
			break
		}
		if modernFound && predecessorAtOrBefore(pageLast, scanPredecessorPosition{finishedAt: modernFinished, id: modernID}) {
			break
		}
		cursor = &pageLast
	}
	if modernFound {
		return modern, modernID, true, nil
	}
	return notification.ScanSummary{}, "", false, nil
}

func predecessorCursorTime(cursor *scanPredecessorPosition, current scanPredecessorPosition) time.Time {
	if cursor == nil {
		return current.finishedAt
	}
	return cursor.finishedAt
}

func predecessorCursorID(cursor *scanPredecessorPosition, current scanPredecessorPosition) string {
	if cursor == nil {
		return current.id
	}
	return cursor.id
}

func predecessorAtOrBefore(left, right scanPredecessorPosition) bool {
	return left.finishedAt.Before(right.finishedAt) || (left.finishedAt.Equal(right.finishedAt) && left.id <= right.id)
}

// ListStaleRunning returns scan jobs still 'running' that started before olderThan (≤ limit),
// oldest first – the stale-scan sweeper's input.
func (r *ScanJobStore) ListStaleRunning(ctx context.Context, olderThan time.Time, limit int) ([]ports.ScanJob, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.pool.Query(ctx,
		`SELECT id, engagement_id, target, kind, status, stage, progress, COALESCE(error,''), started_at, finished_at, debug_events, source_package, engine_outcomes, notification_snapshot
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
		var debugEvents, sourcePackage, outcomes, snapshot []byte
		if err := rows.Scan(&j.ID, &j.EngagementID, &j.Target, &j.Kind, &status, &j.Stage, &j.Progress, &j.Error, &j.StartedAt, &finished, &debugEvents, &sourcePackage, &outcomes, &snapshot); err != nil {
			return nil, fmt.Errorf("scan scan job: %w", err)
		}
		j.Status = ports.ScanStatus(status)
		j.FinishedAt = finished
		if err := decodeScanJobEngineOutcomes(outcomes, &j); err != nil {
			return nil, err
		}
		if err := decodeScanDebugEvents(debugEvents, &j); err != nil {
			return nil, err
		}
		if err := decodeScanJobSource(sourcePackage, &j); err != nil {
			return nil, err
		}
		if err := decodeScanJobNotificationSnapshot(snapshot, &j); err != nil {
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
		outcomes      []byte
		snapshot      []byte
	)
	err := r.pool.QueryRow(ctx,
		`SELECT id, engagement_id, target, kind, status, stage, progress, COALESCE(error,''), started_at, finished_at, debug_events, source_package, engine_outcomes, notification_snapshot
		 FROM scan_jobs WHERE id=$1`, id).
		Scan(&j.ID, &j.EngagementID, &j.Target, &j.Kind, &status, &j.Stage, &j.Progress, &j.Error, &j.StartedAt, &finished, &debugEvents, &sourcePackage, &outcomes, &snapshot)
	if errors.Is(err, pgx.ErrNoRows) {
		return ports.ScanJob{}, fmt.Errorf("scan job %s: %w", id, shared.ErrNotFound)
	}
	if err != nil {
		return ports.ScanJob{}, fmt.Errorf("load scan job: %w", err)
	}
	j.Status = ports.ScanStatus(status)
	j.FinishedAt = finished
	if err := decodeScanJobEngineOutcomes(outcomes, &j); err != nil {
		return ports.ScanJob{}, err
	}
	if err := decodeScanDebugEvents(debugEvents, &j); err != nil {
		return ports.ScanJob{}, err
	}
	if err := decodeScanJobSource(sourcePackage, &j); err != nil {
		return ports.ScanJob{}, err
	}
	if err := decodeScanJobNotificationSnapshot(snapshot, &j); err != nil {
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
	rows, err := r.pool.Query(ctx, `SELECT j.id, j.engagement_id, j.target, j.kind, j.status, j.stage, j.progress, COALESCE(j.error,''), j.started_at, j.finished_at, j.source_package, j.engine_outcomes, j.notification_snapshot
		FROM unnest($1::text[]) AS e(engagement_id)
		JOIN LATERAL (
			SELECT id, engagement_id, target, kind, status, stage, progress, error, started_at, finished_at, source_package, engine_outcomes, notification_snapshot
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
		var sourcePackage, outcomes, snapshot []byte
		if err := rows.Scan(&j.ID, &j.EngagementID, &j.Target, &j.Kind, &status, &j.Stage, &j.Progress, &j.Error, &j.StartedAt, &finished, &sourcePackage, &outcomes, &snapshot); err != nil {
			return nil, fmt.Errorf("scan latest scan job: %w", err)
		}
		j.Status, j.FinishedAt, j.DebugEvents = ports.ScanStatus(status), finished, []ports.ScanDebugEvent{}
		if err := decodeScanJobEngineOutcomes(outcomes, &j); err != nil {
			return nil, err
		}
		if err := decodeScanJobSource(sourcePackage, &j); err != nil {
			return nil, err
		}
		if err := decodeScanJobNotificationSnapshot(snapshot, &j); err != nil {
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
		outcomes      []byte
		snapshot      []byte
	)
	err := r.pool.QueryRow(ctx,
		`SELECT id, engagement_id, target, kind, status, stage, progress, COALESCE(error,''), started_at, finished_at, debug_events, source_package, engine_outcomes, notification_snapshot
		 FROM scan_jobs WHERE engagement_id=$1 ORDER BY started_at DESC LIMIT 1`, engagementID.String()).
		Scan(&j.ID, &j.EngagementID, &j.Target, &j.Kind, &status, &j.Stage, &j.Progress, &j.Error, &j.StartedAt, &finished, &debugEvents, &sourcePackage, &outcomes, &snapshot)
	if errors.Is(err, pgx.ErrNoRows) {
		return ports.ScanJob{}, fmt.Errorf("scan job for %s: %w", engagementID, shared.ErrNotFound)
	}
	if err != nil {
		return ports.ScanJob{}, fmt.Errorf("load scan job: %w", err)
	}
	j.Status = ports.ScanStatus(status)
	j.FinishedAt = finished
	if err := decodeScanJobEngineOutcomes(outcomes, &j); err != nil {
		return ports.ScanJob{}, err
	}
	if err := decodeScanDebugEvents(debugEvents, &j); err != nil {
		return ports.ScanJob{}, err
	}
	if err := decodeScanJobSource(sourcePackage, &j); err != nil {
		return ports.ScanJob{}, err
	}
	if err := decodeScanJobNotificationSnapshot(snapshot, &j); err != nil {
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

func encodeScanJobEngineOutcomes(job ports.ScanJob) ([]byte, error) {
	outcomes, err := scanrun.CanonicalEngineOutcomes(job.EngineOutcomes)
	if err != nil {
		return nil, err
	}
	if len(outcomes) == 0 {
		return []byte("[]"), nil
	}
	return json.Marshal(outcomes)
}

func decodeScanJobEngineOutcomes(data []byte, job *ports.ScanJob) error {
	if len(data) > 0 {
		if err := json.Unmarshal(data, &job.EngineOutcomes); err != nil {
			return fmt.Errorf("decode job engine outcomes: %w", err)
		}
	}
	if _, err := scanrun.CanonicalEngineOutcomes(job.EngineOutcomes); err != nil {
		return err
	}
	job.EngineCoverage = scanrun.ComputeEngineCoverage(job.EngineOutcomes)
	return nil
}

func encodeScanJobNotificationSnapshot(job ports.ScanJob) ([]byte, error) {
	if job.NotificationSnapshot.TargetKey == "" {
		return []byte("{}"), nil
	}
	data, err := json.Marshal(job.NotificationSnapshot)
	if err != nil {
		return nil, fmt.Errorf("marshal scan notification snapshot: %w", err)
	}
	if len(data) > 4*1024*1024 {
		return nil, fmt.Errorf("%w: scan notification snapshot is too large", shared.ErrValidation)
	}
	return data, nil
}

func decodeScanJobNotificationSnapshot(data []byte, job *ports.ScanJob) error {
	if len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, &job.NotificationSnapshot); err != nil {
		return fmt.Errorf("decode scan notification snapshot: %w", err)
	}
	return nil
}
