package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerabilityintel"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerabilitysync"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const syncJobPayloadLimit = 1 << 20

type SyncRunStore struct {
	pool *pgxpool.Pool
	ids  ports.IDGenerator
}

func NewSyncRunStore(pool *pgxpool.Pool, ids ports.IDGenerator) *SyncRunStore {
	return &SyncRunStore{pool: pool, ids: ids}
}

var _ ports.SyncRunStore = (*SyncRunStore)(nil)
var _ ports.VulnerabilitySyncRunReadStore = (*SyncRunStore)(nil)

func (s *SyncRunStore) Start(ctx context.Context, request ports.SyncRunStart) (vulnerabilitysync.Run, bool, error) {
	if err := validateSyncStart(request); err != nil {
		return vulnerabilitysync.Run{}, false, err
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() {
		return vulnerabilitysync.Run{}, false, fmt.Errorf("%w: tenant context is required for sync job", shared.ErrValidation)
	}
	if s.ids == nil {
		return vulnerabilitysync.Run{}, false, fmt.Errorf("%w: sync run id generator is nil", shared.ErrValidation)
	}
	checkpoint, err := vulnerabilitysync.NormalizeCheckpoint(request.Checkpoint)
	if err != nil {
		return vulnerabilitysync.Run{}, false, err
	}
	snapshot, err := vulnerabilitysync.NormalizeSourceSnapshot(request.SourceSnapshot)
	if err != nil {
		return vulnerabilitysync.Run{}, false, err
	}
	var (
		result  vulnerabilitysync.Run
		created bool
	)
	err = WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "synapse:sync-source:"+request.SourceID.String()); err != nil {
			return fmt.Errorf("lock sync source: %w", err)
		}
		if existing, found, err := findExistingSyncRun(ctx, tx, request); err != nil {
			return err
		} else if found {
			result = existing
			return nil
		}
		now := time.Now().UTC()
		runID := s.ids.NewID()
		jobID := s.ids.NewID().String()
		if _, err := tx.Exec(ctx, `
			INSERT INTO jobs(id, tenant_id, kind, payload, status, available_at)
			VALUES($1,$2,$3,$4,'queued',now())`, jobID, tenantID.String(), request.JobKind, request.JobPayload); err != nil {
			return fmt.Errorf("insert sync job: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO vulnerability_sync_runs
			(id, source_id, adapter_type, source_snapshot, mode, trigger, actor, client_idempotency_key,
			 durable_job_id, checkpoint, state, created_at, updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,NULLIF($8,''),$9,$10,'queued',$11,$11)`,
			runID.String(), request.SourceID.String(), request.AdapterType, snapshot, string(request.Mode), request.Trigger,
			strings.TrimSpace(request.Actor), request.ClientIdempotencyKey, jobID, checkpoint, now); err != nil {
			return fmt.Errorf("insert sync run: %w", err)
		}
		result, err = scanSyncRun(tx.QueryRow(ctx, syncRunSelect+` WHERE id=$1`, runID.String()))
		if err != nil {
			return fmt.Errorf("load created sync run: %w", err)
		}
		created = true
		return nil
	})
	if err != nil {
		return vulnerabilitysync.Run{}, false, err
	}
	return result, created, nil
}

func (s *SyncRunStore) RecoverStale(ctx context.Context, staleRunID shared.ID, staleBefore time.Time, request ports.SyncRunStart) (vulnerabilitysync.Run, bool, error) {
	if staleRunID.IsZero() || staleBefore.IsZero() {
		return vulnerabilitysync.Run{}, false, fmt.Errorf("%w: stale recovery identity is required", shared.ErrValidation)
	}
	if err := validateSyncStart(request); err != nil {
		return vulnerabilitysync.Run{}, false, err
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() {
		return vulnerabilitysync.Run{}, false, fmt.Errorf("%w: tenant context is required for sync job", shared.ErrValidation)
	}
	if s.ids == nil {
		return vulnerabilitysync.Run{}, false, fmt.Errorf("%w: sync run id generator is nil", shared.ErrValidation)
	}
	checkpoint, err := vulnerabilitysync.NormalizeCheckpoint(request.Checkpoint)
	if err != nil {
		return vulnerabilitysync.Run{}, false, err
	}
	snapshot, err := vulnerabilitysync.NormalizeSourceSnapshot(request.SourceSnapshot)
	if err != nil {
		return vulnerabilitysync.Run{}, false, err
	}
	var result vulnerabilitysync.Run
	created := false
	err = WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "synapse:sync-source:"+request.SourceID.String()); err != nil {
			return fmt.Errorf("lock sync source recovery: %w", err)
		}
		if request.ClientIdempotencyKey != "" {
			existing, err := scanSyncRun(tx.QueryRow(ctx, syncRunSelect+` WHERE source_id=$1 AND client_idempotency_key=$2`, request.SourceID.String(), request.ClientIdempotencyKey))
			if err == nil {
				result = existing
				return nil
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		stale, err := scanSyncRun(tx.QueryRow(ctx, syncRunSelect+` WHERE id=$1 AND state IN ('queued','running') AND updated_at<$2 FOR UPDATE`, staleRunID.String(), staleBefore))
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrConflict
		}
		if err != nil {
			return fmt.Errorf("load stale sync run: %w", err)
		}
		if stale.SourceID != request.SourceID || stale.Mode != request.Mode {
			return fmt.Errorf("%w: stale recovery source or mode mismatch", shared.ErrValidation)
		}
		now := time.Now().UTC()
		if _, err := tx.Exec(ctx, `UPDATE vulnerability_sync_runs SET state='superseded',finished_at=$2,updated_at=$2 WHERE id=$1`, staleRunID.String(), now); err != nil {
			return fmt.Errorf("supersede stale sync run: %w", err)
		}
		runID, jobID := s.ids.NewID(), s.ids.NewID().String()
		if _, err := tx.Exec(ctx, `INSERT INTO jobs(id,tenant_id,kind,payload,status,available_at) VALUES($1,$2,$3,$4,'queued',$5)`, jobID, tenantID.String(), request.JobKind, request.JobPayload, now); err != nil {
			return fmt.Errorf("insert recovered sync job: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO vulnerability_sync_runs
			(id,source_id,adapter_type,source_snapshot,mode,trigger,actor,client_idempotency_key,durable_job_id,checkpoint,state,created_at,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,NULLIF($8,''),$9,$10,'queued',$11,$11)`,
			runID.String(), request.SourceID.String(), request.AdapterType, snapshot, string(request.Mode), request.Trigger,
			strings.TrimSpace(request.Actor), request.ClientIdempotencyKey, jobID, checkpoint, now); err != nil {
			return fmt.Errorf("insert recovered sync run: %w", err)
		}
		result, err = scanSyncRun(tx.QueryRow(ctx, syncRunSelect+` WHERE id=$1`, runID.String()))
		created = err == nil
		return err
	})
	if err != nil {
		return vulnerabilitysync.Run{}, false, err
	}
	return result, created, nil
}

func (s *SyncRunStore) Get(ctx context.Context, id shared.ID) (vulnerabilitysync.Run, error) {
	var result vulnerabilitysync.Run
	read := func(tx pgx.Tx) error {
		var err error
		query := syncRunSelect + ` WHERE id=$1`
		args := []any{id.String()}
		if tenantID, ok := shared.TenantFrom(ctx); ok && !tenantID.IsZero() {
			query += ` AND EXISTS (SELECT 1 FROM jobs j WHERE j.id=vulnerability_sync_runs.durable_job_id AND j.tenant_id=$2)`
			args = append(args, shared.TenantOrDefault(tenantID).String())
		}
		result, err = scanSyncRun(tx.QueryRow(ctx, query, args...))
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("sync run %s: %w", id, shared.ErrNotFound)
		}
		return err
	}
	var err error
	if tenantID, ok := shared.TenantFrom(ctx); ok && !tenantID.IsZero() {
		err = WithTenant(ctx, s.pool, tenantID.String(), read)
	} else {
		err = WithGlobalRead(ctx, s.pool, read)
	}
	if err != nil {
		return vulnerabilitysync.Run{}, err
	}
	return result, nil
}

func (s *SyncRunStore) GetByDurableJobID(ctx context.Context, jobID string) (vulnerabilitysync.Run, error) {
	jobID = strings.TrimSpace(jobID)
	if jobID == "" {
		return vulnerabilitysync.Run{}, fmt.Errorf("%w: durable job id is required", shared.ErrValidation)
	}
	var result vulnerabilitysync.Run
	read := func(tx pgx.Tx) error {
		var err error
		query := syncRunSelect + ` WHERE durable_job_id=$1`
		args := []any{jobID}
		if tenantID, ok := shared.TenantFrom(ctx); ok && !tenantID.IsZero() {
			query += ` AND EXISTS (SELECT 1 FROM jobs j WHERE j.id=vulnerability_sync_runs.durable_job_id AND j.tenant_id=$2)`
			args = append(args, shared.TenantOrDefault(tenantID).String())
		}
		result, err = scanSyncRun(tx.QueryRow(ctx, query, args...))
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("sync job %s: %w", jobID, shared.ErrNotFound)
		}
		return err
	}
	var err error
	if tenantID, ok := shared.TenantFrom(ctx); ok && !tenantID.IsZero() {
		err = WithTenant(ctx, s.pool, tenantID.String(), read)
	} else {
		err = WithGlobalRead(ctx, s.pool, read)
	}
	if err != nil {
		return vulnerabilitysync.Run{}, err
	}
	return result, nil
}

func (s *SyncRunStore) LatestForSource(ctx context.Context, sourceID shared.ID, states []vulnerabilitysync.State) (vulnerabilitysync.Run, error) {
	if sourceID.IsZero() {
		return vulnerabilitysync.Run{}, fmt.Errorf("%w: source id is required", shared.ErrValidation)
	}
	values := make([]string, len(states))
	for index, state := range states {
		if !state.Valid() {
			return vulnerabilitysync.Run{}, fmt.Errorf("%w: invalid sync run state", shared.ErrValidation)
		}
		values[index] = string(state)
	}
	var result vulnerabilitysync.Run
	read := func(tx pgx.Tx) error {
		query := syncRunSelect + ` WHERE source_id=$1 AND (cardinality($2::text[])=0 OR state=ANY($2::text[]))`
		args := []any{sourceID.String(), values}
		if tenantID, ok := shared.TenantFrom(ctx); ok && !tenantID.IsZero() {
			query += ` AND EXISTS (SELECT 1 FROM jobs j WHERE j.id=vulnerability_sync_runs.durable_job_id AND j.tenant_id=$3)`
			args = append(args, shared.TenantOrDefault(tenantID).String())
		}
		query += ` ORDER BY created_at DESC,id DESC LIMIT 1`
		var err error
		result, err = scanSyncRun(tx.QueryRow(ctx, query, args...))
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		return err
	}
	var err error
	if tenantID, ok := shared.TenantFrom(ctx); ok && !tenantID.IsZero() {
		err = WithTenant(ctx, s.pool, tenantID.String(), read)
	} else {
		err = WithGlobalRead(ctx, s.pool, read)
	}
	return result, err
}

func (s *SyncRunStore) MarkRunning(ctx context.Context, id shared.ID) error {
	tag, err := s.pool.Exec(ctx, `UPDATE vulnerability_sync_runs SET state='running', started_at=COALESCE(started_at, now()), updated_at=now() WHERE id=$1 AND state='queued'`, id.String())
	if err != nil {
		return fmt.Errorf("mark sync run running: %w", err)
	}
	if tag.RowsAffected() != 0 {
		return nil
	}
	run, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if run.State == vulnerabilitysync.StateRunning {
		return nil
	}
	return shared.ErrConflict
}

func (s *SyncRunStore) Advance(ctx context.Context, id shared.ID, expectedCheckpoint, nextCheckpoint []byte, counts vulnerabilitysync.Counts, errors []string) (vulnerabilitysync.Run, error) {
	if err := counts.Validate(); err != nil {
		return vulnerabilitysync.Run{}, err
	}
	expected, err := vulnerabilitysync.NormalizeCheckpoint(expectedCheckpoint)
	if err != nil {
		return vulnerabilitysync.Run{}, err
	}
	next, err := vulnerabilitysync.NormalizeCheckpoint(nextCheckpoint)
	if err != nil {
		return vulnerabilitysync.Run{}, err
	}
	errors = trimSyncErrors(errors)
	encodedErrors, _ := json.Marshal(errors)
	var result vulnerabilitysync.Run
	err = WithGlobalWrite(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE vulnerability_sync_runs SET checkpoint=$2, processed_count=$3, inserted_count=$4,
			updated_count=$5, unchanged_count=$6, skipped_count=$7, quarantined_count=$8,
			error_samples=$9, updated_at=now()
			WHERE id=$1 AND state='running' AND checkpoint=$10`, id.String(), next, counts.Processed,
			counts.Inserted, counts.Updated, counts.Unchanged, counts.Skipped, counts.Quarantined, encodedErrors, expected)
		if err != nil {
			return fmt.Errorf("advance sync run: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return syncRunAdvanceMiss(ctx, tx, id, expected)
		}
		result, err = scanSyncRun(tx.QueryRow(ctx, syncRunSelect+` WHERE id=$1`, id.String()))
		return err
	})
	if err != nil {
		return vulnerabilitysync.Run{}, err
	}
	return result, nil
}

func (s *SyncRunStore) Finish(ctx context.Context, id shared.ID, state vulnerabilitysync.State, counts vulnerabilitysync.Counts, samples []string) (vulnerabilitysync.Run, error) {
	if !state.Terminal() {
		return vulnerabilitysync.Run{}, fmt.Errorf("%w: invalid terminal sync state", shared.ErrValidation)
	}
	if err := counts.Validate(); err != nil {
		return vulnerabilitysync.Run{}, err
	}
	encodedErrors, _ := json.Marshal(trimSyncErrors(samples))
	var result vulnerabilitysync.Run
	err := WithGlobalWrite(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE vulnerability_sync_runs SET state=$2, processed_count=$3, inserted_count=$4,
			updated_count=$5, unchanged_count=$6, skipped_count=$7, quarantined_count=$8,
			error_samples=$9, finished_at=COALESCE(finished_at, now()), updated_at=now()
			WHERE id=$1 AND state IN ('queued','running')`, id.String(), string(state), counts.Processed,
			counts.Inserted, counts.Updated, counts.Unchanged, counts.Skipped, counts.Quarantined, encodedErrors)
		if err != nil {
			return fmt.Errorf("finish sync run: %w", err)
		}
		if tag.RowsAffected() == 0 {
			result, err = scanSyncRun(tx.QueryRow(ctx, syncRunSelect+` WHERE id=$1`, id.String()))
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("sync run %s: %w", id, shared.ErrNotFound)
			}
			return err
		}
		result, err = scanSyncRun(tx.QueryRow(ctx, syncRunSelect+` WHERE id=$1`, id.String()))
		return err
	})
	if err != nil {
		return vulnerabilitysync.Run{}, err
	}
	return result, nil
}

func (s *SyncRunStore) Supersede(ctx context.Context, id shared.ID) error {
	tag, err := s.pool.Exec(ctx, `UPDATE vulnerability_sync_runs SET state='superseded', finished_at=COALESCE(finished_at, now()), updated_at=now() WHERE id=$1 AND state IN ('queued','running')`, id.String())
	if err != nil {
		return fmt.Errorf("supersede sync run: %w", err)
	}
	if tag.RowsAffected() != 0 {
		return nil
	}
	run, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if run.State == vulnerabilitysync.StateSuperseded {
		return nil
	}
	return shared.ErrConflict
}

func (s *SyncRunStore) ListStale(ctx context.Context, olderThan time.Time, limit int) ([]vulnerabilitysync.Run, error) {
	if limit <= 0 {
		limit = 100
	}
	out := make([]vulnerabilitysync.Run, 0)
	read := func(tx pgx.Tx) error {
		query := syncRunSelect + ` WHERE state IN ('queued','running') AND updated_at < $1`
		args := []any{olderThan}
		if tenantID, ok := shared.TenantFrom(ctx); ok && !tenantID.IsZero() {
			query += ` AND EXISTS (SELECT 1 FROM jobs j WHERE j.id=vulnerability_sync_runs.durable_job_id AND j.tenant_id=$2)`
			args = append(args, shared.TenantOrDefault(tenantID).String())
		}
		args = append(args, limit)
		query += fmt.Sprintf(` ORDER BY updated_at,id LIMIT $%d`, len(args))
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("list stale sync runs: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			run, err := scanSyncRun(rows)
			if err != nil {
				return err
			}
			out = append(out, run)
		}
		return rows.Err()
	}
	var err error
	if tenantID, ok := shared.TenantFrom(ctx); ok && !tenantID.IsZero() {
		err = WithTenant(ctx, s.pool, tenantID.String(), read)
	} else {
		err = WithGlobalRead(ctx, s.pool, read)
	}
	return out, err
}

func (s *SyncRunStore) ListVulnerabilitySyncRuns(ctx context.Context, query vulnerabilityintel.SyncRunQuery) (vulnerabilityintel.SyncRunPage, error) {
	contextTenant, ok := shared.TenantFrom(ctx)
	query.TenantID = shared.TenantOrDefault(query.TenantID)
	if !ok || shared.TenantOrDefault(contextTenant) != query.TenantID {
		return vulnerabilityintel.SyncRunPage{}, fmt.Errorf("%w: sync run query tenant does not match context", shared.ErrValidation)
	}
	query.Limit = vulnerabilityintel.NormalizeLimit(query.Limit)
	query.Trigger = strings.TrimSpace(query.Trigger)
	if !query.CreatedAtFrom.IsZero() && !query.CreatedAtBefore.IsZero() && !query.CreatedAtFrom.Before(query.CreatedAtBefore) {
		return vulnerabilityintel.SyncRunPage{}, fmt.Errorf("%w: sync run date range is invalid", shared.ErrValidation)
	}
	states := make([]string, len(query.States))
	for index, state := range query.States {
		if !state.Valid() {
			return vulnerabilityintel.SyncRunPage{}, fmt.Errorf("%w: invalid sync run state", shared.ErrValidation)
		}
		states[index] = string(state)
	}
	modes := make([]string, len(query.Modes))
	for index, mode := range query.Modes {
		if !mode.Valid() {
			return vulnerabilityintel.SyncRunPage{}, fmt.Errorf("%w: invalid sync run mode", shared.ErrValidation)
		}
		modes[index] = string(mode)
	}
	items := make([]vulnerabilityintel.SyncRunItem, 0, query.Limit+1)
	err := WithTenant(ctx, s.pool, query.TenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, syncRunReadSelect+` WHERE ($1='' OR v.source_id=$1)
			AND (cardinality($2::text[])=0 OR v.state=ANY($2::text[]))
			AND (cardinality($3::text[])=0 OR v.mode=ANY($3::text[]))
			AND ($4='' OR v.trigger=$4)
			AND (NOT $5 OR v.created_at >= $6)
			AND (NOT $7 OR v.created_at < $8)
			AND (NOT $9 OR (v.created_at,v.id)<($10,$11))
			AND j.tenant_id=$12
			ORDER BY v.created_at DESC,v.id DESC LIMIT $13`, query.SourceID.String(), states, modes, query.Trigger,
			!query.CreatedAtFrom.IsZero(), query.CreatedAtFrom, !query.CreatedAtBefore.IsZero(), query.CreatedAtBefore,
			!query.Cursor.BeforeTime.IsZero(), query.Cursor.BeforeTime, query.Cursor.BeforeID, query.TenantID.String(), query.Limit+1)
		if err != nil {
			return fmt.Errorf("list vulnerability sync runs: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			item, err := scanSyncRunItem(rows)
			if err != nil {
				return fmt.Errorf("scan vulnerability sync run: %w", err)
			}
			items = append(items, item)
		}
		return rows.Err()
	})
	if err != nil {
		return vulnerabilityintel.SyncRunPage{}, err
	}
	page := vulnerabilityintel.SyncRunPage{}
	if len(items) > query.Limit {
		last := items[query.Limit-1].Run
		page.Next = &vulnerabilityintel.Cursor{BeforeTime: last.CreatedAt, BeforeID: last.ID.String()}
		items = items[:query.Limit]
	}
	page.Items = items
	return page, nil
}

func (s *SyncRunStore) GetVulnerabilitySyncRun(ctx context.Context, tenantID, id shared.ID) (vulnerabilityintel.SyncRunItem, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	contextTenant, ok := shared.TenantFrom(ctx)
	if !ok || shared.TenantOrDefault(contextTenant) != tenantID {
		return vulnerabilityintel.SyncRunItem{}, fmt.Errorf("%w: sync run tenant does not match context", shared.ErrValidation)
	}
	var item vulnerabilityintel.SyncRunItem
	err := WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		var err error
		item, err = scanSyncRunItem(tx.QueryRow(ctx, syncRunReadSelect+` WHERE v.id=$1 AND j.tenant_id=$2`, id.String(), tenantID.String()))
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("sync run %s: %w", id, shared.ErrNotFound)
		}
		return err
	})
	return item, err
}

func (s *SyncRunStore) LatestSuccessfulVulnerabilitySync(ctx context.Context, tenantID shared.ID) (*time.Time, error) {
	contextTenant, ok := shared.TenantFrom(ctx)
	tenantID = shared.TenantOrDefault(tenantID)
	if !ok || shared.TenantOrDefault(contextTenant) != tenantID {
		return nil, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	var latest *time.Time
	err := WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		var value *time.Time
		if err := tx.QueryRow(ctx, `SELECT max(finished_at) FROM vulnerability_sync_runs
			WHERE state='succeeded' AND EXISTS (SELECT 1 FROM jobs WHERE jobs.id=vulnerability_sync_runs.durable_job_id AND jobs.tenant_id=$1)`, tenantID.String()).Scan(&value); err != nil {
			return fmt.Errorf("load latest successful vulnerability sync: %w", err)
		}
		latest = value
		return nil
	})
	return latest, err
}

const syncRunSelect = `SELECT id, source_id, adapter_type, source_snapshot, mode, trigger, actor,
	COALESCE(client_idempotency_key,''), COALESCE(durable_job_id,''), checkpoint,
	processed_count, inserted_count, updated_count, unchanged_count, skipped_count, quarantined_count,
	error_samples, state, started_at, finished_at, created_at, updated_at FROM vulnerability_sync_runs`

type syncRunRow interface{ Scan(...any) error }

func scanSyncRun(row syncRunRow) (vulnerabilitysync.Run, error) {
	var (
		run                                                           vulnerabilitysync.Run
		sourceID, adapter, mode, trigger, actor, clientKey, jobID     string
		snapshot, checkpoint, errorSamples                            []byte
		state                                                         string
		processed, inserted, updated, unchanged, skipped, quarantined int64
	)
	if err := row.Scan(&run.ID, &sourceID, &adapter, &snapshot, &mode, &trigger, &actor, &clientKey, &jobID, &checkpoint,
		&processed, &inserted, &updated, &unchanged, &skipped, &quarantined, &errorSamples, &state,
		&run.StartedAt, &run.FinishedAt, &run.CreatedAt, &run.UpdatedAt); err != nil {
		return vulnerabilitysync.Run{}, err
	}
	run.SourceID, run.AdapterType, run.Mode, run.Trigger, run.Actor = shared.ID(sourceID), adapter, vulnerabilitysync.Mode(mode), trigger, actor
	run.ClientIdempotencyKey, run.DurableJobID, run.SourceSnapshot, run.Checkpoint, run.State = clientKey, jobID, snapshot, checkpoint, vulnerabilitysync.State(state)
	run.Counts = vulnerabilitysync.Counts{Processed: processed, Inserted: inserted, Updated: updated, Unchanged: unchanged, Skipped: skipped, Quarantined: quarantined}
	if len(errorSamples) > 0 {
		if err := json.Unmarshal(errorSamples, &run.ErrorSamples); err != nil {
			return vulnerabilitysync.Run{}, fmt.Errorf("decode sync error samples: %w", err)
		}
	}
	if err := run.Validate(); err != nil {
		return vulnerabilitysync.Run{}, fmt.Errorf("validate stored sync run: %w", err)
	}
	return run, nil
}

const syncRunReadSelect = `SELECT v.id, v.source_id, v.adapter_type, v.source_snapshot, v.mode, v.trigger, v.actor,
	COALESCE(v.client_idempotency_key,''), COALESCE(v.durable_job_id,''), v.checkpoint,
	v.processed_count, v.inserted_count, v.updated_count, v.unchanged_count, v.skipped_count, v.quarantined_count,
	v.error_samples, v.state, v.started_at, v.finished_at, v.created_at, v.updated_at, j.attempts, j.status='failed'
	FROM vulnerability_sync_runs v JOIN jobs j ON j.id=v.durable_job_id`

func scanSyncRunItem(row syncRunRow) (vulnerabilityintel.SyncRunItem, error) {
	var (
		run                                                           vulnerabilitysync.Run
		item                                                          vulnerabilityintel.SyncRunItem
		sourceID, adapter, mode, trigger, actor, clientKey, jobID     string
		snapshot, checkpoint, errorSamples                            []byte
		state                                                         string
		processed, inserted, updated, unchanged, skipped, quarantined int64
	)
	if err := row.Scan(&run.ID, &sourceID, &adapter, &snapshot, &mode, &trigger, &actor, &clientKey, &jobID, &checkpoint,
		&processed, &inserted, &updated, &unchanged, &skipped, &quarantined, &errorSamples, &state,
		&run.StartedAt, &run.FinishedAt, &run.CreatedAt, &run.UpdatedAt, &item.Attempts, &item.DeadLettered); err != nil {
		return vulnerabilityintel.SyncRunItem{}, err
	}
	run.SourceID, run.AdapterType, run.Mode, run.Trigger, run.Actor = shared.ID(sourceID), adapter, vulnerabilitysync.Mode(mode), trigger, actor
	run.ClientIdempotencyKey, run.DurableJobID, run.SourceSnapshot, run.Checkpoint, run.State = clientKey, jobID, snapshot, checkpoint, vulnerabilitysync.State(state)
	run.Counts = vulnerabilitysync.Counts{Processed: processed, Inserted: inserted, Updated: updated, Unchanged: unchanged, Skipped: skipped, Quarantined: quarantined}
	if len(errorSamples) > 0 {
		if err := json.Unmarshal(errorSamples, &run.ErrorSamples); err != nil {
			return vulnerabilityintel.SyncRunItem{}, fmt.Errorf("decode sync error samples: %w", err)
		}
	}
	if err := run.Validate(); err != nil {
		return vulnerabilityintel.SyncRunItem{}, fmt.Errorf("validate stored sync run: %w", err)
	}
	item.Run = run
	return item, nil
}

func findExistingSyncRun(ctx context.Context, tx pgx.Tx, request ports.SyncRunStart) (vulnerabilitysync.Run, bool, error) {
	query := syncRunSelect + ` WHERE source_id=$1 AND ((client_idempotency_key=$2 AND $2 <> '') OR (mode=$3 AND state IN ('queued','running'))) ORDER BY CASE WHEN client_idempotency_key=$2 AND $2 <> '' THEN 0 ELSE 1 END, created_at LIMIT 1`
	run, err := scanSyncRun(tx.QueryRow(ctx, query, request.SourceID.String(), request.ClientIdempotencyKey, string(request.Mode)))
	if errors.Is(err, pgx.ErrNoRows) {
		return vulnerabilitysync.Run{}, false, nil
	}
	if err != nil {
		return vulnerabilitysync.Run{}, false, err
	}
	return run, true, nil
}

func syncRunAdvanceMiss(ctx context.Context, tx pgx.Tx, id shared.ID, expected []byte) error {
	var current []byte
	err := tx.QueryRow(ctx, `SELECT checkpoint FROM vulnerability_sync_runs WHERE id=$1`, id.String()).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("sync run %s: %w", id, shared.ErrNotFound)
	}
	if err != nil {
		return err
	}
	if string(current) != string(expected) {
		return shared.ErrConflict
	}
	return shared.ErrConflict
}

func validateSyncStart(request ports.SyncRunStart) error {
	if request.SourceID.IsZero() || request.AdapterType == "" || !request.Mode.Valid() || request.Trigger == "" || strings.TrimSpace(request.Actor) == "" || len(request.Actor) > vulnerabilitysync.MaxActorBytes || request.JobKind == "" {
		return fmt.Errorf("%w: invalid sync start request", shared.ErrValidation)
	}
	if len(request.JobPayload) > syncJobPayloadLimit {
		return fmt.Errorf("%w: sync job payload is too large", shared.ErrValidation)
	}
	if _, err := vulnerabilitysync.NormalizeCheckpoint(request.Checkpoint); err != nil {
		return err
	}
	_, err := vulnerabilitysync.NormalizeSourceSnapshot(request.SourceSnapshot)
	return err
}

func trimSyncErrors(samples []string) []string {
	out := make([]string, 0, len(samples))
	for _, sample := range samples {
		out = vulnerabilitysync.AddErrorSample(out, sample)
	}
	return out
}

func isUniqueConstraint(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func WithGlobalRead(ctx context.Context, pool *pgxpool.Pool, fn func(pgx.Tx) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func WithGlobalWrite(ctx context.Context, pool *pgxpool.Pool, fn func(pgx.Tx) error) error {
	return WithGlobalRead(ctx, pool, fn)
}
