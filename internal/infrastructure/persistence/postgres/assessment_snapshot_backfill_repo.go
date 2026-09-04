package postgres

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const assessmentSnapshotBackfillRunColumns = `tenant_id,id,schema_version,dry_run,batch_size,snapshot_at,checkpoint_assessment_id,state,lease_owner,lease_token,lease_expires_at,processed_count,created_count,would_create_count,skipped_count,failed_count,created_by,created_at,updated_at,completed_at`

type AssessmentSnapshotBackfillRepository struct{ pool *pgxpool.Pool }

func NewAssessmentSnapshotBackfillRepository(pool *pgxpool.Pool) *AssessmentSnapshotBackfillRepository {
	return &AssessmentSnapshotBackfillRepository{pool: pool}
}

var _ ports.AssessmentSnapshotBackfillStore = (*AssessmentSnapshotBackfillRepository)(nil)

func (repository *AssessmentSnapshotBackfillRepository) AcquireAssessmentSnapshotBackfillRun(ctx context.Context, request ports.AssessmentSnapshotBackfillAcquireRequest) (run ports.AssessmentSnapshotBackfillRun, resumed bool, err error) {
	if err := validatePostgresAssessmentSnapshotBackfillAcquire(request); err != nil {
		return ports.AssessmentSnapshotBackfillRun{}, false, err
	}
	err = WithTenant(ctx, repository.pool, request.Run.TenantID.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT id FROM tenants WHERE id=$1 FOR UPDATE`, request.Run.TenantID.String()); err != nil {
			return fmt.Errorf("lock assessment snapshot backfill tenant: %w", err)
		}
		row := tx.QueryRow(ctx, `SELECT `+assessmentSnapshotBackfillRunColumns+` FROM assessment_snapshot_backfill_runs WHERE tenant_id=$1 AND state='running' FOR UPDATE`, request.Run.TenantID.String())
		existing, scanErr := scanAssessmentSnapshotBackfillRun(row)
		if scanErr == nil {
			if existing.LeaseOwner != request.Run.LeaseOwner && existing.LeaseExpiresAt.After(request.Run.CreatedAt) {
				return fmt.Errorf("%w: assessment snapshot backfill already running for tenant", shared.ErrConflict)
			}
			if existing.SchemaVersion != request.Run.SchemaVersion || existing.DryRun != request.Run.DryRun || existing.BatchSize != request.Run.BatchSize {
				return fmt.Errorf("%w: requested assessment snapshot backfill config (schema=%d dry_run=%t batch_size=%d) differs from persisted config (schema=%d dry_run=%t batch_size=%d)", shared.ErrConflict,
					request.Run.SchemaVersion, request.Run.DryRun, request.Run.BatchSize, existing.SchemaVersion, existing.DryRun, existing.BatchSize)
			}
			updated, err := scanAssessmentSnapshotBackfillRun(tx.QueryRow(ctx, `UPDATE assessment_snapshot_backfill_runs SET lease_owner=$3,lease_token=$4,lease_expires_at=$5,updated_at=$6 WHERE tenant_id=$1 AND id=$2 AND state='running' RETURNING `+assessmentSnapshotBackfillRunColumns,
				request.Run.TenantID.String(), existing.ID.String(), request.Run.LeaseOwner, request.Run.LeaseToken.String(), request.Run.CreatedAt.Add(request.LeaseDuration), request.Run.CreatedAt))
			if err != nil {
				return fmt.Errorf("resume assessment snapshot backfill run: %w", err)
			}
			run, resumed = updated, true
			return nil
		}
		if !errors.Is(scanErr, pgx.ErrNoRows) {
			return fmt.Errorf("find active assessment snapshot backfill run: %w", scanErr)
		}
		created, err := scanAssessmentSnapshotBackfillRun(tx.QueryRow(ctx, `INSERT INTO assessment_snapshot_backfill_runs (`+assessmentSnapshotBackfillRunColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,'running',$8,$9,$10,0,0,0,0,0,$11,$12,$12,NULL) RETURNING `+assessmentSnapshotBackfillRunColumns,
			request.Run.TenantID.String(), request.Run.ID.String(), request.Run.SchemaVersion, request.Run.DryRun, request.Run.BatchSize, request.Run.SnapshotAt,
			request.InitialCheckpoint.String(), request.Run.LeaseOwner, request.Run.LeaseToken.String(), request.Run.CreatedAt.Add(request.LeaseDuration), request.Run.CreatedBy, request.Run.CreatedAt))
		if err != nil {
			return fmt.Errorf("create assessment snapshot backfill run: %w", err)
		}
		run = created
		return nil
	})
	return run, resumed, err
}

func (repository *AssessmentSnapshotBackfillRepository) GetAssessmentSnapshotBackfillRun(ctx context.Context, tenantID, runID shared.ID) (run ports.AssessmentSnapshotBackfillRun, err error) {
	tenantID = shared.TenantOrDefault(tenantID)
	err = WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		item, err := scanAssessmentSnapshotBackfillRun(tx.QueryRow(ctx, `SELECT `+assessmentSnapshotBackfillRunColumns+` FROM assessment_snapshot_backfill_runs WHERE tenant_id=$1 AND id=$2`, tenantID.String(), runID.String()))
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("get assessment snapshot backfill run: %w", err)
		}
		run = item
		return nil
	})
	return run, err
}

func (repository *AssessmentSnapshotBackfillRepository) GetAssessmentSnapshotBackfillItem(ctx context.Context, tenantID, runID, assessmentID shared.ID) (item ports.AssessmentSnapshotBackfillItem, err error) {
	tenantID = shared.TenantOrDefault(tenantID)
	err = WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT tenant_id,run_id,assessment_id,schema_version,idempotency_key,source_hash,COALESCE(snapshot_id,''),outcome,reason_code,retryable,repair_guidance,processed_at FROM assessment_snapshot_backfill_items WHERE tenant_id=$1 AND run_id=$2 AND assessment_id=$3`, tenantID.String(), runID.String(), assessmentID.String())
		if err := row.Scan(&item.TenantID, &item.RunID, &item.AssessmentID, &item.SchemaVersion, &item.IdempotencyKey, &item.SourceHash, &item.SnapshotID, &item.Outcome, &item.ReasonCode, &item.Retryable, &item.RepairGuidance, &item.ProcessedAt); errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		} else if err != nil {
			return fmt.Errorf("get assessment snapshot backfill item: %w", err)
		}
		return nil
	})
	return item, err
}

func (repository *AssessmentSnapshotBackfillRepository) CommitAssessmentSnapshotBackfillItem(ctx context.Context, tenantID, runID, leaseToken shared.ID, now time.Time, build func(context.Context) (ports.AssessmentSnapshotBackfillItem, error)) (item ports.AssessmentSnapshotBackfillItem, created bool, err error) {
	tenantID, now = shared.TenantOrDefault(tenantID), now.UTC()
	if tenantID.IsZero() || runID.IsZero() || leaseToken.IsZero() || now.IsZero() || build == nil {
		return item, false, fmt.Errorf("%w: assessment snapshot backfill commit identity is invalid", shared.ErrValidation)
	}
	err = WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		var active bool
		if err := tx.QueryRow(ctx, `SELECT state='running' AND lease_token=$3 AND lease_expires_at>$4 FROM assessment_snapshot_backfill_runs WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID.String(), runID.String(), leaseToken.String(), now).Scan(&active); errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		} else if err != nil {
			return fmt.Errorf("lock assessment snapshot backfill lease: %w", err)
		}
		if !active {
			return fmt.Errorf("%w: assessment snapshot backfill lease is stale", shared.ErrConflict)
		}
		var err error
		item, err = build(bindTenantTransaction(ctx, tenantID, tx))
		if err != nil {
			return err
		}
		if item.TenantID != tenantID || item.RunID != runID {
			return fmt.Errorf("%w: assessment snapshot backfill item ownership differs from lease", shared.ErrValidation)
		}
		if err := validatePostgresAssessmentSnapshotBackfillItem(item); err != nil {
			return err
		}
		result, err := tx.Exec(ctx, `INSERT INTO assessment_snapshot_backfill_items(
			tenant_id,run_id,assessment_id,schema_version,idempotency_key,source_hash,snapshot_id,outcome,reason_code,retryable,repair_guidance,processed_at)
			SELECT $1,$2,$3,$4,$5,$6,NULLIF($7,''),$8,$9,$10,$11,$12
			WHERE EXISTS (SELECT 1 FROM assessment_snapshot_backfill_runs WHERE tenant_id=$1 AND id=$2 AND state='running')
			ON CONFLICT DO NOTHING`, item.TenantID.String(), item.RunID.String(), item.AssessmentID.String(), item.SchemaVersion,
			item.IdempotencyKey, item.SourceHash, item.SnapshotID.String(), item.Outcome, item.ReasonCode, item.Retryable, item.RepairGuidance, item.ProcessedAt)
		if err != nil {
			return mapPostgresError(err, "save assessment snapshot backfill item")
		}
		created = result.RowsAffected() == 1
		if !created {
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM assessment_snapshot_backfill_items WHERE tenant_id=$1 AND run_id=$2 AND assessment_id=$3)`, item.TenantID.String(), item.RunID.String(), item.AssessmentID.String()).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				return fmt.Errorf("%w: assessment snapshot backfill run is not active", shared.ErrConflict)
			}
		}
		return nil
	})
	return item, created, err
}

func (repository *AssessmentSnapshotBackfillRepository) AdvanceAssessmentSnapshotBackfillRun(ctx context.Context, tenantID, runID shared.ID, leaseOwner string, leaseToken, checkpoint shared.ID, now time.Time, leaseDuration time.Duration) (run ports.AssessmentSnapshotBackfillRun, err error) {
	tenantID, leaseOwner, now = shared.TenantOrDefault(tenantID), strings.TrimSpace(leaseOwner), now.UTC()
	if leaseToken.IsZero() || leaseDuration <= 0 {
		return ports.AssessmentSnapshotBackfillRun{}, fmt.Errorf("%w: assessment snapshot backfill lease duration is invalid", shared.ErrValidation)
	}
	err = WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		updated, err := scanAssessmentSnapshotBackfillRun(tx.QueryRow(ctx, `UPDATE assessment_snapshot_backfill_runs AS run SET checkpoint_assessment_id=$5,lease_expires_at=$7,updated_at=$6,
			processed_count=(SELECT count(*) FROM assessment_snapshot_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id),
			created_count=(SELECT count(*) FROM assessment_snapshot_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='created'),
			would_create_count=(SELECT count(*) FROM assessment_snapshot_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='would_create'),
			skipped_count=(SELECT count(*) FROM assessment_snapshot_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='skipped'),
			failed_count=(SELECT count(*) FROM assessment_snapshot_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='failed')
			WHERE run.tenant_id=$1 AND run.id=$2 AND run.state='running' AND run.lease_owner=$3 AND run.lease_token=$4 AND run.lease_expires_at>$6 AND run.checkpoint_assessment_id COLLATE "C" <= $5
			RETURNING `+assessmentSnapshotBackfillRunColumns, tenantID.String(), runID.String(), leaseOwner, leaseToken.String(), checkpoint.String(), now, now.Add(leaseDuration)))
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: assessment snapshot backfill checkpoint rejected", shared.ErrConflict)
		}
		if err != nil {
			return fmt.Errorf("advance assessment snapshot backfill run: %w", err)
		}
		run = updated
		return nil
	})
	return run, err
}

func (repository *AssessmentSnapshotBackfillRepository) FinishAssessmentSnapshotBackfillRun(ctx context.Context, tenantID, runID shared.ID, leaseOwner string, leaseToken shared.ID, state ports.AssessmentSnapshotBackfillState, now time.Time) (run ports.AssessmentSnapshotBackfillRun, err error) {
	if state != ports.AssessmentSnapshotBackfillCompleted && state != ports.AssessmentSnapshotBackfillCancelled && state != ports.AssessmentSnapshotBackfillFailed {
		return ports.AssessmentSnapshotBackfillRun{}, fmt.Errorf("%w: invalid assessment snapshot backfill terminal state", shared.ErrValidation)
	}
	tenantID, leaseOwner, now = shared.TenantOrDefault(tenantID), strings.TrimSpace(leaseOwner), now.UTC()
	if tenantID.IsZero() || runID.IsZero() || leaseOwner == "" || leaseToken.IsZero() || now.IsZero() {
		return ports.AssessmentSnapshotBackfillRun{}, fmt.Errorf("%w: assessment snapshot backfill completion identity is invalid", shared.ErrValidation)
	}
	err = WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		finished, err := scanAssessmentSnapshotBackfillRun(tx.QueryRow(ctx, `UPDATE assessment_snapshot_backfill_runs AS run SET state=$5,lease_owner='',lease_token='',lease_expires_at=NULL,updated_at=$6,completed_at=$6,
			processed_count=(SELECT count(*) FROM assessment_snapshot_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id),
			created_count=(SELECT count(*) FROM assessment_snapshot_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='created'),
			would_create_count=(SELECT count(*) FROM assessment_snapshot_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='would_create'),
			skipped_count=(SELECT count(*) FROM assessment_snapshot_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='skipped'),
			failed_count=(SELECT count(*) FROM assessment_snapshot_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='failed')
			WHERE run.tenant_id=$1 AND run.id=$2 AND run.state='running' AND run.lease_owner=$3 AND run.lease_token=$4 AND run.lease_expires_at>$6 RETURNING `+assessmentSnapshotBackfillRunColumns,
			tenantID.String(), runID.String(), leaseOwner, leaseToken.String(), string(state), now))
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: assessment snapshot backfill completion rejected", shared.ErrConflict)
		}
		if err != nil {
			return fmt.Errorf("finish assessment snapshot backfill run: %w", err)
		}
		run = finished
		return nil
	})
	return run, err
}

func scanAssessmentSnapshotBackfillRun(row rowScanner) (ports.AssessmentSnapshotBackfillRun, error) {
	var (
		run                       ports.AssessmentSnapshotBackfillRun
		state                     string
		leaseExpires, completedAt pgtype.Timestamptz
	)
	if err := row.Scan(&run.TenantID, &run.ID, &run.SchemaVersion, &run.DryRun, &run.BatchSize, &run.SnapshotAt, &run.CheckpointAssessment, &state, &run.LeaseOwner, &run.LeaseToken, &leaseExpires,
		&run.ProcessedCount, &run.CreatedCount, &run.WouldCreateCount, &run.SkippedCount, &run.FailedCount, &run.CreatedBy, &run.CreatedAt, &run.UpdatedAt, &completedAt); err != nil {
		return ports.AssessmentSnapshotBackfillRun{}, err
	}
	run.State = ports.AssessmentSnapshotBackfillState(state)
	if leaseExpires.Valid {
		run.LeaseExpiresAt = leaseExpires.Time
	}
	if completedAt.Valid {
		completed := completedAt.Time
		run.CompletedAt = &completed
	}
	return run, nil
}

func validatePostgresAssessmentSnapshotBackfillAcquire(request ports.AssessmentSnapshotBackfillAcquireRequest) error {
	run := request.Run
	if run.TenantID.IsZero() || run.ID.IsZero() || run.LeaseToken.IsZero() || run.SchemaVersion <= 0 || run.BatchSize < 1 || run.BatchSize > 2000 || run.SnapshotAt.IsZero() || run.State != ports.AssessmentSnapshotBackfillRunning || strings.TrimSpace(run.LeaseOwner) == "" || len(run.LeaseOwner) > 256 || strings.TrimSpace(run.CreatedBy) == "" || len(run.CreatedBy) > 256 || run.CreatedAt.IsZero() || request.LeaseDuration <= 0 {
		return fmt.Errorf("%w: assessment snapshot backfill run is invalid", shared.ErrValidation)
	}
	return nil
}

func validatePostgresAssessmentSnapshotBackfillItem(item ports.AssessmentSnapshotBackfillItem) error {
	validOutcome := item.Outcome == "created" || item.Outcome == "would_create" || item.Outcome == "skipped" || item.Outcome == "failed"
	_, hashErr := hex.DecodeString(item.SourceHash)
	if item.TenantID.IsZero() || item.RunID.IsZero() || item.AssessmentID.IsZero() || item.SchemaVersion <= 0 || strings.TrimSpace(item.IdempotencyKey) == "" || len(item.IdempotencyKey) > 128 || len(item.SourceHash) != 64 || strings.ToLower(item.SourceHash) != item.SourceHash || hashErr != nil || !validOutcome || strings.TrimSpace(item.ReasonCode) == "" || len(item.ReasonCode) > 64 || len(item.RepairGuidance) > 1024 || item.ProcessedAt.IsZero() {
		return fmt.Errorf("%w: assessment snapshot backfill item is invalid", shared.ErrValidation)
	}
	if item.Outcome == "created" && item.SnapshotID.IsZero() {
		return fmt.Errorf("%w: created assessment snapshot backfill item requires a snapshot", shared.ErrValidation)
	}
	return nil
}
