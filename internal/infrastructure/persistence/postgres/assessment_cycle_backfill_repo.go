package postgres

import (
	"context"
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

const assessmentCycleBackfillRunCols = `tenant_id,id,schema_version,dry_run,batch_size,snapshot_at,checkpoint_assessment_id,state,lease_owner,lease_token,lease_expires_at,processed_count,created_count,would_create_count,skipped_count,failed_count,created_by,created_at,updated_at,completed_at`

type AssessmentCycleBackfillRepository struct{ pool *pgxpool.Pool }

func NewAssessmentCycleBackfillRepository(pool *pgxpool.Pool) *AssessmentCycleBackfillRepository {
	return &AssessmentCycleBackfillRepository{pool: pool}
}

var _ ports.AssessmentCycleBackfillStore = (*AssessmentCycleBackfillRepository)(nil)

func (repository *AssessmentCycleBackfillRepository) AcquireAssessmentCycleBackfillRun(ctx context.Context, request ports.AssessmentCycleBackfillAcquireRequest) (run ports.AssessmentCycleBackfillRun, resumed bool, err error) {
	if err := validatePostgresBackfillAcquire(request); err != nil {
		return ports.AssessmentCycleBackfillRun{}, false, err
	}
	err = WithTenant(ctx, repository.pool, request.Run.TenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT `+assessmentCycleBackfillRunCols+` FROM assessment_cycle_backfill_runs WHERE tenant_id=$1 AND state='running' FOR UPDATE`, request.Run.TenantID.String())
		existing, scanErr := scanAssessmentCycleBackfillRun(row)
		if scanErr == nil {
			if existing.LeaseOwner != request.Run.LeaseOwner && existing.LeaseExpiresAt.After(request.Run.CreatedAt) {
				return fmt.Errorf("%w: assessment cycle backfill already running for tenant", shared.ErrConflict)
			}
			if existing.SchemaVersion != request.Run.SchemaVersion || existing.DryRun != request.Run.DryRun || existing.BatchSize != request.Run.BatchSize {
				return fmt.Errorf("%w: requested assessment cycle backfill config (schema=%d dry_run=%t batch_size=%d) differs from persisted config (schema=%d dry_run=%t batch_size=%d)", shared.ErrConflict,
					request.Run.SchemaVersion, request.Run.DryRun, request.Run.BatchSize, existing.SchemaVersion, existing.DryRun, existing.BatchSize)
			}
			row = tx.QueryRow(ctx, `UPDATE assessment_cycle_backfill_runs SET lease_owner=$3,lease_token=$4,lease_expires_at=$5,updated_at=$6 WHERE tenant_id=$1 AND id=$2 AND state='running' RETURNING `+assessmentCycleBackfillRunCols,
				request.Run.TenantID.String(), existing.ID.String(), request.Run.LeaseOwner, request.Run.LeaseToken.String(), request.Run.CreatedAt.Add(request.LeaseDuration), request.Run.CreatedAt)
			updated, err := scanAssessmentCycleBackfillRun(row)
			if err != nil {
				return fmt.Errorf("resume assessment cycle backfill run: %w", err)
			}
			run, resumed = updated, true
			return nil
		}
		if !errors.Is(scanErr, pgx.ErrNoRows) {
			return fmt.Errorf("find active assessment cycle backfill run: %w", scanErr)
		}
		row = tx.QueryRow(ctx, `INSERT INTO assessment_cycle_backfill_runs (`+assessmentCycleBackfillRunCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,'running',$8,$9,$10,0,0,0,0,0,$11,$12,$12,NULL) RETURNING `+assessmentCycleBackfillRunCols,
			request.Run.TenantID.String(), request.Run.ID.String(), request.Run.SchemaVersion, request.Run.DryRun, request.Run.BatchSize, request.Run.SnapshotAt,
			request.InitialCheckpoint.String(), request.Run.LeaseOwner, request.Run.LeaseToken.String(), request.Run.CreatedAt.Add(request.LeaseDuration), request.Run.CreatedBy, request.Run.CreatedAt)
		created, err := scanAssessmentCycleBackfillRun(row)
		if err != nil {
			return fmt.Errorf("create assessment cycle backfill run: %w", err)
		}
		run = created
		return nil
	})
	return run, resumed, err
}

func (repository *AssessmentCycleBackfillRepository) GetAssessmentCycleBackfillRun(ctx context.Context, tenantID, runID shared.ID) (run ports.AssessmentCycleBackfillRun, err error) {
	tenantID = shared.TenantOrDefault(tenantID)
	err = WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		item, err := scanAssessmentCycleBackfillRun(tx.QueryRow(ctx, `SELECT `+assessmentCycleBackfillRunCols+` FROM assessment_cycle_backfill_runs WHERE tenant_id=$1 AND id=$2`, tenantID.String(), runID.String()))
		if errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("get assessment cycle backfill run: %w", err)
		}
		run = item
		return nil
	})
	return run, err
}

func (repository *AssessmentCycleBackfillRepository) GetAssessmentCycleBackfillItem(ctx context.Context, tenantID, runID, assessmentID shared.ID) (item ports.AssessmentCycleBackfillItem, err error) {
	tenantID = shared.TenantOrDefault(tenantID)
	err = WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT tenant_id,run_id,assessment_id,schema_version,idempotency_key,COALESCE(cycle_id,''),outcome,reason_code,retryable,repair_guidance,processed_at FROM assessment_cycle_backfill_items WHERE tenant_id=$1 AND run_id=$2 AND assessment_id=$3`, tenantID.String(), runID.String(), assessmentID.String())
		if err := row.Scan(&item.TenantID, &item.RunID, &item.AssessmentID, &item.SchemaVersion, &item.IdempotencyKey, &item.CycleID, &item.Outcome, &item.ReasonCode, &item.Retryable, &item.RepairGuidance, &item.ProcessedAt); errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		} else if err != nil {
			return fmt.Errorf("get assessment cycle backfill item: %w", err)
		}
		return nil
	})
	return item, err
}

func (repository *AssessmentCycleBackfillRepository) CommitAssessmentCycleBackfillItem(ctx context.Context, tenantID, runID, leaseToken shared.ID, now time.Time, build func(context.Context) (ports.AssessmentCycleBackfillItem, error)) (item ports.AssessmentCycleBackfillItem, created bool, err error) {
	tenantID, now = shared.TenantOrDefault(tenantID), now.UTC()
	if tenantID.IsZero() || runID.IsZero() || leaseToken.IsZero() || now.IsZero() || build == nil {
		return item, false, fmt.Errorf("%w: assessment cycle backfill commit identity is invalid", shared.ErrValidation)
	}
	err = WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		var active bool
		if err := tx.QueryRow(ctx, `SELECT state='running' AND lease_token=$3 AND lease_expires_at>$4 FROM assessment_cycle_backfill_runs WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID.String(), runID.String(), leaseToken.String(), now).Scan(&active); errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		} else if err != nil {
			return fmt.Errorf("lock assessment cycle backfill lease: %w", err)
		}
		if !active {
			return fmt.Errorf("%w: assessment cycle backfill lease is stale", shared.ErrConflict)
		}
		var err error
		item, err = build(bindTenantTransaction(ctx, tenantID, tx))
		if err != nil {
			return err
		}
		if item.TenantID != tenantID || item.RunID != runID {
			return fmt.Errorf("%w: assessment cycle backfill item ownership differs from lease", shared.ErrValidation)
		}
		if err := validatePostgresBackfillItem(item); err != nil {
			return err
		}
		var inserted int
		err = tx.QueryRow(ctx, `INSERT INTO assessment_cycle_backfill_items(tenant_id,run_id,assessment_id,schema_version,idempotency_key,cycle_id,outcome,reason_code,retryable,repair_guidance,processed_at)
			VALUES($1,$2,$3,$4,$5,NULLIF($6,''),$7,$8,$9,$10,$11) ON CONFLICT (tenant_id,run_id,assessment_id) DO NOTHING RETURNING 1`,
			item.TenantID.String(), item.RunID.String(), item.AssessmentID.String(), item.SchemaVersion, item.IdempotencyKey, item.CycleID.String(), item.Outcome, item.ReasonCode, item.Retryable, item.RepairGuidance, item.ProcessedAt.UTC()).Scan(&inserted)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("save assessment cycle backfill item: %w", err)
		}
		created = inserted == 1
		return nil
	})
	return item, created, err
}

func (repository *AssessmentCycleBackfillRepository) AdvanceAssessmentCycleBackfillRun(ctx context.Context, tenantID, runID shared.ID, leaseOwner string, leaseToken, checkpoint shared.ID, now time.Time, leaseDuration time.Duration) (run ports.AssessmentCycleBackfillRun, err error) {
	tenantID, leaseOwner, now = shared.TenantOrDefault(tenantID), strings.TrimSpace(leaseOwner), now.UTC()
	if tenantID.IsZero() || runID.IsZero() || leaseOwner == "" || leaseToken.IsZero() || checkpoint.IsZero() || now.IsZero() || leaseDuration <= 0 {
		return ports.AssessmentCycleBackfillRun{}, fmt.Errorf("%w: assessment cycle backfill checkpoint is invalid", shared.ErrValidation)
	}
	err = WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `UPDATE assessment_cycle_backfill_runs AS run SET checkpoint_assessment_id=$5,updated_at=$6::timestamptz,lease_expires_at=$6::timestamptz+($7 * interval '1 microsecond'),
			processed_count=(SELECT count(*) FROM assessment_cycle_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id),
			created_count=(SELECT count(*) FROM assessment_cycle_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='created'),
			would_create_count=(SELECT count(*) FROM assessment_cycle_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='would_create'),
			skipped_count=(SELECT count(*) FROM assessment_cycle_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='skipped'),
			failed_count=(SELECT count(*) FROM assessment_cycle_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='failed')
			WHERE run.tenant_id=$1 AND run.id=$2 AND run.state='running' AND run.lease_owner=$3 AND run.lease_token=$4 AND run.lease_expires_at>$6 AND run.checkpoint_assessment_id COLLATE "C"<=$5 RETURNING `+assessmentCycleBackfillRunCols,
			tenantID.String(), runID.String(), leaseOwner, leaseToken.String(), checkpoint.String(), now, leaseDuration.Microseconds())
		updated, err := scanAssessmentCycleBackfillRun(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: assessment cycle backfill checkpoint rejected", shared.ErrConflict)
		}
		if err != nil {
			return fmt.Errorf("advance assessment cycle backfill run: %w", err)
		}
		run = updated
		return nil
	})
	return run, err
}

func (repository *AssessmentCycleBackfillRepository) FinishAssessmentCycleBackfillRun(ctx context.Context, tenantID, runID shared.ID, leaseOwner string, leaseToken shared.ID, state ports.AssessmentCycleBackfillState, now time.Time) (run ports.AssessmentCycleBackfillRun, err error) {
	if state != ports.AssessmentCycleBackfillCompleted && state != ports.AssessmentCycleBackfillCancelled && state != ports.AssessmentCycleBackfillFailed {
		return ports.AssessmentCycleBackfillRun{}, fmt.Errorf("%w: invalid assessment cycle backfill terminal state", shared.ErrValidation)
	}
	tenantID, leaseOwner, now = shared.TenantOrDefault(tenantID), strings.TrimSpace(leaseOwner), now.UTC()
	if tenantID.IsZero() || runID.IsZero() || leaseOwner == "" || leaseToken.IsZero() || now.IsZero() {
		return ports.AssessmentCycleBackfillRun{}, fmt.Errorf("%w: assessment cycle backfill completion identity is invalid", shared.ErrValidation)
	}
	err = WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `UPDATE assessment_cycle_backfill_runs AS run SET state=$5,lease_owner='',lease_token='',lease_expires_at=NULL,updated_at=$6,completed_at=$6,
			processed_count=(SELECT count(*) FROM assessment_cycle_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id),
			created_count=(SELECT count(*) FROM assessment_cycle_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='created'),
			would_create_count=(SELECT count(*) FROM assessment_cycle_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='would_create'),
			skipped_count=(SELECT count(*) FROM assessment_cycle_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='skipped'),
			failed_count=(SELECT count(*) FROM assessment_cycle_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='failed')
			WHERE run.tenant_id=$1 AND run.id=$2 AND run.state='running' AND run.lease_owner=$3 AND run.lease_token=$4 AND run.lease_expires_at>$6 RETURNING `+assessmentCycleBackfillRunCols,
			tenantID.String(), runID.String(), leaseOwner, leaseToken.String(), string(state), now)
		finished, err := scanAssessmentCycleBackfillRun(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: assessment cycle backfill completion rejected", shared.ErrConflict)
		}
		if err != nil {
			return fmt.Errorf("finish assessment cycle backfill run: %w", err)
		}
		run = finished
		return nil
	})
	return run, err
}

func scanAssessmentCycleBackfillRun(row rowScanner) (ports.AssessmentCycleBackfillRun, error) {
	var (
		run                       ports.AssessmentCycleBackfillRun
		state                     string
		leaseExpires, completedAt pgtype.Timestamptz
	)
	if err := row.Scan(&run.TenantID, &run.ID, &run.SchemaVersion, &run.DryRun, &run.BatchSize, &run.SnapshotAt, &run.CheckpointAssessment, &state, &run.LeaseOwner, &run.LeaseToken, &leaseExpires,
		&run.ProcessedCount, &run.CreatedCount, &run.WouldCreateCount, &run.SkippedCount, &run.FailedCount, &run.CreatedBy, &run.CreatedAt, &run.UpdatedAt, &completedAt); err != nil {
		return ports.AssessmentCycleBackfillRun{}, err
	}
	run.State = ports.AssessmentCycleBackfillState(state)
	if leaseExpires.Valid {
		run.LeaseExpiresAt = leaseExpires.Time
	}
	if completedAt.Valid {
		completed := completedAt.Time
		run.CompletedAt = &completed
	}
	return run, nil
}

func validatePostgresBackfillAcquire(request ports.AssessmentCycleBackfillAcquireRequest) error {
	run := request.Run
	if run.TenantID.IsZero() || run.ID.IsZero() || run.LeaseToken.IsZero() || run.SchemaVersion <= 0 || run.BatchSize < 1 || run.BatchSize > 2000 || run.SnapshotAt.IsZero() || run.State != ports.AssessmentCycleBackfillRunning || strings.TrimSpace(run.LeaseOwner) == "" || len(run.LeaseOwner) > 256 || strings.TrimSpace(run.CreatedBy) == "" || len(run.CreatedBy) > 256 || run.CreatedAt.IsZero() || request.LeaseDuration <= 0 {
		return fmt.Errorf("%w: assessment cycle backfill run is invalid", shared.ErrValidation)
	}
	return nil
}

func validatePostgresBackfillItem(item ports.AssessmentCycleBackfillItem) error {
	validOutcome := item.Outcome == "created" || item.Outcome == "would_create" || item.Outcome == "skipped" || item.Outcome == "failed"
	if item.TenantID.IsZero() || item.RunID.IsZero() || item.AssessmentID.IsZero() || item.SchemaVersion <= 0 || strings.TrimSpace(item.IdempotencyKey) == "" || len(item.IdempotencyKey) > 128 || !validOutcome || strings.TrimSpace(item.ReasonCode) == "" || len(item.ReasonCode) > 64 || len(item.RepairGuidance) > 1024 || item.ProcessedAt.IsZero() {
		return fmt.Errorf("%w: assessment cycle backfill item is invalid", shared.ErrValidation)
	}
	return nil
}
