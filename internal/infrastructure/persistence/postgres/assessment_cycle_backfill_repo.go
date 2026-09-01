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

const assessmentCycleBackfillRunCols = `tenant_id,id,schema_version,dry_run,batch_size,snapshot_at,checkpoint_assessment_id,state,lease_owner,lease_expires_at,processed_count,created_count,would_create_count,skipped_count,failed_count,created_by,created_at,updated_at,completed_at`

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
			row = tx.QueryRow(ctx, `UPDATE assessment_cycle_backfill_runs SET lease_owner=$3,lease_expires_at=$4,updated_at=$5 WHERE tenant_id=$1 AND id=$2 AND state='running' RETURNING `+assessmentCycleBackfillRunCols,
				request.Run.TenantID.String(), existing.ID.String(), request.Run.LeaseOwner, request.Run.CreatedAt.Add(request.LeaseDuration), request.Run.CreatedAt)
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
		row = tx.QueryRow(ctx, `INSERT INTO assessment_cycle_backfill_runs (`+assessmentCycleBackfillRunCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,'running',$8,$9,0,0,0,0,0,$10,$11,$11,NULL) RETURNING `+assessmentCycleBackfillRunCols,
			request.Run.TenantID.String(), request.Run.ID.String(), request.Run.SchemaVersion, request.Run.DryRun, request.Run.BatchSize, request.Run.SnapshotAt,
			request.InitialCheckpoint.String(), request.Run.LeaseOwner, request.Run.CreatedAt.Add(request.LeaseDuration), request.Run.CreatedBy, request.Run.CreatedAt)
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

func (repository *AssessmentCycleBackfillRepository) SaveAssessmentCycleBackfillItem(ctx context.Context, item ports.AssessmentCycleBackfillItem) (created bool, err error) {
	if err := validatePostgresBackfillItem(item); err != nil {
		return false, err
	}
	err = WithTenant(ctx, repository.pool, item.TenantID.String(), func(tx pgx.Tx) error {
		var inserted int
		err := tx.QueryRow(ctx, `INSERT INTO assessment_cycle_backfill_items(tenant_id,run_id,assessment_id,schema_version,idempotency_key,cycle_id,outcome,reason_code,retryable,repair_guidance,processed_at)
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
	return created, err
}

func (repository *AssessmentCycleBackfillRepository) AdvanceAssessmentCycleBackfillRun(ctx context.Context, tenantID, runID shared.ID, leaseOwner string, checkpoint shared.ID, now time.Time, leaseDuration time.Duration) (run ports.AssessmentCycleBackfillRun, err error) {
	tenantID, leaseOwner, now = shared.TenantOrDefault(tenantID), strings.TrimSpace(leaseOwner), now.UTC()
	if tenantID.IsZero() || runID.IsZero() || leaseOwner == "" || checkpoint.IsZero() || now.IsZero() || leaseDuration <= 0 {
		return ports.AssessmentCycleBackfillRun{}, fmt.Errorf("%w: assessment cycle backfill checkpoint is invalid", shared.ErrValidation)
	}
	err = WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `UPDATE assessment_cycle_backfill_runs AS run SET checkpoint_assessment_id=$4,updated_at=$5::timestamptz,lease_expires_at=$5::timestamptz+($6 * interval '1 microsecond'),
			processed_count=(SELECT count(*) FROM assessment_cycle_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id),
			created_count=(SELECT count(*) FROM assessment_cycle_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='created'),
			would_create_count=(SELECT count(*) FROM assessment_cycle_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='would_create'),
			skipped_count=(SELECT count(*) FROM assessment_cycle_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='skipped'),
			failed_count=(SELECT count(*) FROM assessment_cycle_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='failed')
			WHERE run.tenant_id=$1 AND run.id=$2 AND run.state='running' AND run.lease_owner=$3 AND run.checkpoint_assessment_id COLLATE "C"<=$4 RETURNING `+assessmentCycleBackfillRunCols,
			tenantID.String(), runID.String(), leaseOwner, checkpoint.String(), now, leaseDuration.Microseconds())
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

func (repository *AssessmentCycleBackfillRepository) FinishAssessmentCycleBackfillRun(ctx context.Context, tenantID, runID shared.ID, leaseOwner string, state ports.AssessmentCycleBackfillState, now time.Time) (run ports.AssessmentCycleBackfillRun, err error) {
	if state != ports.AssessmentCycleBackfillCompleted && state != ports.AssessmentCycleBackfillCancelled && state != ports.AssessmentCycleBackfillFailed {
		return ports.AssessmentCycleBackfillRun{}, fmt.Errorf("%w: invalid assessment cycle backfill terminal state", shared.ErrValidation)
	}
	tenantID, leaseOwner, now = shared.TenantOrDefault(tenantID), strings.TrimSpace(leaseOwner), now.UTC()
	err = WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `UPDATE assessment_cycle_backfill_runs AS run SET state=$4,lease_owner='',lease_expires_at=NULL,updated_at=$5,completed_at=$5,
			processed_count=(SELECT count(*) FROM assessment_cycle_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id),
			created_count=(SELECT count(*) FROM assessment_cycle_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='created'),
			would_create_count=(SELECT count(*) FROM assessment_cycle_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='would_create'),
			skipped_count=(SELECT count(*) FROM assessment_cycle_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='skipped'),
			failed_count=(SELECT count(*) FROM assessment_cycle_backfill_items item WHERE item.tenant_id=run.tenant_id AND item.run_id=run.id AND item.outcome='failed')
			WHERE run.tenant_id=$1 AND run.id=$2 AND run.state='running' AND run.lease_owner=$3 RETURNING `+assessmentCycleBackfillRunCols,
			tenantID.String(), runID.String(), leaseOwner, string(state), now)
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
	if err := row.Scan(&run.TenantID, &run.ID, &run.SchemaVersion, &run.DryRun, &run.BatchSize, &run.SnapshotAt, &run.CheckpointAssessment, &state, &run.LeaseOwner, &leaseExpires,
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
	if run.TenantID.IsZero() || run.ID.IsZero() || run.SchemaVersion <= 0 || run.BatchSize < 1 || run.BatchSize > 2000 || run.SnapshotAt.IsZero() || run.State != ports.AssessmentCycleBackfillRunning || strings.TrimSpace(run.LeaseOwner) == "" || len(run.LeaseOwner) > 256 || strings.TrimSpace(run.CreatedBy) == "" || len(run.CreatedBy) > 256 || run.CreatedAt.IsZero() || request.LeaseDuration <= 0 {
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
