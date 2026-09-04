package assessmentcycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	cycledom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	AssessmentCycleBackfillSchemaVersion = 1
	DefaultAssessmentCycleBackfillBatch  = 500
	MaxAssessmentCycleBackfillBatch      = 2000
	assessmentCycleBackfillRetries       = 3
	defaultAssessmentCycleBackfillLease  = 10 * time.Minute
)

const (
	BackfillOutcomeCreated     = "created"
	BackfillOutcomeWouldCreate = "would_create"
	BackfillOutcomeSkipped     = "skipped"
	BackfillOutcomeFailed      = "failed"

	BackfillReasonCreated        = "created"
	BackfillReasonWouldCreate    = "would_create"
	BackfillReasonAlreadyInCycle = "already_in_cycle"
	BackfillReasonHiddenContext  = "hidden_project_context"
	BackfillReasonSourceMissing  = "source_not_found"
	BackfillReasonInvalidSource  = "invalid_source"
	BackfillReasonWriteFailed    = "write_failed"
)

type historicalSingletonBackfiller interface {
	BackfillHistoricalSingleton(context.Context, BackfillHistoricalSingletonInput) (BackfillHistoricalSingletonResult, error)
}

type AssessmentCycleBackfillObserver interface {
	ObserveAssessmentCycleBackfillItem(outcome string)
	ObserveAssessmentCycleBackfillRun(state string)
}

type BackfillRunner struct {
	backfiller historicalSingletonBackfiller
	source     ports.AssessmentCycleBackfillSource
	store      ports.AssessmentCycleBackfillStore
	ids        ports.IDGenerator
	clock      ports.Clock
	audit      ports.AuditLogger
	observer   AssessmentCycleBackfillObserver
}

func NewBackfillRunner(backfiller historicalSingletonBackfiller, source ports.AssessmentCycleBackfillSource, store ports.AssessmentCycleBackfillStore, ids ports.IDGenerator, clock ports.Clock, audit ports.AuditLogger, observer AssessmentCycleBackfillObserver) (*BackfillRunner, error) {
	if backfiller == nil || source == nil || store == nil || ids == nil || clock == nil {
		return nil, fmt.Errorf("%w: assessment cycle backfill dependencies are required", shared.ErrValidation)
	}
	return &BackfillRunner{backfiller: backfiller, source: source, store: store, ids: ids, clock: clock, audit: audit, observer: observer}, nil
}

type BackfillRequest struct {
	TenantID      shared.ID
	Actor         string
	LeaseOwner    string
	DryRun        bool
	BatchSize     int
	ResumeAfter   shared.ID
	LeaseDuration time.Duration
}

func (runner *BackfillRunner) Run(ctx context.Context, request BackfillRequest) (ports.AssessmentCycleBackfillRun, error) {
	tenantID := shared.TenantOrDefault(request.TenantID)
	actor, leaseOwner := strings.TrimSpace(request.Actor), strings.TrimSpace(request.LeaseOwner)
	if tenantID.IsZero() || actor == "" || len(actor) > 256 || leaseOwner == "" || len(leaseOwner) > 256 {
		return ports.AssessmentCycleBackfillRun{}, fmt.Errorf("%w: tenant, actor, and lease owner are required", shared.ErrValidation)
	}
	batchSize := request.BatchSize
	if batchSize == 0 {
		batchSize = DefaultAssessmentCycleBackfillBatch
	}
	if batchSize < 1 || batchSize > MaxAssessmentCycleBackfillBatch {
		return ports.AssessmentCycleBackfillRun{}, fmt.Errorf("%w: batch size must be between 1 and %d", shared.ErrValidation, MaxAssessmentCycleBackfillBatch)
	}
	leaseDuration := request.LeaseDuration
	if leaseDuration <= 0 {
		leaseDuration = defaultAssessmentCycleBackfillLease
	}
	now := runner.clock.Now().UTC()
	acquisitionID := runner.ids.NewID()
	run, resumed, err := runner.store.AcquireAssessmentCycleBackfillRun(ctx, ports.AssessmentCycleBackfillAcquireRequest{
		Run: ports.AssessmentCycleBackfillRun{
			TenantID: tenantID, ID: acquisitionID, SchemaVersion: AssessmentCycleBackfillSchemaVersion,
			DryRun: request.DryRun, BatchSize: batchSize, SnapshotAt: now, State: ports.AssessmentCycleBackfillRunning,
			LeaseOwner: leaseOwner, LeaseToken: acquisitionID, LeaseExpiresAt: now.Add(leaseDuration), CreatedBy: actor, CreatedAt: now, UpdatedAt: now,
		},
		InitialCheckpoint: request.ResumeAfter,
		LeaseDuration:     leaseDuration,
	})
	if err != nil {
		return ports.AssessmentCycleBackfillRun{}, err
	}
	runner.record(ctx, actor, "assessment_cycle.backfill_started", run.ID, map[string]string{
		"tenant_id": tenantID.String(), "dry_run": strconv.FormatBool(run.DryRun), "resumed": strconv.FormatBool(resumed), "batch_size": strconv.Itoa(run.BatchSize),
	})

	for {
		if err := ctx.Err(); err != nil {
			return runner.finish(ctx, run, leaseOwner, ports.AssessmentCycleBackfillCancelled, actor, err)
		}
		assessments, err := runner.source.ListAssessmentCycleBackfillEngagements(ctx, tenantID, run.CheckpointAssessment, run.SnapshotAt, run.BatchSize)
		if err != nil {
			return runner.finish(ctx, run, leaseOwner, ports.AssessmentCycleBackfillFailed, actor, err)
		}
		if len(assessments) == 0 {
			return runner.finish(ctx, run, leaseOwner, ports.AssessmentCycleBackfillCompleted, actor, nil)
		}
		if len(assessments) > run.BatchSize {
			return runner.finish(ctx, run, leaseOwner, ports.AssessmentCycleBackfillFailed, actor, fmt.Errorf("backfill source returned %d rows for limit %d", len(assessments), run.BatchSize))
		}
		for _, assessment := range assessments {
			if err := ctx.Err(); err != nil {
				return runner.finish(ctx, run, leaseOwner, ports.AssessmentCycleBackfillCancelled, actor, err)
			}
			if _, err := runner.store.GetAssessmentCycleBackfillItem(ctx, tenantID, run.ID, assessment.ID); err == nil {
				continue
			} else if !errors.Is(err, shared.ErrNotFound) {
				return runner.finish(ctx, run, leaseOwner, ports.AssessmentCycleBackfillFailed, actor, err)
			}
			item, created, err := runner.store.CommitAssessmentCycleBackfillItem(ctx, tenantID, run.ID, run.LeaseToken, runner.clock.Now().UTC(), func(txCtx context.Context) (ports.AssessmentCycleBackfillItem, error) {
				return runner.processItem(txCtx, run, assessment.ID, actor), nil
			})
			if err != nil {
				return runner.finish(ctx, run, leaseOwner, ports.AssessmentCycleBackfillFailed, actor, err)
			}
			if created && runner.observer != nil {
				runner.observer.ObserveAssessmentCycleBackfillItem(item.Outcome)
			}
		}
		checkpoint := assessments[len(assessments)-1].ID
		run, err = runner.store.AdvanceAssessmentCycleBackfillRun(ctx, tenantID, run.ID, leaseOwner, run.LeaseToken, checkpoint, runner.clock.Now().UTC(), leaseDuration)
		if err != nil {
			return runner.finish(ctx, run, leaseOwner, ports.AssessmentCycleBackfillFailed, actor, err)
		}
		runner.record(ctx, actor, "assessment_cycle.backfill_batch_committed", run.ID, map[string]string{
			"tenant_id": tenantID.String(), "checkpoint_assessment_id": checkpoint.String(), "processed_count": strconv.Itoa(run.ProcessedCount),
		})
	}
}

func (runner *BackfillRunner) processItem(ctx context.Context, run ports.AssessmentCycleBackfillRun, assessmentID shared.ID, actor string) ports.AssessmentCycleBackfillItem {
	item := ports.AssessmentCycleBackfillItem{
		TenantID: run.TenantID, RunID: run.ID, AssessmentID: assessmentID, SchemaVersion: run.SchemaVersion,
		IdempotencyKey: backfillIdempotencyKey(assessmentID, run.SchemaVersion), ProcessedAt: runner.clock.Now().UTC(),
	}
	var (
		result BackfillHistoricalSingletonResult
		err    error
	)
	for attempt := 0; attempt < assessmentCycleBackfillRetries; attempt++ {
		result, err = runner.backfiller.BackfillHistoricalSingleton(ctx, BackfillHistoricalSingletonInput{
			TenantID: run.TenantID, AssessmentID: assessmentID, SchemaVersion: run.SchemaVersion, Actor: actor, DryRun: run.DryRun,
		})
		if err == nil || !retryableBackfillError(err) {
			break
		}
	}
	if err != nil {
		item.Outcome, item.ReasonCode, item.Retryable, item.RepairGuidance = backfillFailure(err)
		return item
	}
	item.CycleID = result.CycleID
	switch {
	case result.Created:
		item.Outcome, item.ReasonCode = BackfillOutcomeCreated, BackfillReasonCreated
	case result.WouldCreate:
		item.Outcome, item.ReasonCode = BackfillOutcomeWouldCreate, BackfillReasonWouldCreate
	default:
		item.Outcome, item.ReasonCode = BackfillOutcomeSkipped, result.ReasonCode
	}
	return item
}

func (runner *BackfillRunner) finish(ctx context.Context, run ports.AssessmentCycleBackfillRun, leaseOwner string, state ports.AssessmentCycleBackfillState, actor string, cause error) (ports.AssessmentCycleBackfillRun, error) {
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	finished, err := runner.store.FinishAssessmentCycleBackfillRun(finishCtx, run.TenantID, run.ID, leaseOwner, run.LeaseToken, state, runner.clock.Now().UTC())
	if err != nil {
		if cause != nil {
			return run, errors.Join(cause, err)
		}
		return run, err
	}
	if runner.observer != nil {
		runner.observer.ObserveAssessmentCycleBackfillRun(string(state))
	}
	runner.record(finishCtx, actor, "assessment_cycle.backfill_"+string(state), run.ID, map[string]string{
		"tenant_id": run.TenantID.String(), "processed_count": strconv.Itoa(finished.ProcessedCount), "created_count": strconv.Itoa(finished.CreatedCount),
		"would_create_count": strconv.Itoa(finished.WouldCreateCount), "skipped_count": strconv.Itoa(finished.SkippedCount), "failed_count": strconv.Itoa(finished.FailedCount),
	})
	if cause != nil {
		return finished, cause
	}
	return finished, nil
}

func (runner *BackfillRunner) record(ctx context.Context, actor, action string, target shared.ID, metadata map[string]string) {
	if runner.audit != nil {
		_ = runner.audit.Record(ctx, ports.AuditEntry{Actor: actor, Action: action, Target: target.String(), Metadata: metadata, At: runner.clock.Now().UTC()})
	}
}

func retryableBackfillError(err error) bool {
	return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, shared.ErrValidation) && !errors.Is(err, shared.ErrNotFound) && !errors.Is(err, cycledom.ErrHiddenProjectContext)
}

func backfillFailure(err error) (outcome, reason string, retryable bool, guidance string) {
	switch {
	case errors.Is(err, cycledom.ErrHiddenProjectContext):
		return BackfillOutcomeSkipped, BackfillReasonHiddenContext, false, "No repair is required; hidden Project analysis contexts are ineligible."
	case errors.Is(err, shared.ErrNotFound):
		return BackfillOutcomeFailed, BackfillReasonSourceMissing, false, "Verify the source Assessment still exists in the tenant before rerunning."
	case errors.Is(err, shared.ErrValidation):
		return BackfillOutcomeFailed, BackfillReasonInvalidSource, false, "Correct the source Assessment boundary or lifecycle data before rerunning."
	default:
		return BackfillOutcomeFailed, BackfillReasonWriteFailed, true, "Retry after restoring database availability; run the integrity verifier before cutover."
	}
}

func backfillIdempotencyKey(assessmentID shared.ID, schemaVersion int) string {
	sum := sha256.Sum256([]byte(assessmentID.String() + "\x00" + strconv.Itoa(schemaVersion)))
	return "assessment-cycle-backfill-v" + strconv.Itoa(schemaVersion) + "-" + hex.EncodeToString(sum[:])
}
