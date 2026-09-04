package assessmentsnapshot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	AssessmentSnapshotBackfillSchemaVersion = 1
	DefaultAssessmentSnapshotBackfillBatch  = 500
	MaxAssessmentSnapshotBackfillBatch      = 2000
	assessmentSnapshotBackfillRetries       = 3
	defaultAssessmentSnapshotBackfillLease  = 10 * time.Minute
)

const (
	SnapshotBackfillOutcomeCreated     = "created"
	SnapshotBackfillOutcomeWouldCreate = "would_create"
	SnapshotBackfillOutcomeSkipped     = "skipped"
	SnapshotBackfillOutcomeFailed      = "failed"

	SnapshotBackfillReasonCreated               = "created"
	SnapshotBackfillReasonWouldCreate           = "would_create"
	SnapshotBackfillReasonAlreadyProjected      = "already_projected"
	SnapshotBackfillReasonCycleMissing          = "cycle_not_found"
	SnapshotBackfillReasonScanRunMissing        = "scan_run_not_found"
	SnapshotBackfillReasonVerifiedRunMissing    = "verified_run_unavailable"
	SnapshotBackfillReasonInvalidSource         = "invalid_source"
	SnapshotBackfillReasonSourceReadFailed      = "source_read_failed"
	SnapshotBackfillReasonProjectionWriteFailed = "projection_write_failed"
)

type LegacyProjector struct {
	snapshots ports.AssessmentSnapshotRepository
	cycles    ports.AssessmentCycleRepository
	tx        ports.TenantTransactionRunner
	ids       ports.IDGenerator
	clock     ports.Clock
	audit     ports.AuditLogger
}

func NewLegacyProjector(snapshots ports.AssessmentSnapshotRepository, cycles ports.AssessmentCycleRepository, tx ports.TenantTransactionRunner, ids ports.IDGenerator, clock ports.Clock, audit ports.AuditLogger) (*LegacyProjector, error) {
	if snapshots == nil || cycles == nil || tx == nil || ids == nil || clock == nil || audit == nil {
		return nil, fmt.Errorf("%w: legacy assessment snapshot projector dependencies are required", shared.ErrValidation)
	}
	return &LegacyProjector{snapshots: snapshots, cycles: cycles, tx: tx, ids: ids, clock: clock, audit: audit}, nil
}

type LegacyProjectionInput struct {
	TenantID     shared.ID
	AssessmentID shared.ID
	Actor        string
	SourceHash   string
	SelectedRun  domain.SelectedRun
	DryRun       bool
}

type LegacyProjectionResult struct {
	SnapshotID  shared.ID
	Created     bool
	WouldCreate bool
	ReasonCode  string
}

func (projector *LegacyProjector) Project(ctx context.Context, input LegacyProjectionInput) (LegacyProjectionResult, error) {
	tenantID, actor := shared.TenantOrDefault(input.TenantID), strings.TrimSpace(input.Actor)
	if tenantID.IsZero() || input.AssessmentID.IsZero() || actor == "" || len(actor) > 256 || !validSnapshotBackfillHash(input.SourceHash) {
		return LegacyProjectionResult{}, fmt.Errorf("%w: legacy assessment snapshot projection input is invalid", shared.ErrValidation)
	}
	requestKey := legacyProjectionRequestKey(input.SourceHash)
	if existing, err := projector.snapshots.GetByRequestKey(ctx, tenantID, input.AssessmentID, requestKey); err == nil {
		return LegacyProjectionResult{SnapshotID: existing.ID, ReasonCode: SnapshotBackfillReasonAlreadyProjected}, nil
	} else if !errors.Is(err, shared.ErrNotFound) {
		return LegacyProjectionResult{}, err
	}
	cycle, err := projector.cycles.GetCycleByAssessment(ctx, tenantID, input.AssessmentID)
	if errors.Is(err, shared.ErrNotFound) {
		return LegacyProjectionResult{ReasonCode: SnapshotBackfillReasonCycleMissing}, nil
	}
	if err != nil {
		return LegacyProjectionResult{}, err
	}
	if _, err := projector.cycles.GetMember(ctx, tenantID, cycle.ID, input.AssessmentID); errors.Is(err, shared.ErrNotFound) {
		return LegacyProjectionResult{ReasonCode: SnapshotBackfillReasonCycleMissing}, nil
	} else if err != nil {
		return LegacyProjectionResult{}, err
	}
	if input.DryRun {
		return LegacyProjectionResult{WouldCreate: true, ReasonCode: SnapshotBackfillReasonWouldCreate}, nil
	}

	var result LegacyProjectionResult
	err = projector.tx.Run(ctx, tenantID, func(txCtx context.Context) error {
		locked, err := projector.cycles.LockCycleForUpdate(txCtx, tenantID, cycle.ID)
		if err != nil {
			return err
		}
		if _, err := projector.cycles.GetMember(txCtx, tenantID, locked.ID, input.AssessmentID); err != nil {
			return err
		}
		now := projector.clock.Now().UTC()
		candidate, err := domain.NewFinalized(tenantID, projector.ids.NewID(), locked.ID, input.AssessmentID, domain.Boundary{
			Kind: locked.BoundaryKind, BusinessAssetID: locked.BusinessAssetID, ProjectID: locked.ProjectID,
		}, requestKey, actor, now, []domain.SelectedRun{input.SelectedRun})
		if err != nil {
			return err
		}
		if candidate.Provenance != domain.ProvenanceLegacy {
			return fmt.Errorf("%w: projected assessment snapshot must remain legacy", shared.ErrValidation)
		}
		candidate.RequestHash = legacyProjectionRequestHash(input.SourceHash, candidate.ContentHash)
		stored, created, err := projector.snapshots.CreateLegacyProjection(txCtx, candidate)
		if err != nil {
			return err
		}
		result.SnapshotID = stored.ID
		if !created {
			result.ReasonCode = SnapshotBackfillReasonAlreadyProjected
			return nil
		}
		result.Created, result.ReasonCode = true, SnapshotBackfillReasonCreated
		if err := projector.audit.Record(txCtx, ports.AuditEntry{
			Actor: actor, Action: "assessment_snapshot.legacy_projected", Target: stored.ID.String(), At: now,
			Metadata: map[string]string{
				"tenant_id": tenantID.String(), "cycle_id": locked.ID.String(), "assessment_id": input.AssessmentID.String(),
				"source_hash": input.SourceHash, "content_hash": stored.ContentHash, "snapshot_number": strconv.Itoa(stored.SnapshotNumber),
			},
		}); err != nil {
			return fmt.Errorf("audit legacy assessment snapshot projection: %w", err)
		}
		return nil
	})
	return result, err
}

type legacySnapshotProjector interface {
	Project(context.Context, LegacyProjectionInput) (LegacyProjectionResult, error)
}

type AssessmentSnapshotBackfillObserver interface {
	ObserveAssessmentSnapshotBackfillItem(outcome string)
	ObserveAssessmentSnapshotBackfillRun(state string)
}

type BackfillRunner struct {
	projector legacySnapshotProjector
	source    ports.AssessmentSnapshotBackfillSource
	store     ports.AssessmentSnapshotBackfillStore
	runs      ports.AssessmentSnapshotRunReader
	results   ports.ScanResultStore
	ids       ports.IDGenerator
	clock     ports.Clock
	audit     ports.AuditLogger
	observer  AssessmentSnapshotBackfillObserver
}

func NewBackfillRunner(projector legacySnapshotProjector, source ports.AssessmentSnapshotBackfillSource, store ports.AssessmentSnapshotBackfillStore, runs ports.AssessmentSnapshotRunReader, results ports.ScanResultStore, ids ports.IDGenerator, clock ports.Clock, audit ports.AuditLogger, observer AssessmentSnapshotBackfillObserver) (*BackfillRunner, error) {
	if projector == nil || source == nil || store == nil || runs == nil || results == nil || ids == nil || clock == nil {
		return nil, fmt.Errorf("%w: assessment snapshot backfill dependencies are required", shared.ErrValidation)
	}
	return &BackfillRunner{projector: projector, source: source, store: store, runs: runs, results: results, ids: ids, clock: clock, audit: audit, observer: observer}, nil
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

func (runner *BackfillRunner) Run(ctx context.Context, request BackfillRequest) (ports.AssessmentSnapshotBackfillRun, error) {
	tenantID := shared.TenantOrDefault(request.TenantID)
	actor, leaseOwner := strings.TrimSpace(request.Actor), strings.TrimSpace(request.LeaseOwner)
	if tenantID.IsZero() || actor == "" || len(actor) > 256 || leaseOwner == "" || len(leaseOwner) > 256 {
		return ports.AssessmentSnapshotBackfillRun{}, fmt.Errorf("%w: tenant, actor, and lease owner are required", shared.ErrValidation)
	}
	batchSize := request.BatchSize
	if batchSize == 0 {
		batchSize = DefaultAssessmentSnapshotBackfillBatch
	}
	if batchSize < 1 || batchSize > MaxAssessmentSnapshotBackfillBatch {
		return ports.AssessmentSnapshotBackfillRun{}, fmt.Errorf("%w: batch size must be between 1 and %d", shared.ErrValidation, MaxAssessmentSnapshotBackfillBatch)
	}
	leaseDuration := request.LeaseDuration
	if leaseDuration <= 0 {
		leaseDuration = defaultAssessmentSnapshotBackfillLease
	}
	now := runner.clock.Now().UTC()
	acquisitionID := runner.ids.NewID()
	run, resumed, err := runner.store.AcquireAssessmentSnapshotBackfillRun(ctx, ports.AssessmentSnapshotBackfillAcquireRequest{
		Run: ports.AssessmentSnapshotBackfillRun{
			TenantID: tenantID, ID: acquisitionID, SchemaVersion: AssessmentSnapshotBackfillSchemaVersion,
			DryRun: request.DryRun, BatchSize: batchSize, SnapshotAt: now, State: ports.AssessmentSnapshotBackfillRunning,
			LeaseOwner: leaseOwner, LeaseToken: acquisitionID, LeaseExpiresAt: now.Add(leaseDuration), CreatedBy: actor, CreatedAt: now, UpdatedAt: now,
		},
		InitialCheckpoint: request.ResumeAfter,
		LeaseDuration:     leaseDuration,
	})
	if err != nil {
		return ports.AssessmentSnapshotBackfillRun{}, err
	}
	runner.record(ctx, actor, "assessment_snapshot.backfill_started", run.ID, map[string]string{
		"tenant_id": tenantID.String(), "dry_run": strconv.FormatBool(run.DryRun), "resumed": strconv.FormatBool(resumed), "batch_size": strconv.Itoa(run.BatchSize),
	})

	for {
		if err := ctx.Err(); err != nil {
			return runner.finish(ctx, run, leaseOwner, ports.AssessmentSnapshotBackfillCancelled, actor, err)
		}
		assessments, err := runner.source.ListAssessmentSnapshotBackfillEngagements(ctx, tenantID, run.CheckpointAssessment, run.SnapshotAt, run.BatchSize)
		if err != nil {
			return runner.finish(ctx, run, leaseOwner, snapshotBackfillTerminalState(err), actor, err)
		}
		if len(assessments) == 0 {
			return runner.finish(ctx, run, leaseOwner, ports.AssessmentSnapshotBackfillCompleted, actor, nil)
		}
		if len(assessments) > run.BatchSize {
			return runner.finish(ctx, run, leaseOwner, ports.AssessmentSnapshotBackfillFailed, actor, fmt.Errorf("backfill source returned %d rows for limit %d", len(assessments), run.BatchSize))
		}
		for _, assessment := range assessments {
			if err := ctx.Err(); err != nil {
				return runner.finish(ctx, run, leaseOwner, ports.AssessmentSnapshotBackfillCancelled, actor, err)
			}
			if _, err := runner.store.GetAssessmentSnapshotBackfillItem(ctx, tenantID, run.ID, assessment.ID); err == nil {
				continue
			} else if !errors.Is(err, shared.ErrNotFound) {
				return runner.finish(ctx, run, leaseOwner, snapshotBackfillTerminalState(err), actor, err)
			}
			item, created, err := runner.store.CommitAssessmentSnapshotBackfillItem(ctx, tenantID, run.ID, run.LeaseToken, runner.clock.Now().UTC(), func(txCtx context.Context) (ports.AssessmentSnapshotBackfillItem, error) {
				return runner.processItem(txCtx, run, assessment.ID, actor), nil
			})
			if err != nil {
				return runner.finish(ctx, run, leaseOwner, snapshotBackfillTerminalState(err), actor, err)
			}
			if created && runner.observer != nil {
				runner.observer.ObserveAssessmentSnapshotBackfillItem(item.Outcome)
			}
		}
		checkpoint := assessments[len(assessments)-1].ID
		run, err = runner.store.AdvanceAssessmentSnapshotBackfillRun(ctx, tenantID, run.ID, leaseOwner, run.LeaseToken, checkpoint, runner.clock.Now().UTC(), leaseDuration)
		if err != nil {
			return runner.finish(ctx, run, leaseOwner, snapshotBackfillTerminalState(err), actor, err)
		}
		runner.record(ctx, actor, "assessment_snapshot.backfill_batch_committed", run.ID, map[string]string{
			"tenant_id": tenantID.String(), "checkpoint_assessment_id": checkpoint.String(), "processed_count": strconv.Itoa(run.ProcessedCount),
		})
	}
}

type projectionSource struct {
	selected   domain.SelectedRun
	sourceHash string
	reasonCode string
}

func (runner *BackfillRunner) processItem(ctx context.Context, run ports.AssessmentSnapshotBackfillRun, assessmentID shared.ID, actor string) ports.AssessmentSnapshotBackfillItem {
	source, sourceErr := runner.loadProjectionSource(ctx, run, assessmentID)
	if source.sourceHash == "" {
		source.sourceHash = fallbackProjectionSourceHash(assessmentID, run.SchemaVersion)
	}
	item := ports.AssessmentSnapshotBackfillItem{
		TenantID: run.TenantID, RunID: run.ID, AssessmentID: assessmentID, SchemaVersion: run.SchemaVersion,
		IdempotencyKey: snapshotBackfillIdempotencyKey(assessmentID, run.SchemaVersion, source.sourceHash), SourceHash: source.sourceHash,
		ProcessedAt: runner.clock.Now().UTC(),
	}
	if sourceErr != nil {
		item.Outcome, item.ReasonCode, item.Retryable, item.RepairGuidance = snapshotBackfillFailure(sourceErr, true)
		return item
	}
	if source.reasonCode != "" {
		item.Outcome, item.ReasonCode = SnapshotBackfillOutcomeSkipped, source.reasonCode
		return item
	}
	var (
		result LegacyProjectionResult
		err    error
	)
	for attempt := 0; attempt < assessmentSnapshotBackfillRetries; attempt++ {
		result, err = runner.projector.Project(ctx, LegacyProjectionInput{
			TenantID: run.TenantID, AssessmentID: assessmentID, Actor: actor, SourceHash: source.sourceHash,
			SelectedRun: source.selected, DryRun: run.DryRun,
		})
		if err == nil || !retryableAssessmentSnapshotBackfillError(err) {
			break
		}
	}
	if err != nil {
		item.Outcome, item.ReasonCode, item.Retryable, item.RepairGuidance = snapshotBackfillFailure(err, false)
		return item
	}
	item.SnapshotID = result.SnapshotID
	switch {
	case result.Created:
		item.Outcome, item.ReasonCode = SnapshotBackfillOutcomeCreated, SnapshotBackfillReasonCreated
	case result.WouldCreate:
		item.Outcome, item.ReasonCode = SnapshotBackfillOutcomeWouldCreate, SnapshotBackfillReasonWouldCreate
	default:
		item.Outcome, item.ReasonCode = SnapshotBackfillOutcomeSkipped, result.ReasonCode
	}
	return item
}

func (runner *BackfillRunner) loadProjectionSource(ctx context.Context, run ports.AssessmentSnapshotBackfillRun, assessmentID shared.ID) (projectionSource, error) {
	resultData, resultErr := runner.results.LatestResult(ctx, assessmentID)
	if resultErr != nil && !errors.Is(resultErr, shared.ErrNotFound) {
		return projectionSource{}, resultErr
	}
	resultHash := ""
	if resultErr == nil {
		// ponytail: scan_results is source evidence only, so raw stored bytes are sufficient here;
		// switch to canonical JSON hashing if a second storage representation participates.
		sum := sha256.Sum256(resultData)
		resultHash = hex.EncodeToString(sum[:])
	}
	runs, err := runner.runs.ListScanRuns(ctx, run.TenantID, assessmentID)
	if err != nil {
		return projectionSource{}, err
	}
	eligible := make([]scanrun.ScanRun, 0, len(runs))
	for _, candidate := range runs {
		if !candidate.CreatedAt.After(run.SnapshotAt) {
			eligible = append(eligible, candidate)
		}
	}
	if len(eligible) == 0 {
		return projectionSource{sourceHash: projectionSourceHash(assessmentID, run.SchemaVersion, "", "", resultHash), reasonCode: SnapshotBackfillReasonScanRunMissing}, nil
	}
	for _, candidate := range eligible {
		if candidate.Provenance != scanrun.ProvenanceNative || validateTrustedScanRun(candidate) != nil {
			continue
		}
		if err := validateProjectionRun(candidate, run.TenantID, assessmentID); err != nil {
			return projectionSource{}, err
		}
		return projectionSource{
			selected:   domain.SelectedRun{ID: candidate.ID, ManifestHash: candidate.ManifestHash, Provenance: scanrun.ProvenanceLegacy, TerminalStatus: candidate.TerminalStatus, Lanes: candidate.Lanes},
			sourceHash: projectionSourceHash(assessmentID, run.SchemaVersion, candidate.ID, candidate.ManifestHash, resultHash),
		}, nil
	}
	for _, candidate := range eligible {
		if candidate.Provenance != scanrun.ProvenanceLegacy {
			continue
		}
		if err := validateProjectionRun(candidate, run.TenantID, assessmentID); err != nil {
			return projectionSource{}, err
		}
		hash := legacyRunHash(candidate)
		return projectionSource{
			selected:   domain.SelectedRun{ID: candidate.ID, ManifestHash: hash, Provenance: scanrun.ProvenanceLegacy, TerminalStatus: candidate.TerminalStatus, Lanes: candidate.Lanes},
			sourceHash: projectionSourceHash(assessmentID, run.SchemaVersion, candidate.ID, hash, resultHash),
		}, nil
	}
	return projectionSource{sourceHash: projectionSourceHash(assessmentID, run.SchemaVersion, "", "", resultHash), reasonCode: SnapshotBackfillReasonVerifiedRunMissing}, nil
}

func validateProjectionRun(run scanrun.ScanRun, tenantID, assessmentID shared.ID) error {
	if strings.TrimSpace(run.ID) == "" || run.TenantID != tenantID || run.EngagementID != assessmentID || run.CreatedAt.IsZero() {
		return fmt.Errorf("%w: assessment snapshot projection run ownership is invalid", shared.ErrValidation)
	}
	return nil
}

func (runner *BackfillRunner) finish(ctx context.Context, run ports.AssessmentSnapshotBackfillRun, leaseOwner string, state ports.AssessmentSnapshotBackfillState, actor string, cause error) (ports.AssessmentSnapshotBackfillRun, error) {
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	finished, err := runner.store.FinishAssessmentSnapshotBackfillRun(finishCtx, run.TenantID, run.ID, leaseOwner, run.LeaseToken, state, runner.clock.Now().UTC())
	if err != nil {
		if cause != nil {
			return run, errors.Join(cause, err)
		}
		return run, err
	}
	if runner.observer != nil {
		runner.observer.ObserveAssessmentSnapshotBackfillRun(string(state))
	}
	runner.record(finishCtx, actor, "assessment_snapshot.backfill_"+string(state), run.ID, map[string]string{
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

func retryableAssessmentSnapshotBackfillError(err error) bool {
	return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, shared.ErrValidation) && !errors.Is(err, shared.ErrNotFound) && !errors.Is(err, shared.ErrConflict)
}

func snapshotBackfillTerminalState(err error) ports.AssessmentSnapshotBackfillState {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return ports.AssessmentSnapshotBackfillCancelled
	}
	return ports.AssessmentSnapshotBackfillFailed
}

func snapshotBackfillFailure(err error, sourceRead bool) (outcome, reason string, retryable bool, guidance string) {
	switch {
	case errors.Is(err, shared.ErrValidation):
		return SnapshotBackfillOutcomeFailed, SnapshotBackfillReasonInvalidSource, false, "Correct the owned scan-run provenance before rerunning the projection."
	case errors.Is(err, shared.ErrNotFound):
		return SnapshotBackfillOutcomeSkipped, SnapshotBackfillReasonCycleMissing, false, "Run the singleton-Cycle backfill before rerunning the Snapshot projection."
	case sourceRead:
		return SnapshotBackfillOutcomeFailed, SnapshotBackfillReasonSourceReadFailed, true, "Retry after restoring source repository availability; source evidence is never copied into failure records."
	default:
		return SnapshotBackfillOutcomeFailed, SnapshotBackfillReasonProjectionWriteFailed, true, "Retry after restoring database availability; verify Snapshot integrity before cutover."
	}
}

func legacyProjectionRequestKey(sourceHash string) string {
	return "assessment-snapshot-backfill-v1-" + sourceHash
}

func legacyProjectionRequestHash(sourceHash, contentHash string) string {
	sum := sha256.Sum256([]byte(sourceHash + "\x00" + contentHash))
	return hex.EncodeToString(sum[:])
}

func projectionSourceHash(assessmentID shared.ID, schemaVersion int, runID, runHash, resultHash string) string {
	payload, _ := json.Marshal(struct {
		AssessmentID string `json:"assessment_id"`
		ResultHash   string `json:"result_hash"`
		RunHash      string `json:"run_hash"`
		RunID        string `json:"run_id"`
		Schema       int    `json:"schema_version"`
	}{assessmentID.String(), resultHash, runHash, runID, schemaVersion})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func fallbackProjectionSourceHash(assessmentID shared.ID, schemaVersion int) string {
	return projectionSourceHash(assessmentID, schemaVersion, "", "", "")
}

func snapshotBackfillIdempotencyKey(assessmentID shared.ID, schemaVersion int, sourceHash string) string {
	sum := sha256.Sum256([]byte(assessmentID.String() + "\x00" + strconv.Itoa(schemaVersion) + "\x00" + sourceHash))
	return "assessment-snapshot-backfill-v" + strconv.Itoa(schemaVersion) + "-" + hex.EncodeToString(sum[:])
}

func validSnapshotBackfillHash(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
