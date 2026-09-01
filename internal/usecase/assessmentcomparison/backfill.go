package assessmentcomparison

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcomparison"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	DefaultComparisonBackfillBatch     = 500
	MaxComparisonBackfillBatch         = 2000
	DefaultComparisonBacklogWarning    = 500
	DefaultComparisonBacklogHardLimit  = 1000
	DefaultComparisonOldestActiveLimit = 15 * time.Minute
	DefaultComparisonRepairMaxAttempts = DefaultMaxAttempts
)

var (
	ErrComparisonBacklogHardLimit = errors.New("assessment comparison backlog hard limit reached")
	ErrComparisonOldestActive     = errors.New("assessment comparison oldest active job limit exceeded")
)

type comparisonBackfillService interface {
	Queue(context.Context, QueueInput) (domain.Comparison, bool, domain.PairDecision, error)
	Repair(context.Context, WorkInput) (domain.Comparison, error)
}

type BackfillRunner struct {
	service     comparisonBackfillService
	cycles      ports.AssessmentCycleListRepository
	comparisons ports.AssessmentComparisonRepairRepository
	clock       ports.Clock
	audit       ports.AuditLogger
}

type BackfillRequest struct {
	TenantID          shared.ID
	Actor             string
	DryRun            bool
	RepairFailed      bool
	BatchSize         int
	BacklogWarning    int
	BacklogHardLimit  int
	OldestActiveLimit time.Duration
	AfterUpdatedAt    time.Time
	AfterCycleID      shared.ID
}

type BackfillResult struct {
	Processed           int
	Queued              int
	Existing            int
	WouldQueue          int
	Skipped             int
	RepairAttempted     int
	Repaired            int
	WouldRepair         int
	BacklogWarning      bool
	CheckpointUpdatedAt time.Time
	CheckpointCycleID   shared.ID
	Backlog             ports.AssessmentComparisonBacklog
}

func NewBackfillRunner(service comparisonBackfillService, cycles ports.AssessmentCycleListRepository, comparisons ports.AssessmentComparisonRepairRepository, clock ports.Clock, audit ports.AuditLogger) (*BackfillRunner, error) {
	if service == nil || cycles == nil || comparisons == nil || clock == nil || audit == nil {
		return nil, fmt.Errorf("%w: assessment comparison backfill dependencies are required", shared.ErrValidation)
	}
	return &BackfillRunner{service: service, cycles: cycles, comparisons: comparisons, clock: clock, audit: audit}, nil
}

func (runner *BackfillRunner) Run(ctx context.Context, request BackfillRequest) (BackfillResult, error) {
	if err := normalizeBackfillRequest(&request); err != nil {
		return BackfillResult{}, err
	}
	result := BackfillResult{CheckpointUpdatedAt: request.AfterUpdatedAt, CheckpointCycleID: request.AfterCycleID}
	backlog, err := runner.comparisons.GetAssessmentComparisonBacklog(ctx, request.TenantID)
	if err != nil {
		return result, err
	}
	if err := enforceComparisonBacklog(backlog, request, runner.clock.Now().UTC()); err != nil {
		return result, err
	}

	if request.RepairFailed {
		failed, err := runner.comparisons.ListFailedAssessmentComparisons(ctx, request.TenantID, request.BatchSize)
		if err != nil {
			return result, err
		}
		for _, candidate := range failed {
			result.RepairAttempted++
			if request.DryRun {
				result.WouldRepair++
				continue
			}
			repaired, err := runner.service.Repair(ctx, WorkInput{
				TenantID: request.TenantID, ComparisonID: candidate.ID, Actor: request.Actor, MaxAttempts: DefaultComparisonRepairMaxAttempts,
			})
			if err != nil {
				return result, fmt.Errorf("repair assessment comparison %s: %w", candidate.ID, err)
			}
			readback, err := runner.comparisons.GetMetadata(ctx, request.TenantID, candidate.ID)
			if err != nil {
				return result, fmt.Errorf("read back repaired assessment comparison %s: %w", candidate.ID, err)
			}
			if repaired.ID != candidate.ID || readback.ID != candidate.ID || readback.InputHash != candidate.InputHash || readback.BaselineSnapshotID != candidate.BaselineSnapshotID || readback.CurrentSnapshotID != candidate.CurrentSnapshotID {
				return result, fmt.Errorf("%w: repaired assessment comparison %s changed immutable projection identity", shared.ErrConflict, candidate.ID)
			}
			result.Repaired++
		}
	}

	for {
		backlog, err = runner.comparisons.GetAssessmentComparisonBacklog(ctx, request.TenantID)
		if err != nil {
			return result, err
		}
		if err := enforceComparisonBacklog(backlog, request, runner.clock.Now().UTC()); err != nil {
			return result, err
		}
		records, err := runner.cycles.ListCycles(ctx, ports.AssessmentCycleListQuery{
			TenantID: request.TenantID, Limit: request.BatchSize, MemberLimit: 1,
			AfterUpdatedAt: result.CheckpointUpdatedAt, AfterCycleID: result.CheckpointCycleID,
		})
		if err != nil {
			return result, err
		}
		if len(records) == 0 {
			break
		}
		active := backlog.Active()
		for _, record := range records {
			result.Processed++
			if record.RootSnapshotID.IsZero() || record.CurrentSnapshotID.IsZero() || record.RootSnapshotID == record.CurrentSnapshotID {
				result.Skipped++
				continue
			}
			if request.DryRun {
				result.WouldQueue++
				continue
			}
			if active >= request.BacklogHardLimit {
				return result, fmt.Errorf("%w: tenant %s has %d queued or generating comparisons", ErrComparisonBacklogHardLimit, request.TenantID, active)
			}
			comparison, created, decision, err := runner.service.Queue(ctx, QueueInput{
				TenantID: request.TenantID, BaselineSnapshotID: record.RootSnapshotID, CurrentSnapshotID: record.CurrentSnapshotID,
				Mode: domain.ModeLifecycle, FingerprintVersion: 1, RiskModelVersion: RiskModelVersionV1, Actor: request.Actor,
			})
			if err != nil {
				return result, fmt.Errorf("queue lifecycle comparison for cycle %s: %w", record.Cycle.ID, err)
			}
			if !decision.Allowed {
				result.Skipped++
				continue
			}
			if comparison.ID.IsZero() {
				return result, fmt.Errorf("%w: queued lifecycle comparison for cycle %s has no id", shared.ErrConflict, record.Cycle.ID)
			}
			if created {
				result.Queued++
				active++
			} else {
				result.Existing++
			}
		}
		last := records[len(records)-1].Cycle
		result.CheckpointUpdatedAt, result.CheckpointCycleID = last.UpdatedAt.UTC(), last.ID
		if err := runner.recordBatch(ctx, request, result); err != nil {
			return result, err
		}
		if len(records) < request.BatchSize {
			break
		}
	}

	result.Backlog, err = runner.comparisons.GetAssessmentComparisonBacklog(ctx, request.TenantID)
	if err != nil {
		return result, err
	}
	result.BacklogWarning = result.Backlog.Active() >= request.BacklogWarning
	return result, nil
}

func normalizeBackfillRequest(request *BackfillRequest) error {
	request.TenantID = shared.TenantOrDefault(request.TenantID)
	request.Actor = strings.TrimSpace(request.Actor)
	if request.BatchSize == 0 {
		request.BatchSize = DefaultComparisonBackfillBatch
	}
	if request.BacklogWarning == 0 {
		request.BacklogWarning = DefaultComparisonBacklogWarning
	}
	if request.BacklogHardLimit == 0 {
		request.BacklogHardLimit = DefaultComparisonBacklogHardLimit
	}
	if request.OldestActiveLimit == 0 {
		request.OldestActiveLimit = DefaultComparisonOldestActiveLimit
	}
	if request.TenantID.IsZero() || request.Actor == "" || len(request.Actor) > 256 || request.BatchSize < 1 || request.BatchSize > MaxComparisonBackfillBatch || request.BacklogWarning < 1 || request.BacklogHardLimit < request.BacklogWarning || request.BacklogHardLimit > DefaultComparisonBacklogHardLimit || request.OldestActiveLimit <= 0 {
		return fmt.Errorf("%w: assessment comparison backfill request is invalid", shared.ErrValidation)
	}
	if request.AfterUpdatedAt.IsZero() != request.AfterCycleID.IsZero() {
		return fmt.Errorf("%w: assessment comparison backfill cursor requires updated time and cycle id", shared.ErrValidation)
	}
	request.AfterUpdatedAt = request.AfterUpdatedAt.UTC()
	return nil
}

func enforceComparisonBacklog(backlog ports.AssessmentComparisonBacklog, request BackfillRequest, now time.Time) error {
	if backlog.Active() >= request.BacklogHardLimit {
		return fmt.Errorf("%w: tenant %s has %d queued or generating comparisons", ErrComparisonBacklogHardLimit, request.TenantID, backlog.Active())
	}
	if backlog.OldestActiveAt != nil && now.Sub(backlog.OldestActiveAt.UTC()) > request.OldestActiveLimit {
		return fmt.Errorf("%w: tenant %s oldest active comparison is %s", ErrComparisonOldestActive, request.TenantID, now.Sub(backlog.OldestActiveAt.UTC()).Round(time.Second))
	}
	return nil
}

func (runner *BackfillRunner) recordBatch(ctx context.Context, request BackfillRequest, result BackfillResult) error {
	return runner.audit.Record(ctx, ports.AuditEntry{
		Actor: request.Actor, Action: "assessment_comparison.backfill_batch", Target: request.TenantID.String(), At: runner.clock.Now().UTC(),
		Metadata: map[string]string{
			"tenant_id": request.TenantID.String(), "dry_run": strconv.FormatBool(request.DryRun),
			"processed": strconv.Itoa(result.Processed), "queued": strconv.Itoa(result.Queued), "existing": strconv.Itoa(result.Existing),
			"would_queue": strconv.Itoa(result.WouldQueue), "skipped": strconv.Itoa(result.Skipped), "repaired": strconv.Itoa(result.Repaired), "would_repair": strconv.Itoa(result.WouldRepair),
			"checkpoint_updated_at": result.CheckpointUpdatedAt.Format(time.RFC3339Nano), "checkpoint_cycle_id": result.CheckpointCycleID.String(),
		},
	})
}
