package assessmentcomparison

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcomparison"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestBackfillRunnerQueuesPagesAndHonorsBacklogWarning(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	repository := &backfillRepository{backlog: ports.AssessmentComparisonBacklog{Queued: 499}, metadata: map[shared.ID]domain.Comparison{}}
	service := &backfillService{repository: repository, existingCurrent: "current-1"}
	cycles := &backfillCycleLister{records: []ports.AssessmentCycleListRecord{
		backfillCycle("cycle-3", "root-3", "current-3", now.Add(3*time.Minute)),
		backfillCycle("cycle-2", "same-2", "same-2", now.Add(2*time.Minute)),
		backfillCycle("cycle-1", "root-1", "current-1", now.Add(time.Minute)),
	}}
	runner, err := NewBackfillRunner(service, cycles, repository, fixedComparisonClock{now: now}, &backfillAudit{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(context.Background(), BackfillRequest{TenantID: "tenant-a", Actor: "operator", BatchSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	if result.Processed != 3 || result.Queued != 1 || result.Existing != 1 || result.Skipped != 1 || !result.BacklogWarning || result.Backlog.Active() != 500 || result.CheckpointCycleID != "cycle-1" {
		t.Fatalf("unexpected backfill result: %+v", result)
	}
	if cycles.calls != 2 {
		t.Fatalf("expected two cycle pages, got %d", cycles.calls)
	}
}

func TestBackfillRunnerRepairsWithImmutableReadback(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	failed := domain.Comparison{TenantID: "tenant-a", ID: "comparison-1", BaselineSnapshotID: "root-1", CurrentSnapshotID: "current-1", InputHash: "input-hash", Status: domain.StatusFailed, UpdatedAt: now}
	repository := &backfillRepository{failed: []domain.Comparison{failed}, metadata: map[shared.ID]domain.Comparison{failed.ID: failed}}
	service := &backfillService{repository: repository}
	runner, err := NewBackfillRunner(service, &backfillCycleLister{}, repository, fixedComparisonClock{now: now}, &backfillAudit{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(context.Background(), BackfillRequest{TenantID: "tenant-a", Actor: "operator", RepairFailed: true, BatchSize: 500})
	if err != nil {
		t.Fatal(err)
	}
	if result.RepairAttempted != 1 || result.Repaired != 1 || service.repairs != 1 {
		t.Fatalf("unexpected repair result: %+v repairs=%d", result, service.repairs)
	}
}

func TestBackfillRunnerStopsAtHardAndAgeGates(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	for name, testCase := range map[string]struct {
		backlog ports.AssessmentComparisonBacklog
		want    error
	}{
		"hard": {backlog: ports.AssessmentComparisonBacklog{Queued: 1000}, want: ErrComparisonBacklogHardLimit},
		"age":  {backlog: ports.AssessmentComparisonBacklog{Queued: 1, OldestActiveAt: timePointer(now.Add(-16 * time.Minute))}, want: ErrComparisonOldestActive},
	} {
		t.Run(name, func(t *testing.T) {
			repository := &backfillRepository{backlog: testCase.backlog, metadata: map[shared.ID]domain.Comparison{}}
			runner, err := NewBackfillRunner(&backfillService{repository: repository}, &backfillCycleLister{}, repository, fixedComparisonClock{now: now}, &backfillAudit{})
			if err != nil {
				t.Fatal(err)
			}
			_, err = runner.Run(context.Background(), BackfillRequest{TenantID: "tenant-a", Actor: "operator"})
			if !errors.Is(err, testCase.want) {
				t.Fatalf("error=%v want=%v", err, testCase.want)
			}
		})
	}
}

type backfillService struct {
	repository      *backfillRepository
	existingCurrent shared.ID
	repairs         int
	nextID          int
}

func (service *backfillService) Queue(_ context.Context, input QueueInput) (domain.Comparison, bool, domain.PairDecision, error) {
	service.nextID++
	comparison := domain.Comparison{ID: shared.ID(fmt.Sprintf("comparison-%d", service.nextID)), BaselineSnapshotID: input.BaselineSnapshotID, CurrentSnapshotID: input.CurrentSnapshotID}
	if input.CurrentSnapshotID == service.existingCurrent {
		return comparison, false, domain.PairDecision{Allowed: true}, nil
	}
	service.repository.backlog.Queued++
	return comparison, true, domain.PairDecision{Allowed: true}, nil
}

func (service *backfillService) Repair(_ context.Context, input WorkInput) (domain.Comparison, error) {
	service.repairs++
	comparison := service.repository.metadata[input.ComparisonID]
	comparison.Status = domain.StatusComplete
	service.repository.metadata[input.ComparisonID] = comparison
	return comparison, nil
}

type backfillRepository struct {
	backlog  ports.AssessmentComparisonBacklog
	failed   []domain.Comparison
	metadata map[shared.ID]domain.Comparison
}

func (repository *backfillRepository) GetAssessmentComparisonBacklog(context.Context, shared.ID) (ports.AssessmentComparisonBacklog, error) {
	return repository.backlog, nil
}

func (repository *backfillRepository) ListFailedAssessmentComparisons(_ context.Context, _ shared.ID, limit int) ([]domain.Comparison, error) {
	failed := append([]domain.Comparison(nil), repository.failed...)
	if len(failed) > limit {
		failed = failed[:limit]
	}
	return failed, nil
}

func (repository *backfillRepository) GetMetadata(_ context.Context, _ shared.ID, comparisonID shared.ID) (domain.Comparison, error) {
	comparison, ok := repository.metadata[comparisonID]
	if !ok {
		return domain.Comparison{}, shared.ErrNotFound
	}
	return comparison, nil
}

type backfillCycleLister struct {
	records []ports.AssessmentCycleListRecord
	calls   int
}

func (lister *backfillCycleLister) ListCycles(_ context.Context, query ports.AssessmentCycleListQuery) ([]ports.AssessmentCycleListRecord, error) {
	lister.calls++
	records := append([]ports.AssessmentCycleListRecord(nil), lister.records...)
	sort.Slice(records, func(left, right int) bool {
		if records[left].Cycle.UpdatedAt.Equal(records[right].Cycle.UpdatedAt) {
			return records[left].Cycle.ID > records[right].Cycle.ID
		}
		return records[left].Cycle.UpdatedAt.After(records[right].Cycle.UpdatedAt)
	})
	result := make([]ports.AssessmentCycleListRecord, 0, query.Limit)
	for _, record := range records {
		if !query.AfterUpdatedAt.IsZero() && (record.Cycle.UpdatedAt.After(query.AfterUpdatedAt) || record.Cycle.UpdatedAt.Equal(query.AfterUpdatedAt) && record.Cycle.ID >= query.AfterCycleID) {
			continue
		}
		result = append(result, record)
		if len(result) == query.Limit {
			break
		}
	}
	return result, nil
}

func (*backfillCycleLister) ListMigrationPendingAssessments(context.Context, ports.AssessmentCycleListQuery) ([]ports.AssessmentCycleMigrationPendingRecord, int, error) {
	return nil, 0, nil
}

type fixedComparisonClock struct{ now time.Time }

func (clock fixedComparisonClock) Now() time.Time { return clock.now }

type backfillAudit struct{}

func (*backfillAudit) Record(context.Context, ports.AuditEntry) error { return nil }

func backfillCycle(cycleID, rootSnapshotID, currentSnapshotID shared.ID, updatedAt time.Time) ports.AssessmentCycleListRecord {
	return ports.AssessmentCycleListRecord{
		Cycle:          assessmentcycle.AssessmentCycle{ID: cycleID, UpdatedAt: updatedAt},
		RootSnapshotID: rootSnapshotID, CurrentSnapshotID: currentSnapshotID,
	}
}

func timePointer(value time.Time) *time.Time { return &value }
