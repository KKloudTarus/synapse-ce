package memory

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcomparison"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestAssessmentComparisonRepositoryIdempotencyCASAndIsolation(t *testing.T) {
	repository := NewAssessmentComparisonRepository()
	now := time.Date(2026, 8, 31, 14, 0, 0, 0, time.UTC)
	comparison := queuedMemoryComparison(t, "tenant-a", "comparison-a", now)
	stored, created, err := repository.CreateQueued(context.Background(), comparison)
	if err != nil || !created || stored.ID != comparison.ID {
		t.Fatalf("create stored=%+v created=%v err=%v", stored, created, err)
	}
	replay := comparison
	replay.ID, replay.CreatedAt, replay.UpdatedAt = "different-candidate-id", now.Add(time.Minute), now.Add(time.Minute)
	stored, created, err = repository.CreateQueued(context.Background(), replay)
	if err != nil || created || stored.ID != comparison.ID {
		t.Fatalf("replay stored=%+v created=%v err=%v", stored, created, err)
	}
	if _, err := repository.Get(context.Background(), "tenant-b", comparison.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant get error=%v", err)
	}

	updated := comparison
	if err := updated.Start(updated.Version, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := repository.UpdateCAS(context.Background(), updated, 1); err != nil {
		t.Fatal(err)
	}
	if err := repository.UpdateCAS(context.Background(), updated, 1); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale update error=%v", err)
	}
	loaded, err := repository.GetByInputHash(context.Background(), "tenant-a", comparison.InputHash)
	if err != nil || loaded.Status != assessmentcomparison.StatusGenerating || loaded.Version != 2 {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	metadata, err := repository.GetMetadata(context.Background(), "tenant-a", comparison.ID)
	if err != nil || len(metadata.Items) != 0 || metadata.ID != comparison.ID {
		t.Fatalf("metadata=%+v err=%v", metadata, err)
	}
	backlog, err := repository.GetAssessmentComparisonBacklog(context.Background(), "tenant-a")
	if err != nil || backlog.Generating != 1 || backlog.OldestActiveAt == nil {
		t.Fatalf("generating backlog=%+v err=%v", backlog, err)
	}
	failed := updated
	if err := failed.Fail("dead_lettered", false, 3, failed.Version, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := repository.UpdateCAS(context.Background(), failed, 2); err != nil {
		t.Fatal(err)
	}
	backlog, err = repository.GetAssessmentComparisonBacklog(context.Background(), "tenant-a")
	if err != nil || backlog.Active() != 0 || backlog.Failed != 1 || backlog.DeadLettered != 1 {
		t.Fatalf("failed backlog=%+v err=%v", backlog, err)
	}
	failedRows, err := repository.ListFailedAssessmentComparisons(context.Background(), "tenant-a", 10)
	if err != nil || len(failedRows) != 1 || failedRows[0].ID != comparison.ID {
		t.Fatalf("failed rows=%+v err=%v", failedRows, err)
	}
}

func queuedMemoryComparison(t *testing.T, tenantID, comparisonID string, now time.Time) assessmentcomparison.Comparison {
	t.Helper()
	input := assessmentcomparison.GenerationInput{
		Mode:             assessmentcomparison.ModeLifecycle,
		Baseline:         assessmentcomparison.SnapshotHashRef{ID: "baseline", ContentHash: strings.Repeat("a", 64)},
		Current:          assessmentcomparison.SnapshotHashRef{ID: "current", ContentHash: strings.Repeat("b", 64)},
		AlgorithmVersion: 1, FingerprintVersion: 1, RiskModelVersion: 1, CoveragePolicyVersion: 1,
	}
	payload, inputHash, err := assessmentcomparison.HashGenerationInput(input)
	if err != nil {
		t.Fatal(err)
	}
	comparison, err := assessmentcomparison.NewQueued(shared.ID(tenantID), "cycle", shared.ID(comparisonID), input, payload, inputHash, now)
	if err != nil {
		t.Fatal(err)
	}
	return comparison
}
