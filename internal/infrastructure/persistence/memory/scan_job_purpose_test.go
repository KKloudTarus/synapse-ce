package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestLatestProjectAnalysisExcludesProjectSourceJobs(t *testing.T) {
	store := NewScanJobStore()
	ctx := shared.WithTenant(context.Background(), "tenant")
	full := ports.ScanJob{ID: "full", EngagementID: "engagement", Target: "repo", Kind: ports.TargetLocal, Status: ports.ScanSucceeded, StartedAt: time.Unix(1, 0)}
	source := ports.ScanJob{ID: "source", EngagementID: "engagement", Target: "repo/a", Kind: ports.TargetLocal, Purpose: ports.ScanPurposeProjectSource, Status: ports.ScanSucceeded, StartedAt: time.Unix(2, 0)}
	if err := store.Save(ctx, full); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, source); err != nil {
		t.Fatal(err)
	}
	got, err := store.LatestProjectAnalysisForEngagement(ctx, "engagement")
	if err != nil || got.ID != full.ID {
		t.Fatalf("latest project analysis = %+v, %v", got, err)
	}
	if _, err := store.LatestProjectAnalysisForEngagement(ctx, "other"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing engagement = %v", err)
	}
}

func TestScanJobPurposeIsImmutable(t *testing.T) {
	store := NewScanJobStore()
	job := ports.ScanJob{ID: "source", EngagementID: "engagement", Target: "repo/a", Kind: ports.TargetLocal, Purpose: ports.ScanPurposeProjectSource, Status: ports.ScanRunning, StartedAt: time.Unix(1, 0)}
	if err := store.CreateRunning(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	job.Purpose = ""
	if err := store.Save(context.Background(), job); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("rewritten purpose = %v, want validation", err)
	}
}
