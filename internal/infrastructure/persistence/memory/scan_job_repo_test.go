package memory

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sourcepackage"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestScanJobStatusUpdatesPreserveAdmissionBinding(t *testing.T) {
	ctx := context.Background()
	store := NewScanJobStore()
	packageAtAdmission := sourcepackage.Package{VersionID: "owned-version", TenantID: "tenant", EngagementID: "assessment", SHA256: "original"}
	job := ports.ScanJob{ID: "job", EngagementID: "assessment", Kind: ports.TargetUpload, Target: packageAtAdmission.Target(),
		Status: ports.ScanRunning, StartedAt: time.Now().UTC(), SourcePackage: &packageAtAdmission}
	if err := store.CreateRunning(ctx, job); err != nil {
		t.Fatal(err)
	}
	packageAtAdmission.SHA256 = "mutated-by-caller"
	changed := job
	changed.EngagementID, changed.Kind, changed.Target = "other-assessment", ports.TargetGit, "other-target"
	changed.Status, changed.SourcePackage = ports.ScanFailed, nil
	if err := store.Save(ctx, changed); err != nil {
		t.Fatal(err)
	}
	got, err := store.LatestForEngagement(ctx, "assessment")
	if err != nil {
		t.Fatal(err)
	}
	if got.EngagementID != job.EngagementID || got.Kind != job.Kind || got.Target != job.Target || !got.StartedAt.Equal(job.StartedAt) {
		t.Fatalf("status update changed admitted identity: %+v", got)
	}
	if got.Status != ports.ScanFailed || got.SourcePackage == nil || got.SourcePackage.SHA256 != "original" {
		t.Fatalf("status/source not retained: %+v", got)
	}
	got.SourcePackage.SHA256 = "mutated-by-reader"
	again, err := store.GetJob(ctx, job.ID)
	if err != nil || again.SourcePackage.SHA256 != "original" {
		t.Fatalf("reader mutated stored source: %+v %v", again, err)
	}
}
