package sca

import (
	"context"
	"errors"
	"testing"
	"time"

	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sourcepackage"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type tenantCheckedSourceJobs struct{ *memory.ScanJobStore }

func (store tenantCheckedSourceJobs) Save(ctx context.Context, job ports.ScanJob) error {
	if job.SourcePackage != nil {
		tenant, ok := shared.TenantFrom(ctx)
		if !ok || tenant != job.SourcePackage.TenantID {
			return shared.ErrValidation
		}
	}
	return store.ScanJobStore.Save(ctx, job)
}

func TestUploadedSourceSweeperBindsEachOwnedTenant(t *testing.T) {
	ctx := context.Background() // API/worker sweepers are global daemons.
	engagements := memory.NewEngagementRepository()
	jobs := tenantCheckedSourceJobs{memory.NewScanJobStore()}
	for _, tenant := range []shared.ID{"tenant-a", "tenant-b"} {
		assessment, err := engdom.New(shared.ID("assessment-"+tenant.String()), tenant, "Uploaded source", "", time.Unix(1000, 0).UTC())
		if err != nil {
			t.Fatal(err)
		}
		if err := engagements.Create(ctx, assessment); err != nil {
			t.Fatal(err)
		}
		item := sourcepackage.Package{TenantID: tenant, EngagementID: assessment.ID, VersionID: "owned-version", SHA256: "owned-content"}
		job := ports.ScanJob{ID: "job-" + tenant.String(), EngagementID: assessment.ID.String(), Kind: ports.TargetUpload, Target: item.Target(),
			Status: ports.ScanRunning, StartedAt: time.Unix(1000, 0).UTC(), SourcePackage: &item}
		if err := jobs.CreateRunning(ctx, job); err != nil {
			t.Fatal(err)
		}
	}
	svc := newAsyncSvc(engagements, fakeClock{t: time.Unix(10000, 0).UTC()}, &fakeAcquirer{}, &fakeAudit{}, &fakeDetector{}, jobs, fakeIDs{})
	svc.SetRunLock(memory.NewRunLock())
	n, err := svc.SweepStaleScans(ctx, 5*time.Minute)
	if err != nil || n != 2 {
		t.Fatalf("global sweeper failed to finalize tenant-bound uploads: count=%d err=%v", n, err)
	}
	for _, tenant := range []shared.ID{"tenant-a", "tenant-b"} {
		got, err := jobs.GetJob(ctx, "job-"+tenant.String())
		if err != nil || got.Status != ports.ScanFailed || got.SourcePackage == nil || got.SourcePackage.TenantID != tenant {
			t.Fatalf("sweeper lost source/terminal state for %s: %+v %v", tenant, got, err)
		}
	}
}

func TestUploadedSourceSweeperRejectsForgedOwner(t *testing.T) {
	ctx := context.Background()
	engagements := memory.NewEngagementRepository()
	assessment, err := engdom.New("assessment", "owner-tenant", "Source", "", time.Unix(1000, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := engagements.Create(ctx, assessment); err != nil {
		t.Fatal(err)
	}
	jobs := tenantCheckedSourceJobs{memory.NewScanJobStore()}
	item := sourcepackage.Package{TenantID: "foreign-tenant", EngagementID: assessment.ID, SHA256: "content"}
	job := ports.ScanJob{ID: "forged-job", EngagementID: assessment.ID.String(), Kind: ports.TargetUpload, Target: item.Target(),
		Status: ports.ScanRunning, StartedAt: time.Unix(1000, 0).UTC(), SourcePackage: &item}
	if err := jobs.CreateRunning(ctx, job); err != nil {
		t.Fatal(err)
	}
	svc := newAsyncSvc(engagements, fakeClock{t: time.Unix(10000, 0).UTC()}, &fakeAcquirer{}, &fakeAudit{}, &fakeDetector{}, jobs, fakeIDs{})
	svc.SetRunLock(memory.NewRunLock())
	if n, err := svc.SweepStaleScans(ctx, 5*time.Minute); n != 0 || !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("sweeper trusted unverified source tenant: count=%d err=%v", n, err)
	}
	got, err := jobs.GetJob(ctx, job.ID)
	if err != nil || got.Status != ports.ScanRunning {
		t.Fatalf("forged source job was mutated: %+v %v", got, err)
	}
}
