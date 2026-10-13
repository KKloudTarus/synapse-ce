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

// tenantCheckedJobs models PostgreSQL's terminal-save guard. The global
// sweeper must recover the tenant from the engagement for git, image, and
// local scans, which have no frozen uploaded-source binding.
type tenantCheckedJobs struct {
	*memory.ScanJobStore
	owners map[string]shared.ID
}

func (store tenantCheckedJobs) Save(ctx context.Context, job ports.ScanJob) error {
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant != store.owners[job.ID] {
		return shared.ErrValidation
	}
	return store.ScanJobStore.Save(ctx, job)
}

type failingTerminalSaveJobs struct {
	tenantCheckedJobs
	failID string
	err    error
	cancel context.CancelFunc
}

func (store failingTerminalSaveJobs) Save(ctx context.Context, job ports.ScanJob) error {
	if job.ID == store.failID && job.Status == ports.ScanFailed {
		if store.cancel != nil {
			store.cancel()
		}
		return store.err
	}
	return store.tenantCheckedJobs.Save(ctx, job)
}

type failingOwnerLookupRepo struct {
	*memory.EngagementRepository
	failID shared.ID
	err    error
}

func (repo failingOwnerLookupRepo) GetByID(ctx context.Context, id shared.ID) (*engdom.Engagement, error) {
	if id == repo.failID {
		return nil, repo.err
	}
	return repo.EngagementRepository.GetByID(ctx, id)
}

func TestSweepStaleScansContinuesAfterCandidateSaveFailure(t *testing.T) {
	ctx := context.Background()
	tenant := shared.ID("tenant-a")
	engagements := memory.NewEngagementRepository()
	saveErr := errors.New("terminal save unavailable")
	jobs := failingTerminalSaveJobs{
		tenantCheckedJobs: tenantCheckedJobs{ScanJobStore: memory.NewScanJobStore(), owners: map[string]shared.ID{}},
		failID:            "job-save-fails",
		err:               saveErr,
	}
	for index, jobID := range []string{"job-save-fails", "job-save-succeeds"} {
		assessment, err := engdom.New(shared.ID("assessment-"+jobID), tenant, "Repository scan", "", time.Unix(1000, 0).UTC())
		if err != nil {
			t.Fatal(err)
		}
		if err := engagements.Create(ctx, assessment); err != nil {
			t.Fatal(err)
		}
		job := ports.ScanJob{ID: jobID, EngagementID: assessment.ID.String(), Kind: ports.TargetGit, Target: "https://example.invalid/repository.git",
			Status: ports.ScanRunning, StartedAt: time.Unix(int64(1000+index), 0).UTC()}
		jobs.owners[job.ID] = tenant
		if err := jobs.CreateRunning(shared.WithTenant(ctx, tenant), job); err != nil {
			t.Fatal(err)
		}
	}

	lock := memory.NewRunLock()
	svc := newAsyncSvc(engagements, fakeClock{t: time.Unix(10000, 0).UTC()}, &fakeAcquirer{}, &fakeAudit{}, &fakeDetector{}, jobs, fakeIDs{})
	svc.SetRunLock(lock)
	n, err := svc.SweepStaleScans(ctx, 5*time.Minute)
	if n != 1 || !errors.Is(err, saveErr) {
		t.Fatalf("sweeper must reclaim later jobs after a save failure: count=%d err=%v", n, err)
	}
	failed, err := jobs.GetJob(ctx, "job-save-fails")
	if err != nil || failed.Status != ports.ScanRunning {
		t.Fatalf("failed terminal save mutated job: %+v %v", failed, err)
	}
	succeeded, err := jobs.GetJob(ctx, "job-save-succeeds")
	if err != nil || succeeded.Status != ports.ScanFailed || succeeded.FinishedAt == nil {
		t.Fatalf("later candidate was not reclaimed: %+v %v", succeeded, err)
	}
	for _, jobID := range []string{"job-save-fails", "job-save-succeeds"} {
		release, ok, err := lock.TryLock(ctx, jobID)
		if err != nil || !ok {
			t.Fatalf("candidate %s lease remained held: ok=%v err=%v", jobID, ok, err)
		}
		release()
	}
}

func TestSweepStaleScansContinuesAfterCandidateOwnerLookupFailure(t *testing.T) {
	ctx := context.Background()
	tenant := shared.ID("tenant-a")
	base := memory.NewEngagementRepository()
	lookupErr := errors.New("engagement lookup unavailable")
	jobs := tenantCheckedJobs{ScanJobStore: memory.NewScanJobStore(), owners: map[string]shared.ID{}}
	var failedEngagementID shared.ID
	for index, jobID := range []string{"job-owner-fails", "job-owner-succeeds"} {
		assessment, err := engdom.New(shared.ID("assessment-"+jobID), tenant, "Repository scan", "", time.Unix(1000, 0).UTC())
		if err != nil {
			t.Fatal(err)
		}
		if err := base.Create(ctx, assessment); err != nil {
			t.Fatal(err)
		}
		if jobID == "job-owner-fails" {
			failedEngagementID = assessment.ID
		}
		job := ports.ScanJob{ID: jobID, EngagementID: assessment.ID.String(), Kind: ports.TargetGit, Target: "https://example.invalid/repository.git",
			Status: ports.ScanRunning, StartedAt: time.Unix(int64(1000+index), 0).UTC()}
		jobs.owners[job.ID] = tenant
		if err := jobs.CreateRunning(shared.WithTenant(ctx, tenant), job); err != nil {
			t.Fatal(err)
		}
	}

	lock := memory.NewRunLock()
	svc := newAsyncSvc(failingOwnerLookupRepo{EngagementRepository: base, failID: failedEngagementID, err: lookupErr}, fakeClock{t: time.Unix(10000, 0).UTC()}, &fakeAcquirer{}, &fakeAudit{}, &fakeDetector{}, jobs, fakeIDs{})
	svc.SetRunLock(lock)
	n, err := svc.SweepStaleScans(ctx, 5*time.Minute)
	if n != 1 || !errors.Is(err, lookupErr) {
		t.Fatalf("sweeper must reclaim later jobs after owner lookup failure: count=%d err=%v", n, err)
	}
	failed, err := jobs.GetJob(ctx, "job-owner-fails")
	if err != nil || failed.Status != ports.ScanRunning {
		t.Fatalf("failed owner lookup mutated job: %+v %v", failed, err)
	}
	succeeded, err := jobs.GetJob(ctx, "job-owner-succeeds")
	if err != nil || succeeded.Status != ports.ScanFailed || succeeded.FinishedAt == nil {
		t.Fatalf("later candidate was not reclaimed: %+v %v", succeeded, err)
	}
	for _, jobID := range []string{"job-owner-fails", "job-owner-succeeds"} {
		release, ok, err := lock.TryLock(ctx, jobID)
		if err != nil || !ok {
			t.Fatalf("candidate %s lease remained held: ok=%v err=%v", jobID, ok, err)
		}
		release()
	}
}

func TestSweepStaleScansStopsOnCancellationAfterPriorCandidateFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tenant := shared.ID("tenant-a")
	engagements := memory.NewEngagementRepository()
	saveErr := errors.New("terminal save unavailable")
	jobs := failingTerminalSaveJobs{
		tenantCheckedJobs: tenantCheckedJobs{ScanJobStore: memory.NewScanJobStore(), owners: map[string]shared.ID{}},
		failID:            "job-save-fails",
		err:               saveErr,
		cancel:            cancel,
	}
	for index, jobID := range []string{"job-save-fails", "job-not-attempted"} {
		assessment, err := engdom.New(shared.ID("assessment-"+jobID), tenant, "Repository scan", "", time.Unix(1000, 0).UTC())
		if err != nil {
			t.Fatal(err)
		}
		if err := engagements.Create(ctx, assessment); err != nil {
			t.Fatal(err)
		}
		job := ports.ScanJob{ID: jobID, EngagementID: assessment.ID.String(), Kind: ports.TargetGit, Target: "https://example.invalid/repository.git",
			Status: ports.ScanRunning, StartedAt: time.Unix(int64(1000+index), 0).UTC()}
		jobs.owners[job.ID] = tenant
		if err := jobs.CreateRunning(shared.WithTenant(ctx, tenant), job); err != nil {
			t.Fatal(err)
		}
	}

	lock := memory.NewRunLock()
	svc := newAsyncSvc(engagements, fakeClock{t: time.Unix(10000, 0).UTC()}, &fakeAcquirer{}, &fakeAudit{}, &fakeDetector{}, jobs, fakeIDs{})
	svc.SetRunLock(lock)
	n, err := svc.SweepStaleScans(ctx, 5*time.Minute)
	if n != 0 || !errors.Is(err, saveErr) || !errors.Is(err, context.Canceled) {
		t.Fatalf("sweeper must preserve prior failure and stop on cancellation: count=%d err=%v", n, err)
	}
	for _, jobID := range []string{"job-save-fails", "job-not-attempted"} {
		stored, getErr := jobs.GetJob(context.Background(), jobID)
		if getErr != nil || stored.Status != ports.ScanRunning {
			t.Fatalf("cancellation mutated job %s: %+v %v", jobID, stored, getErr)
		}
		release, ok, lockErr := lock.TryLock(context.Background(), jobID)
		if lockErr != nil || !ok {
			t.Fatalf("candidate %s lease remained held: ok=%v err=%v", jobID, ok, lockErr)
		}
		release()
	}
}

func TestSweepStaleScansBindsEngagementOwnerForJobsWithoutFrozenSource(t *testing.T) {
	ctx := context.Background() // API/worker sweepers are global daemons.
	engagements := memory.NewEngagementRepository()
	jobs := tenantCheckedJobs{ScanJobStore: memory.NewScanJobStore(), owners: map[string]shared.ID{}}
	for _, tenant := range []shared.ID{"tenant-a", "tenant-b"} {
		assessment, err := engdom.New(shared.ID("assessment-"+tenant.String()), tenant, "Repository scan", "", time.Unix(1000, 0).UTC())
		if err != nil {
			t.Fatal(err)
		}
		if err := engagements.Create(ctx, assessment); err != nil {
			t.Fatal(err)
		}
		job := ports.ScanJob{ID: "job-" + tenant.String(), EngagementID: assessment.ID.String(), Kind: ports.TargetGit, Target: "https://example.invalid/repository.git",
			Status: ports.ScanRunning, StartedAt: time.Unix(1000, 0).UTC()}
		jobs.owners[job.ID] = tenant
		if err := jobs.CreateRunning(shared.WithTenant(ctx, tenant), job); err != nil {
			t.Fatal(err)
		}
	}

	svc := newAsyncSvc(engagements, fakeClock{t: time.Unix(10000, 0).UTC()}, &fakeAcquirer{}, &fakeAudit{}, &fakeDetector{}, jobs, fakeIDs{})
	svc.SetRunLock(memory.NewRunLock())
	n, err := svc.SweepStaleScans(ctx, 5*time.Minute)
	if err != nil || n != 2 {
		t.Fatalf("global sweeper failed to finalize engagement-owned scans: count=%d err=%v", n, err)
	}
	for _, tenant := range []shared.ID{"tenant-a", "tenant-b"} {
		got, err := jobs.GetJob(ctx, "job-"+tenant.String())
		if err != nil || got.Status != ports.ScanFailed || got.FinishedAt == nil {
			t.Fatalf("sweeper did not persist terminal job for %s: %+v %v", tenant, got, err)
		}
	}
}

func TestSweepStaleScansWithoutFrozenSourceReleasesLeaseWhenOwnerLookupFails(t *testing.T) {
	ctx := context.Background()
	jobs := newFakeJobStore()
	job := ports.ScanJob{ID: "job-owner-missing", EngagementID: "assessment-missing", Kind: ports.TargetLocal,
		Status: ports.ScanRunning, StartedAt: time.Unix(1000, 0).UTC()}
	if err := jobs.Save(ctx, job); err != nil {
		t.Fatal(err)
	}
	lock := memory.NewRunLock()
	svc := newAsyncSvc(&fakeEngRepo{err: shared.ErrNotFound}, fakeClock{t: time.Unix(10000, 0).UTC()}, &fakeAcquirer{}, &fakeAudit{}, &fakeDetector{}, jobs, fakeIDs{})
	svc.SetRunLock(lock)

	n, err := svc.SweepStaleScans(ctx, 5*time.Minute)
	if n != 0 || !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("sweeper must leave a job with no authoritative owner running: count=%d err=%v", n, err)
	}
	stored, err := jobs.GetJob(ctx, job.ID)
	if err != nil || stored.Status != ports.ScanRunning {
		t.Fatalf("owner lookup failure mutated scan job: %+v %v", stored, err)
	}
	release, ok, err := lock.TryLock(ctx, job.ID)
	if err != nil || !ok {
		t.Fatalf("owner lookup failure left scan lease held: ok=%v err=%v", ok, err)
	}
	release()
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
