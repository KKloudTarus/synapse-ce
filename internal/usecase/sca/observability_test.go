package sca

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type recordedSCAOutcome struct {
	duration time.Duration
	outcome  string
}

type fakeSCAObserver struct {
	mu    sync.Mutex
	calls []recordedSCAOutcome
}

type terminalSaveFailingJobStore struct {
	*fakeJobStore
	err error
}

func (s terminalSaveFailingJobStore) Save(ctx context.Context, job ports.ScanJob) error {
	if job.Status == ports.ScanSucceeded || job.Status == ports.ScanFailed {
		return s.err
	}
	return s.fakeJobStore.Save(ctx, job)
}

func (f *fakeSCAObserver) ObserveSCAOutcome(outcome string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, recordedSCAOutcome{outcome: outcome})
}

func (f *fakeSCAObserver) ObserveSCAScan(duration time.Duration, outcome string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, recordedSCAOutcome{duration: duration, outcome: outcome})
}

func (f *fakeSCAObserver) snapshot() []recordedSCAOutcome {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedSCAOutcome(nil), f.calls...)
}

// TestScanObservesSuccessOutcome covers the synchronous path: a completed in-scope scan
// records exactly one terminal "success" outcome.
func TestScanObservesSuccessOutcome(t *testing.T) {
	repo := &fakeEngRepo{eng: engagementWithScope(t, "myrepo")}
	acq := &fakeAcquirer{dir: "/tmp/ws"}
	svc := newSvc(repo, fakeClock{t: time.Unix(0, 0).UTC()}, acq, &fakeAudit{}, &fakeDetector{})
	observer := &fakeSCAObserver{}
	svc.SetObserver(observer)

	if _, err := svc.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: "local", Value: "myrepo"}); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(observer.snapshot()) != 1 || observer.snapshot()[0].outcome != "success" {
		t.Fatalf("observed calls = %+v, want exactly one success", observer.snapshot())
	}
}

// TestScanObservesBlockedOnlyAfterGateForbidden covers that "blocked" is recorded ONLY
// for an execution-gate denial (shared.ErrForbidden) reached after a genuine scan
// attempt (past option normalization / SBOM-import loading) — never for a validation
// failure, which is not a scan attempt.
func TestScanObservesBlockedOnlyAfterGateForbidden(t *testing.T) {
	repo := &fakeEngRepo{eng: engagementWithScope(t, "allowed")}
	acq := &fakeAcquirer{dir: "/tmp/ws"}
	svc := newSvc(repo, fakeClock{t: time.Unix(0, 0).UTC()}, acq, &fakeAudit{}, &fakeDetector{})
	observer := &fakeSCAObserver{}
	svc.SetObserver(observer)

	_, err := svc.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Value: "not-allowed"})
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("want ErrForbidden, got %v", err)
	}
	if len(observer.snapshot()) != 1 || observer.snapshot()[0].outcome != "blocked" {
		t.Fatalf("observed calls = %+v, want exactly one blocked", observer.snapshot())
	}
}

// TestScanValidationFailureNotObserved covers that a validation error (invalid scan
// options, never reaching the execution gate) is not a scan attempt and must not emit
// any terminal outcome — success, failed, or blocked.
func TestScanValidationFailureNotObserved(t *testing.T) {
	repo := &fakeEngRepo{eng: engagementWithScope(t, "myrepo")}
	svc := newSvc(repo, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAcquirer{dir: "/tmp/ws"}, &fakeAudit{}, &fakeDetector{})
	observer := &fakeSCAObserver{}
	svc.SetObserver(observer)

	if _, err := svc.ScanWithOptions(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: "local", Value: "myrepo"}, ScanOptions{Mode: "not-a-real-mode"}); err == nil {
		t.Fatal("want a validation error for an invalid scan mode")
	}
	if len(observer.snapshot()) != 0 {
		t.Fatalf("a pre-gate validation failure must not be observed, got %+v", observer.snapshot())
	}
}

// TestStartScanAsyncObservesSuccessAtExecution covers the async path: the async
// duration is measured from EXECUTION (runScanJob's start), not from the original
// StartScan/enqueue call, and the terminal outcome fires exactly once on completion.
func TestStartScanAsyncObservesSuccessAtExecution(t *testing.T) {
	repo := &fakeEngRepo{eng: engagementWithScope(t, "myrepo")}
	acq := &fakeAcquirer{dir: "/tmp/ws"}
	jobs := newFakeJobStore()
	svc := newAsyncSvc(repo, fakeClock{t: time.Unix(0, 0).UTC()}, acq, &fakeAudit{}, &fakeDetector{}, jobs, fakeIDs{})
	observer := &fakeSCAObserver{}
	svc.SetObserver(observer)

	job, err := svc.StartScan(shared.WithTenant(context.Background(), shared.DefaultTenant), "operator", "e1", ports.AcquireRequest{Kind: "local", Value: "myrepo"})
	if err != nil {
		t.Fatalf("StartScan: %v", err)
	}

	var final ports.ScanJob
	for i := 0; i < 400; i++ {
		j, err := svc.LatestJob(context.Background(), "e1")
		if err != nil {
			t.Fatalf("LatestJob: %v", err)
		}
		final = j
		if j.Status != ports.ScanRunning {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if final.Status != ports.ScanSucceeded {
		t.Fatalf("final status = %q, want succeeded", final.Status)
	}
	if job.ID != final.ID {
		t.Fatalf("job id mismatch: started %q, final %q", job.ID, final.ID)
	}
	if len(observer.snapshot()) != 1 || observer.snapshot()[0].outcome != "success" {
		t.Fatalf("observed calls = %+v, want exactly one success", observer.snapshot())
	}
	if observer.snapshot()[0].duration < 0 {
		t.Errorf("duration must not be negative, got %v", observer.snapshot()[0].duration)
	}
}

// TestRunScanJobIdempotentSkipDoesNotDoubleObserve covers the idempotency guard:
// runScanJob's terminal-state skip for an already-finished redelivery must not emit a
// second terminal observation for the same job.
func TestRunScanJobIdempotentSkipDoesNotDoubleObserve(t *testing.T) {
	repo := &fakeEngRepo{eng: engagementWithScope(t, "myrepo")}
	jobs := newFakeJobStore()
	svc := newAsyncSvc(repo, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAcquirer{dir: "/tmp/ws"}, &fakeAudit{}, &fakeDetector{}, jobs, fakeIDs{})
	observer := &fakeSCAObserver{}
	svc.SetObserver(observer)

	job := ports.ScanJob{ID: "job-1", EngagementID: "e1", Status: ports.ScanRunning, StartedAt: time.Unix(0, 0).UTC()}
	if err := jobs.CreateRunning(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	ctx := shared.WithTenant(context.Background(), shared.DefaultTenant)

	// First delivery runs the pipeline and finishes it (terminal).
	svc.runScanJob(ctx, "operator", "e1", time.Unix(0, 0).UTC(), ports.AcquireRequest{Kind: "local", Value: "myrepo"}, ScanOptions{Mode: ScanModeFull}, job)
	if len(observer.snapshot()) != 1 {
		t.Fatalf("first delivery: observed %d calls, want 1", len(observer.snapshot()))
	}

	// A redelivery of the SAME already-terminal job must be skipped by the idempotency
	// guard (latest.ID == job.ID && terminal) and must NOT emit a second observation.
	svc.runScanJob(ctx, "operator", "e1", time.Unix(0, 0).UTC(), ports.AcquireRequest{Kind: "local", Value: "myrepo"}, ScanOptions{Mode: ScanModeFull}, job)
	if len(observer.snapshot()) != 1 {
		t.Fatalf("redelivery of a terminal job must not double-observe, got %d calls", len(observer.snapshot()))
	}
}

// TestRunScanJobDoesNotRedeliverOnTerminalSaveFailure covers a double-seal hazard: if
// the terminal ScanJob Save fails, the scan already executed but the job is left
// stranded at Status=Running (not terminal). Returning that Save error would make the
// durable queue redeliver the job; runScanJob's idempotency guard only skips a
// redelivery when the latest job is already terminal, so redelivery here would re-run
// the pipeline and seal a DUPLICATE "scan" evidence link plus a phantom ScanRun row.
// RunScanJob must therefore return nil (no redelivery) and must not observe any
// terminal outcome — SweepStaleScans alone finalizes the stranded job and counts it.
func TestRunScanJobDoesNotRedeliverOnTerminalSaveFailure(t *testing.T) {
	repo := &fakeEngRepo{eng: engagementWithScope(t, "myrepo")}
	terminalSaveErr := errors.New("terminal scan job save unavailable")
	jobs := newFakeJobStore()
	svc := newAsyncSvc(repo, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAcquirer{dir: "/tmp/ws"}, &fakeAudit{}, &fakeDetector{}, terminalSaveFailingJobStore{fakeJobStore: jobs, err: terminalSaveErr}, fakeIDs{})
	observer := &fakeSCAObserver{}
	svc.SetObserver(observer)

	job := ports.ScanJob{ID: "job-1", EngagementID: "e1", Status: ports.ScanRunning, StartedAt: time.Unix(0, 0).UTC()}
	if err := jobs.CreateRunning(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(scaJobPayload{
		Actor: "operator", TenantID: strPtr(shared.DefaultTenant.String()), EngagementID: "e1",
		Now: time.Unix(0, 0).UTC(), Req: ports.AcquireRequest{Kind: "local", Value: "myrepo"}, Options: ScanOptions{Mode: ScanModeFull}, Job: job,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = svc.RunScanJob(shared.WithTenant(context.Background(), shared.DefaultTenant), payload)
	if err != nil {
		t.Fatalf("RunScanJob error = %v, want nil so the durable queue does not redeliver", err)
	}
	if calls := observer.snapshot(); len(calls) != 0 {
		t.Fatalf("terminal save failure must not observe an outcome or duration, got %+v", calls)
	}
	stored, err := jobs.LatestForEngagement(context.Background(), "e1")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != ports.ScanRunning || stored.FinishedAt != nil {
		t.Fatalf("terminal save failure must leave the job stranded (running, not terminal) for SweepStaleScans, got %+v", stored)
	}
}

// TestFailStrandedScanJobObservesFailedOnce covers the dead-letter finalization path:
// exactly one "failed" outcome for a job that never reached a terminal state, and no
// observation at all when the job is already terminal (avoiding a double count with
// whatever delivery already finished it).
func TestFailStrandedScanJobObservesFailedOnce(t *testing.T) {
	repo := &fakeEngRepo{eng: engagementWithScope(t, "myrepo")}
	jobs := newFakeJobStore()
	svc := newAsyncSvc(repo, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAcquirer{dir: "/tmp/ws"}, &fakeAudit{}, &fakeDetector{}, jobs, fakeIDs{})
	observer := &fakeSCAObserver{}
	svc.SetObserver(observer)

	job := ports.ScanJob{ID: "job-1", EngagementID: "e1", Status: ports.ScanRunning, StartedAt: time.Unix(0, 0).UTC()}
	if err := jobs.CreateRunning(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(scaJobPayload{
		Actor: "operator", TenantID: strPtr(shared.DefaultTenant.String()), EngagementID: "e1",
		Now: time.Unix(0, 0).UTC(), Req: ports.AcquireRequest{Kind: "local", Value: "myrepo"}, Options: ScanOptions{Mode: ScanModeFull}, Job: job,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := shared.WithTenant(context.Background(), shared.DefaultTenant)

	if err := svc.FailStrandedScanJob(ctx, payload, errors.New("dead-lettered")); err != nil {
		t.Fatalf("FailStrandedScanJob: %v", err)
	}
	if len(observer.snapshot()) != 1 || observer.snapshot()[0].outcome != "failed" {
		t.Fatalf("observed calls = %+v, want exactly one failed", observer.snapshot())
	}

	// Calling it again on the now-terminal job must be a no-op (already terminal guard)
	// and must not double-observe.
	if err := svc.FailStrandedScanJob(ctx, payload, errors.New("dead-lettered again")); err != nil {
		t.Fatalf("FailStrandedScanJob (idempotent): %v", err)
	}
	if len(observer.snapshot()) != 1 {
		t.Fatalf("dead-lettering an already-terminal job must not double-observe, got %d calls", len(observer.snapshot()))
	}
}

// TestStartScanEnqueueFailureObservesFailedOnce covers the enqueue-terminal-failure
// path: when the durable queue rejects Enqueue, the job never reaches execution, and
// this dead end must record exactly one "failed" outcome (not "blocked", not silence).
func TestStartScanEnqueueFailureObservesFailedOnce(t *testing.T) {
	repo := &fakeEngRepo{eng: engagementWithScope(t, "myrepo")}
	jobs := newFakeJobStore()
	svc := newAsyncSvc(repo, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAcquirer{dir: "/tmp/ws"}, &fakeAudit{}, &fakeDetector{}, jobs, fakeIDs{})
	observer := &fakeSCAObserver{}
	svc.SetObserver(observer)
	svc.SetQueue(&failingEnqueueQueue{})

	_, err := svc.StartScan(shared.WithTenant(context.Background(), shared.DefaultTenant), "operator", "e1", ports.AcquireRequest{Kind: "local", Value: "myrepo"})
	if err == nil {
		t.Fatal("want an enqueue error")
	}
	if len(observer.snapshot()) != 1 || observer.snapshot()[0].outcome != "failed" {
		t.Fatalf("observed calls = %+v, want exactly one failed", observer.snapshot())
	}
}

type failingEnqueueQueue struct{}

func (failingEnqueueQueue) Enqueue(context.Context, string, []byte) (string, error) {
	return "", errors.New("queue unavailable")
}
func (failingEnqueueQueue) Claim(context.Context, time.Duration, ...string) (*ports.QueuedJob, error) {
	return nil, nil
}
func (failingEnqueueQueue) Heartbeat(context.Context, string, int64, time.Duration) error {
	return nil
}
func (failingEnqueueQueue) Complete(context.Context, string, int64) error { return nil }
func (failingEnqueueQueue) Fail(context.Context, string, int64, time.Duration) error {
	return nil
}
func (failingEnqueueQueue) Retry(context.Context, string, int64, time.Duration) error {
	return nil
}
func (failingEnqueueQueue) Deadletter(context.Context, string, int64) error { return nil }
func (failingEnqueueQueue) Depth(context.Context, ...string) (int, error)   { return 0, nil }
func (failingEnqueueQueue) Stats(context.Context, ...string) (ports.JobStats, error) {
	return ports.JobStats{}, nil
}

func strPtr(s string) *string { return &s }
