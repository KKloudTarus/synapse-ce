package dastrun

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	ddast "github.com/KKloudTarus/synapse-ce/internal/domain/dastrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/dastrunner"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var t0 = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

type fakeProber struct {
	result dastrunner.Result
	err    error
	calls  int
}

func (f *fakeProber) Run(_ context.Context, _ string, _, _ shared.ID, _ dastrunner.Probe) (dastrunner.Result, error) {
	f.calls++
	return f.result, f.err
}

type fakeAudit struct{ entries []ports.AuditEntry }

func (f *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	f.entries = append(f.entries, e)
	return nil
}

type fixedClock struct{}

func (fixedClock) Now() time.Time { return t0 }

type fixedIDs struct{ n int }

func (g *fixedIDs) NewID() shared.ID { g.n++; return shared.ID("run-" + time.Duration(g.n).String()) }

func newHarness(t *testing.T, prober Prober) (*Service, *memory.DASTRunStore, ports.JobQueue) {
	t.Helper()
	runs := memory.NewDASTRunStore()
	queue := memory.NewJobQueue(&fixedIDs{}, func() time.Time { return t0 })
	runs.SetQueue(queue)
	svc, err := NewService(runs, prober, &fakeAudit{}, fixedClock{}, &fixedIDs{})
	if err != nil {
		t.Fatal(err)
	}
	return svc, runs, queue
}

func tenantCtx() context.Context { return shared.WithTenant(context.Background(), "t1") }

func TestSubmitPersistsAndEnqueues(t *testing.T) {
	svc, runs, queue := newHarness(t, &fakeProber{})
	run, err := svc.Submit(tenantCtx(), "eng-1", "act-1", "alice", dastrunner.Probe{URL: "https://app.example.test"})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if run.Status != ddast.RunQueued {
		t.Errorf("submitted run status = %s, want queued", run.Status)
	}
	got, err := runs.GetDASTRun(tenantCtx(), "t1", run.ID)
	if err != nil {
		t.Fatalf("run not persisted: %v", err)
	}
	if got.EngagementID != "eng-1" || got.ActionID != "act-1" || got.Actor != "alice" {
		t.Errorf("persisted run fields wrong: %+v", got)
	}
	job, err := queue.Claim(context.Background(), time.Minute, JobKind)
	if err != nil || job == nil {
		t.Fatalf("no job enqueued: %v", err)
	}
}

func TestRunJobExecutesAndRecordsVerdict(t *testing.T) {
	prober := &fakeProber{result: dastrunner.Result{Proof: "confirmed", Status: 200, Evidence: "ev-1"}}
	svc, runs, queue := newHarness(t, prober)
	run, _ := svc.Submit(tenantCtx(), "eng-1", "act-1", "alice", dastrunner.Probe{URL: "https://app.example.test"})
	job, _ := queue.Claim(context.Background(), time.Minute, JobKind)

	if err := svc.RunJob(tenantCtx(), job.Payload); err != nil {
		t.Fatalf("RunJob: %v", err)
	}
	if prober.calls != 1 {
		t.Errorf("prober called %d times, want 1", prober.calls)
	}
	got, _ := runs.GetDASTRun(tenantCtx(), "t1", run.ID)
	if got.Status != ddast.RunSucceeded || got.Verdict != "confirmed" || got.HTTPStatus != 200 || got.EvidenceID != "ev-1" {
		t.Fatalf("run not recorded as succeeded with verdict: %+v", got)
	}
}

func TestRunJobRecordsFailureAndDoesNotRetry(t *testing.T) {
	prober := &fakeProber{err: errors.New("probe refused")}
	svc, runs, queue := newHarness(t, prober)
	run, _ := svc.Submit(tenantCtx(), "eng-1", "act-1", "alice", dastrunner.Probe{URL: "https://app.example.test"})
	job, _ := queue.Claim(context.Background(), time.Minute, JobKind)

	// A probe failure is terminal (the approval is consumed): RunJob records it and returns nil, so the
	// queue does not retry a run that cannot succeed.
	if err := svc.RunJob(tenantCtx(), job.Payload); err != nil {
		t.Fatalf("RunJob should not surface a probe failure for retry: %v", err)
	}
	got, _ := runs.GetDASTRun(tenantCtx(), "t1", run.ID)
	if got.Status != ddast.RunFailed || got.ErrorCode == "" {
		t.Fatalf("run not recorded as failed: %+v", got)
	}
}

func TestRunJobIsIdempotentOnTerminalRun(t *testing.T) {
	prober := &fakeProber{result: dastrunner.Result{Proof: "confirmed", Status: 200, Evidence: "ev-1"}}
	svc, _, queue := newHarness(t, prober)
	_, _ = svc.Submit(tenantCtx(), "eng-1", "act-1", "alice", dastrunner.Probe{URL: "https://app.example.test"})
	job, _ := queue.Claim(context.Background(), time.Minute, JobKind)
	if err := svc.RunJob(tenantCtx(), job.Payload); err != nil {
		t.Fatal(err)
	}
	// A redelivery of the same job must not execute the probe again.
	if err := svc.RunJob(tenantCtx(), job.Payload); err != nil {
		t.Fatalf("redelivered RunJob: %v", err)
	}
	if prober.calls != 1 {
		t.Errorf("prober called %d times across a redelivery, want 1", prober.calls)
	}
}

func TestRunJobRejectsTenantMismatch(t *testing.T) {
	svc, _, queue := newHarness(t, &fakeProber{})
	_, _ = svc.Submit(tenantCtx(), "eng-1", "act-1", "alice", dastrunner.Probe{URL: "https://app.example.test"})
	job, _ := queue.Claim(context.Background(), time.Minute, JobKind)
	// A worker running the job under a different tenant context must refuse it.
	if err := svc.RunJob(shared.WithTenant(context.Background(), "t2"), job.Payload); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("tenant-mismatch RunJob = %v, want ErrValidation", err)
	}
}

func TestRunJobDoesNotReExecuteAnInterruptedRun(t *testing.T) {
	// A prior delivery started the probe (run is 'running') and died before recording the outcome. A
	// redelivery must NOT re-run the probe (it may already have consumed the single-use approval); it
	// terminalizes the run 'interrupted' instead of re-admitting a consumed approval and clobbering a
	// real success with a false forbidden.
	prober := &fakeProber{err: shared.ErrForbidden}
	svc, runs, queue := newHarness(t, prober)
	run, _ := svc.Submit(tenantCtx(), "eng-1", "act-1", "alice", dastrunner.Probe{URL: "https://app.example.test"})
	job, _ := queue.Claim(context.Background(), time.Minute, JobKind)
	// Simulate the crash: mark the run running and persist it, as the first delivery would have.
	started := run
	if err := started.Start(); err != nil {
		t.Fatal(err)
	}
	if err := runs.SaveDASTRun(tenantCtx(), started); err != nil {
		t.Fatal(err)
	}
	if err := svc.RunJob(tenantCtx(), job.Payload); err != nil {
		t.Fatalf("RunJob on a running run: %v", err)
	}
	if prober.calls != 0 {
		t.Errorf("prober called %d times on an interrupted run, want 0", prober.calls)
	}
	got, _ := runs.GetDASTRun(tenantCtx(), "t1", run.ID)
	if got.Status != ddast.RunFailed || got.ErrorCode != "interrupted" {
		t.Fatalf("interrupted run = %+v, want failed/interrupted", got)
	}
}

func TestRunJobWithoutProberFailsEgressUnavailable(t *testing.T) {
	// A worker with no live scoped egress (nil prober) must still terminalize an enqueued run so it is
	// operator-visible, not orphaned at 'queued' forever.
	svc, runs, queue := newHarness(t, nil)
	run, _ := svc.Submit(tenantCtx(), "eng-1", "act-1", "alice", dastrunner.Probe{URL: "https://app.example.test"})
	job, _ := queue.Claim(context.Background(), time.Minute, JobKind)
	if err := svc.RunJob(tenantCtx(), job.Payload); err != nil {
		t.Fatalf("RunJob without prober: %v", err)
	}
	got, _ := runs.GetDASTRun(tenantCtx(), "t1", run.ID)
	if got.Status != ddast.RunFailed || got.ErrorCode != "egress_unavailable" {
		t.Fatalf("run without prober = %+v, want failed/egress_unavailable", got)
	}
}

// staleStartStore returns a queued run from Get but always loses the StartRun compare-and-set, simulating
// a redelivery where another worker started or finished the run between our Get and our StartRun.
type staleStartStore struct {
	run          ddast.Run
	finishCalls  int
	terminWrites int
}

func (s *staleStartStore) SaveDASTRun(context.Context, ddast.Run) error { s.terminWrites++; return nil }
func (s *staleStartStore) GetDASTRun(context.Context, shared.ID, shared.ID) (ddast.Run, error) {
	return s.run, nil
}
func (s *staleStartStore) StartRun(context.Context, shared.ID, ddast.Run) (bool, error) {
	return false, nil
}
func (s *staleStartStore) FinishRun(context.Context, shared.ID, ddast.Run) (bool, error) {
	s.finishCalls++
	return false, nil
}
func (s *staleStartStore) EnqueueDASTRun(context.Context, ddast.Run, string, []byte) error {
	return nil
}

func TestRunJobDoesNotProbeWhenStartRunLost(t *testing.T) {
	run, err := ddast.NewRun("run-x", "t1", "eng-1", "act-1", "alice", t0)
	if err != nil {
		t.Fatal(err)
	}
	prober := &fakeProber{result: dastrunner.Result{Proof: "confirmed", Status: 200, Evidence: "ev"}}
	svc, err := NewService(&staleStartStore{run: run}, prober, &fakeAudit{}, fixedClock{}, &fixedIDs{})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(jobPayload{TenantID: "t1", RunID: "run-x", Probe: dastrunner.Probe{URL: "https://app.example.test"}})
	if err := svc.RunJob(tenantCtx(), payload); err != nil {
		t.Fatalf("RunJob: %v", err)
	}
	if prober.calls != 0 {
		t.Errorf("prober called %d times after losing the start CAS, want 0", prober.calls)
	}
}

func TestSubmitRejectsCredentialBearingURL(t *testing.T) {
	// A malformed or credential-bearing target must be rejected at the edge, before the probe is persisted
	// on the durable job (parity with the old synchronous path).
	svc, runs, queue := newHarness(t, &fakeProber{})
	_, err := svc.Submit(tenantCtx(), "eng-1", "act-1", "alice", dastrunner.Probe{URL: "https://app.example.test/?token=secret"})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("Submit with credential URL = %v, want ErrValidation", err)
	}
	// Nothing was enqueued or persisted.
	if job, _ := queue.Claim(context.Background(), time.Minute, JobKind); job != nil {
		t.Fatal("an invalid submit enqueued a job")
	}
	_ = runs
}

func TestRunJobPreservesSealedEvidenceOnFailure(t *testing.T) {
	// A transport-level probe error can still carry sealed evidence; the failed run must surface it.
	prober := &fakeProber{result: dastrunner.Result{Status: 502, Evidence: "ev-seal"}, err: errors.New("probe transport error")}
	svc, runs, queue := newHarness(t, prober)
	run, _ := svc.Submit(tenantCtx(), "eng-1", "act-1", "alice", dastrunner.Probe{URL: "https://app.example.test"})
	job, _ := queue.Claim(context.Background(), time.Minute, JobKind)
	if err := svc.RunJob(tenantCtx(), job.Payload); err != nil {
		t.Fatalf("RunJob: %v", err)
	}
	got, _ := runs.GetDASTRun(tenantCtx(), "t1", run.ID)
	if got.Status != ddast.RunFailed || got.EvidenceID != "ev-seal" || got.HTTPStatus != 502 {
		t.Fatalf("failed run did not preserve sealed evidence: %+v", got)
	}
}

func TestRunJobTerminalizesInvalidSuccessResult(t *testing.T) {
	// A nil-error result missing its proof/evidence is not a valid success. It must terminalize (approval
	// already consumed), not be returned to the queue for retry.
	prober := &fakeProber{result: dastrunner.Result{Status: 200}} // no Proof, no Evidence, nil error
	svc, runs, queue := newHarness(t, prober)
	run, _ := svc.Submit(tenantCtx(), "eng-1", "act-1", "alice", dastrunner.Probe{URL: "https://app.example.test"})
	job, _ := queue.Claim(context.Background(), time.Minute, JobKind)
	if err := svc.RunJob(tenantCtx(), job.Payload); err != nil {
		t.Fatalf("RunJob returned an invalid-result error to the queue: %v", err)
	}
	got, _ := runs.GetDASTRun(tenantCtx(), "t1", run.ID)
	if got.Status != ddast.RunFailed || got.ErrorCode != "invalid_result" {
		t.Fatalf("invalid success result not terminalized: %+v", got)
	}
}

func TestRunJobWithoutProberDoesNotClobberWhenStartLost(t *testing.T) {
	// An egress-less worker that loses the StartRun claim (a capable peer already owns the run) must return
	// without any terminal write, so it cannot clobber the peer's live run with egress_unavailable.
	run, err := ddast.NewRun("run-y", "t1", "eng-1", "act-1", "alice", t0)
	if err != nil {
		t.Fatal(err)
	}
	store := &staleStartStore{run: run}
	svc, err := NewService(store, nil, &fakeAudit{}, fixedClock{}, &fixedIDs{})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(jobPayload{TenantID: "t1", RunID: "run-y", Probe: dastrunner.Probe{URL: "https://app.example.test"}})
	if err := svc.RunJob(tenantCtx(), payload); err != nil {
		t.Fatalf("RunJob: %v", err)
	}
	if store.finishCalls != 0 || store.terminWrites != 0 {
		t.Fatalf("worker that lost the claim wrote the run: finishCalls=%d terminWrites=%d", store.finishCalls, store.terminWrites)
	}
}
