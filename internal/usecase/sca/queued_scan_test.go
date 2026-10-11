package sca

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type deferredScanQueue struct {
	ports.JobQueue
	payloads [][]byte
}

func (q *deferredScanQueue) Enqueue(_ context.Context, _ string, p []byte) (string, error) {
	q.payloads = append(q.payloads, append([]byte(nil), p...))
	return fmt.Sprintf("queued-%d", len(q.payloads)), nil
}
func queuedScanFixture(t *testing.T) (*Service, *deferredScanQueue, *memory.ScanJobStore, *fakeAcquirer, context.Context) {
	t.Helper()
	acq := &fakeAcquirer{dir: t.TempDir()}
	s := newSvc(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, fakeClock{t: time.Unix(0, 0).UTC()}, acq, &fakeAudit{}, &fakeDetector{})
	q := &deferredScanQueue{}
	jobs := memory.NewScanJobStore()
	s.jobs, s.ids = jobs, &sequenceIDs{}
	s.SetQueue(q)
	return s, q, jobs, acq, shared.WithTenant(context.Background(), "tenant")
}
func TestQueuedWebhookScansWaitForRunningSlotAndExecuteAllRefs(t *testing.T) {
	s, q, jobs, acq, ctx := queuedScanFixture(t)
	var ids []string
	for _, ref := range []string{"feature/one", "feature/two"} {
		j, err := s.StartQueuedScanWithOptions(ctx, "hook", "e1", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "myrepo", Ref: ref}, ScanOptions{NoBuildExecution: true})
		if err != nil {
			t.Fatalf("enqueue %s: %v", ref, err)
		}
		ids = append(ids, j.ID)
		if _, err := jobs.GetJob(ctx, j.ID); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("queue reserved running slot: %v", err)
		}
	}
	busy := ports.ScanJob{ID: "busy", EngagementID: "e1", Target: "myrepo", Kind: ports.TargetLocal, Status: ports.ScanRunning}
	if err := jobs.CreateRunning(ctx, busy); err != nil {
		t.Fatal(err)
	}
	if err := s.RunScanJob(ctx, q.payloads[0]); !errors.Is(err, ports.ErrRetryable) {
		t.Fatalf("contention must preserve delivery attempt: %v", err)
	}
	if acq.cleaned != 0 {
		t.Fatal("contending scan executed")
	}
	busy.Status = ports.ScanSucceeded
	if err := jobs.Save(ctx, busy); err != nil {
		t.Fatal(err)
	}
	if err := s.RunScanJob(ctx, q.payloads[0]); err != nil {
		t.Fatal(err)
	}
	newer := busy
	newer.ID = "newer"
	newer.Status = ports.ScanRunning
	if err := jobs.CreateRunning(ctx, newer); err != nil {
		t.Fatal(err)
	}
	// A newer latest job must not make a completed delivery execute again.
	if err := s.RunScanJob(ctx, q.payloads[0]); err != nil {
		t.Fatal(err)
	}
	if acq.cleaned != 1 {
		t.Fatal("terminal delivery reran after a newer scan")
	}
	newer.Status = ports.ScanSucceeded
	if err := jobs.Save(ctx, newer); err != nil {
		t.Fatal(err)
	}
	if err := s.RunScanJob(ctx, q.payloads[1]); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		j, err := jobs.GetJob(ctx, id)
		if err != nil || j.Status != ports.ScanSucceeded {
			t.Fatalf("scan %s: %+v %v", id, j, err)
		}
	}
	if acq.cleaned != 2 {
		t.Fatalf("executed %d scans, want 2", acq.cleaned)
	}
}
func TestDeferredScanDeadletterIsVisibleBeforeFirstExecution(t *testing.T) {
	s, q, jobs, _, ctx := queuedScanFixture(t)
	j, err := s.StartQueuedScanWithOptions(ctx, "hook", "e1", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "myrepo"}, ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.FailStrandedScanJob(ctx, q.payloads[0], errors.New("admission unavailable")); err != nil {
		t.Fatal(err)
	}
	stored, err := jobs.GetJob(ctx, j.ID)
	if err != nil || stored.Status != ports.ScanFailed || stored.Stage != "dead-letter" {
		t.Fatalf("invisible abandoned scan: %+v %v", stored, err)
	}
}
func TestDeferredScanRejectsMalformedJobStateWithoutExecution(t *testing.T) {
	s, q, _, acq, ctx := queuedScanFixture(t)
	if _, err := s.StartQueuedScanWithOptions(ctx, "hook", "e1", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "myrepo"}, ScanOptions{}); err != nil {
		t.Fatal(err)
	}
	var p scaJobPayload
	if err := json.Unmarshal(q.payloads[0], &p); err != nil {
		t.Fatal(err)
	}
	p.Job.Status = "unknown"
	bad, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RunScanJob(ctx, bad); !errors.Is(err, shared.ErrValidation) || acq.cleaned != 0 {
		t.Fatalf("malformed admission: %v", err)
	}
}

func TestDeferredScanRechecksRevokedScopeBeforeExecution(t *testing.T) {
	s, q, _, acq, ctx := queuedScanFixture(t)
	if _, err := s.StartQueuedScanWithOptions(ctx, "hook", "e1", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "myrepo"}, ScanOptions{}); err != nil {
		t.Fatal(err)
	}
	s.engagements.(*fakeEngRepo).eng.Scope.InScope = nil
	if err := s.RunScanJob(ctx, q.payloads[0]); !errors.Is(err, shared.ErrForbidden) || acq.called {
		t.Fatalf("revoked scope executed: %v", err)
	}
}

func TestDeferredDeadletterRejectsAnotherScansIdentity(t *testing.T) {
	s, q, jobs, _, ctx := queuedScanFixture(t)
	j, err := s.StartQueuedScanWithOptions(ctx, "hook", "e1", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "myrepo"}, ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	other := j
	other.EngagementID = "another-engagement"
	if err := jobs.CreateRunning(ctx, other); err != nil {
		t.Fatal(err)
	}
	if err := s.FailStrandedScanJob(ctx, q.payloads[0], errors.New("invalid delivery")); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("mismatched identity: %v", err)
	}
	stored, err := jobs.GetJob(ctx, j.ID)
	if err != nil || stored.Status != ports.ScanRunning {
		t.Fatalf("another scan was finalized: %+v %v", stored, err)
	}
}
