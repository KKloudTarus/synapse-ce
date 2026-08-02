package orchestrator_test

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/orchestrator"
)

type fakeResumableLister struct{ sessions []agent.Session }

func (f fakeResumableLister) TenantIDs(_ context.Context) ([]shared.ID, error) {
	return []shared.ID{""}, nil
}

func (f fakeResumableLister) ListResumable(_ context.Context, _ time.Duration, _ time.Time, _ int) ([]agent.Session, error) {
	return f.sessions, nil
}

type fakeEnqueuer struct {
	kinds    []string
	payloads [][]byte
}

func (f *fakeEnqueuer) Enqueue(_ context.Context, kind string, payload []byte) (string, error) {
	f.kinds = append(f.kinds, kind)
	f.payloads = append(f.payloads, payload)
	return "job-1", nil
}

func reconcilerFor(t *testing.T, sessions []agent.Session) (*orchestrator.Reconciler, *fakeEnqueuer) {
	t.Helper()
	enq := &fakeEnqueuer{}
	r, err := orchestrator.NewReconciler(fakeResumableLister{sessions: sessions}, enq, fixedClock{time.Unix(1_000_000, 0).UTC()}, 10*time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r, enq
}

func TestReconcileOnce_ReEnqueuesStrandedRunning(t *testing.T) {
	r, enq := reconcilerFor(t, []agent.Session{{ID: "s1", Status: agent.StatusRunning}})
	n, err := r.ReconcileOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || len(enq.kinds) != 1 {
		t.Fatalf("expected 1 re-enqueue, got n=%d kinds=%v", n, enq.kinds)
	}
	if enq.kinds[0] != orchestrator.JobKind {
		t.Fatalf("re-enqueued kind = %q, want %q", enq.kinds[0], orchestrator.JobKind)
	}
}

func TestReconcileOnce_AwaitingApprovalNotResumed(t *testing.T) {
	r, enq := reconcilerFor(t, []agent.Session{{ID: "s1", Status: agent.StatusAwaitingApproval}})
	n, err := r.ReconcileOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 || len(enq.kinds) != 0 {
		t.Fatalf("awaiting_approval must NEVER be auto-driven, got n=%d enqueues=%d", n, len(enq.kinds))
	}
}

func TestReconcileOnce_OnlyDrivesRunning(t *testing.T) {
	r, enq := reconcilerFor(t, []agent.Session{
		{ID: "s1", Status: agent.StatusRunning},
		{ID: "s2", Status: agent.StatusAwaitingApproval},
		{ID: "s3", Status: agent.StatusRunning},
	})
	n, _ := r.ReconcileOnce(context.Background())
	if n != 2 || len(enq.kinds) != 2 {
		t.Fatalf("expected 2 running re-enqueued (awaiting skipped), got n=%d enqueues=%d", n, len(enq.kinds))
	}
}

func TestNewReconciler_NilDeps(t *testing.T) {
	if _, err := orchestrator.NewReconciler(nil, &fakeEnqueuer{}, fixedClock{time.Unix(1, 0)}, time.Minute, nil); err == nil {
		t.Fatal("nil lister must fail validation")
	}
}
