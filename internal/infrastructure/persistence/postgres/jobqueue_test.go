package postgres

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
)

// dsn returns the test database DSN, or skips when none is configured (so the suite
// stays green without a DB; CI / the local docker probe sets SYNAPSE_TEST_DB_DSN).
func testDSN(t *testing.T) string {
	t.Helper()
	d := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if d == "" {
		t.Skip("SYNAPSE_TEST_DB_DSN not set – skipping Postgres integration test")
	}
	return d
}

func setupJobQueue(t *testing.T) (*JobQueue, context.Context) {
	t.Helper()
	dsn := testDSN(t)
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, "TRUNCATE jobs CASCADE"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return NewJobQueue(pool, idgen.RandomID{}), shared.WithTenant(ctx, shared.DefaultTenant)
}

func TestPostgresJobQueueConcurrentClaimSkipLocked(t *testing.T) {
	q, ctx := setupJobQueue(t)
	a, _ := q.Enqueue(ctx, "recon", []byte("1"))
	b, _ := q.Enqueue(ctx, "sca", []byte("2"))

	// Two concurrent claimants must get two DISTINCT jobs (FOR UPDATE SKIP LOCKED).
	var wg sync.WaitGroup
	got := make([]string, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if j, err := q.Claim(ctx, 30*time.Second); err == nil && j != nil {
				got[i] = j.ID
			}
		}(i)
	}
	wg.Wait()
	if got[0] == "" || got[1] == "" || got[0] == got[1] {
		t.Fatalf("two concurrent claims must yield two distinct jobs, got %v (a=%s b=%s)", got, a, b)
	}
	// Nothing left to claim.
	if j, _ := q.Claim(ctx, 30*time.Second); j != nil {
		t.Fatalf("queue should be drained, got %+v", j)
	}
}

func TestPostgresJobQueueLeaseReclaim(t *testing.T) {
	q, ctx := setupJobQueue(t)
	id, _ := q.Enqueue(ctx, "recon", nil)

	first, err := q.Claim(ctx, 1*time.Second) // short lease
	if err != nil || first == nil || first.ID != id {
		t.Fatalf("first claim: %+v err=%v", first, err)
	}
	// Immediately, it's leased – not claimable.
	if j, _ := q.Claim(ctx, 1*time.Second); j != nil {
		t.Fatalf("leased job must not be re-claimed, got %+v", j)
	}
	time.Sleep(1500 * time.Millisecond) // let the lease expire
	second, err := q.Claim(ctx, 5*time.Second)
	if err != nil || second == nil || second.ID != id || second.Attempts != 2 {
		t.Fatalf("expired lease must be reclaimable as attempt 2: %+v err=%v", second, err)
	}
	if err := q.Complete(ctx, id); err != nil {
		t.Fatal(err)
	}
	if j, _ := q.Claim(ctx, time.Second); j != nil {
		t.Fatalf("completed job must not be claimable, got %+v", j)
	}
}

// TestPostgresJobQueueClaimByKind covers the kind = ANY($2) filter – a worker
// claims only its kinds. Gated on SYNAPSE_TEST_DB_DSN.
func TestPostgresJobQueueClaimByKind(t *testing.T) {
	q, ctx := setupJobQueue(t)
	_, _ = q.Enqueue(ctx, "recon", []byte("r"))
	_, _ = q.Enqueue(ctx, "sca", []byte("s"))
	j, err := q.Claim(ctx, 30*time.Second, "sca")
	if err != nil || j == nil || j.Kind != "sca" {
		t.Fatalf("an sca worker must claim the sca job, got %+v err=%v", j, err)
	}
	if j2, _ := q.Claim(ctx, 30*time.Second, "sca"); j2 != nil {
		t.Errorf("an sca worker must NOT claim the recon job, got %+v", j2)
	}
	if j3, _ := q.Claim(ctx, 30*time.Second, "recon"); j3 == nil || j3.Kind != "recon" {
		t.Fatalf("a recon worker must claim the recon job, got %+v", j3)
	}
}

// TestPostgresJobQueueAggregateJobQueueStatsAcrossTenants covers the operator metrics
// seam: AggregateJobQueueStats must sum every tenant's RLS-scoped Stats (mirroring
// Claim's per-tenant transaction loop), never a privileged cross-tenant query, and must
// never require or expose a tenant label on the result. Gated on SYNAPSE_TEST_DB_DSN.
func TestPostgresJobQueueAggregateJobQueueStatsAcrossTenants(t *testing.T) {
	q, ctx := setupJobQueue(t)
	tenantA := shared.DefaultTenant
	_, _ = q.Enqueue(ctx, "sca", []byte("a"))

	otherTenant := shared.ID("other-tenant")
	// The tenants schema requires name, so keep this fixture schema-valid instead of relying on an implicit default.
	if _, err := q.pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, $1) ON CONFLICT DO NOTHING`, otherTenant.String()); err != nil {
		t.Fatalf("seed second tenant: %v", err)
	}
	ctxB := shared.WithTenant(context.Background(), otherTenant)
	if _, err := q.Enqueue(ctxB, "sca", []byte("b")); err != nil {
		t.Fatalf("enqueue tenant b: %v", err)
	}

	stats, err := q.AggregateJobQueueStats(context.Background(), "sca")
	if err != nil {
		t.Fatal(err)
	}
	if stats.Queued != 2 {
		t.Fatalf("aggregate queued = %d, want 2 (across tenant %s and %s)", stats.Queued, tenantA, otherTenant)
	}
}
