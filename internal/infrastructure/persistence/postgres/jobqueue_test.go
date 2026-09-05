package postgres

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
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
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	adminPool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(adminPool.Close)
	if _, err := adminPool.Exec(ctx, "TRUNCATE jobs CASCADE"); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	var superuser, bypass bool
	if err := adminPool.QueryRow(ctx, `
		SELECT rolsuper, rolbypassrls
		FROM pg_roles
		WHERE rolname = current_user
	`).Scan(&superuser, &bypass); err != nil {
		t.Fatalf("inspect postgres test role: %v", err)
	}
	if !superuser && !bypass {
		return NewJobQueue(adminPool, idgen.RandomID{}), shared.WithTenant(ctx, shared.DefaultTenant)
	}

	role := "jobqueue_test_" + randHex(t)
	for _, statement := range []string{
		"CREATE ROLE " + role + " LOGIN PASSWORD 'test-password' NOSUPERUSER NOBYPASSRLS",
		"GRANT USAGE ON SCHEMA public TO " + role,
		"GRANT SELECT, INSERT, UPDATE, DELETE ON jobs TO " + role,
		"GRANT SELECT, INSERT, DELETE ON tenants TO " + role,
	} {
		if _, err := adminPool.Exec(ctx, statement); err != nil {
			t.Fatalf("setup runtime role %s: %v", role, err)
		}
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = adminPool.Exec(bg, "DROP OWNED BY "+role)
		_, _ = adminPool.Exec(bg, "DROP ROLE IF EXISTS "+role)
	})

	runtimeConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse runtime pool config: %v", err)
	}
	runtimeConfig.ConnConfig.User = role
	runtimeConfig.ConnConfig.Password = "test-password"
	runtimePool, err := pgxpool.NewWithConfig(ctx, runtimeConfig)
	if err != nil {
		t.Fatalf("connect runtime pool: %v", err)
	}
	t.Cleanup(runtimePool.Close)

	return NewJobQueue(runtimePool, idgen.RandomID{}), shared.WithTenant(ctx, shared.DefaultTenant)
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
	if second.Fence <= first.Fence {
		t.Fatalf("reclaim fence = %d, want greater than first fence %d", second.Fence, first.Fence)
	}
	if err := q.Complete(ctx, id, first.Fence); !errors.Is(err, ports.ErrStaleLease) {
		t.Fatalf("stale complete = %v, want ErrStaleLease", err)
	}
	if err := q.Complete(ctx, id, second.Fence); err != nil {
		t.Fatal(err)
	}
	if j, _ := q.Claim(ctx, time.Second); j != nil {
		t.Fatalf("completed job must not be claimable, got %+v", j)
	}
}

func TestPostgresJobQueueStaleLeaseMutations(t *testing.T) {
	operations := []struct {
		name string
		call func(*JobQueue, context.Context, string, int64) error
	}{
		{"complete", func(q *JobQueue, ctx context.Context, id string, fence int64) error {
			return q.Complete(ctx, id, fence)
		}},
		{"fail", func(q *JobQueue, ctx context.Context, id string, fence int64) error { return q.Fail(ctx, id, fence, 0) }},
		{"retry", func(q *JobQueue, ctx context.Context, id string, fence int64) error {
			return q.Retry(ctx, id, fence, 0)
		}},
		{"deadletter", func(q *JobQueue, ctx context.Context, id string, fence int64) error {
			return q.Deadletter(ctx, id, fence)
		}},
		{"heartbeat", func(q *JobQueue, ctx context.Context, id string, fence int64) error {
			return q.Heartbeat(ctx, id, fence, time.Minute)
		}},
	}
	for _, tt := range operations {
		t.Run(tt.name, func(t *testing.T) {
			q, ctx := setupJobQueue(t)
			id, err := q.Enqueue(ctx, "recon", nil)
			if err != nil {
				t.Fatal(err)
			}
			first, err := q.Claim(ctx, time.Second)
			if err != nil || first == nil {
				t.Fatalf("first claim = %+v, %v", first, err)
			}
			time.Sleep(1500 * time.Millisecond)
			second, err := q.Claim(ctx, time.Minute)
			if err != nil || second == nil || second.Fence <= first.Fence {
				t.Fatalf("reclaim = %+v, %v", second, err)
			}
			if err := tt.call(q, ctx, id, first.Fence); !errors.Is(err, ports.ErrStaleLease) {
				t.Fatalf("stale %s = %v, want ErrStaleLease", tt.name, err)
			}
			if err := q.Heartbeat(ctx, id, second.Fence, time.Minute); err != nil {
				t.Fatalf("current fence heartbeat: %v", err)
			}
		})
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

func TestLogicalQueueTenantIDsDeduplicatesLegacyDefault(t *testing.T) {
	got := logicalQueueTenantIDs([]shared.ID{"", shared.DefaultTenant, "other-tenant"})
	want := []shared.ID{shared.DefaultTenant, "other-tenant"}
	if len(got) != len(want) {
		t.Fatalf("logical tenant count = %d, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("logical tenant %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestPostgresJobQueueAggregateJobQueueStatsAcrossTenants covers the operator metrics
// seam: AggregateJobQueueStats must sum every tenant's RLS-scoped Stats (mirroring
// Claim's per-tenant transaction loop), never a privileged cross-tenant query, and must
// never require or expose a tenant label on the result. Gated on SYNAPSE_TEST_DB_DSN.
func TestPostgresJobQueueRetryDoesNotBurnAttempt(t *testing.T) {
	q, ctx := setupJobQueue(t)
	id, err := q.Enqueue(ctx, "recon", nil)
	if err != nil {
		t.Fatal(err)
	}
	job, err := q.Claim(ctx, time.Minute)
	if err != nil || job == nil || job.Attempts != 1 {
		t.Fatalf("claim = %+v, %v", job, err)
	}
	if err := q.Retry(ctx, id, job.Fence, time.Minute); err != nil {
		t.Fatal(err)
	}
	status, err := q.JobStatus(ctx, id)
	if err != nil || status.Attempts != 0 || status.DeadLettered {
		t.Fatalf("retry status = %+v, %v", status, err)
	}
}

func TestPostgresJobQueueAggregateJobQueueStatsAcrossTenants(t *testing.T) {
	q, ctx := setupJobQueue(t)
	// AggregateJobQueueStats sums per-tenant Stats over every tenant row, so the total is
	// only meaningful when RLS actually constrains each per-tenant read. Under a
	// SUPERUSER/BYPASSRLS role every iteration sees every tenant's jobs and the sum
	// multiplies by the tenant count — a property of the DSN, not of the code under test.
	if err := CheckRLSRuntimeRole(ctx, q.pool); err != nil {
		t.Skipf("cross-tenant queue aggregation requires an RLS-enforcing runtime role: %v", err)
	}
	tenantA := shared.DefaultTenant
	if _, err := q.Enqueue(ctx, "sca", []byte("a")); err != nil {
		t.Fatalf("enqueue default tenant: %v", err)
	}

	otherTenant := shared.ID("other-tenant-" + randHex(t))
	if _, err := q.pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, $1) ON CONFLICT DO NOTHING`, otherTenant.String()); err != nil {
		t.Fatalf("seed second tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = q.pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, otherTenant.String())
	})
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
