package postgres

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

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

const jobQueueRLSTestRole = "synapse_jobqueue_rls_test"

// jobQueueRLSReader returns a queue whose connections are constrained by the same
// non-bypass RLS contract required from the production runtime role. The standard CI
// DSN connects as the postgres superuser, which would otherwise make every per-tenant
// Stats call see every job and cause AggregateJobQueueStats to multiply the totals by
// the number of tenants instead of actually exercising the RLS seam.
func jobQueueRLSReader(t *testing.T, ctx context.Context, admin *pgxpool.Pool) *JobQueue {
	t.Helper()

	var superuser, bypass bool
	if err := admin.QueryRow(ctx, `
		SELECT rolsuper, rolbypassrls
		FROM pg_roles
		WHERE rolname = current_user
	`).Scan(&superuser, &bypass); err != nil {
		t.Fatalf("inspect postgres test role: %v", err)
	}
	if !superuser && !bypass {
		if err := CheckRLSRuntimeRole(ctx, admin); err != nil {
			t.Fatalf("postgres integration role cannot prove queue RLS: %v", err)
		}
		return NewJobQueue(admin, idgen.RandomID{})
	}
	if !superuser {
		t.Fatalf("postgres integration role has BYPASSRLS without superuser; cannot prove queue RLS safely")
	}

	cleanupRole := func(cleanCtx context.Context) {
		_, _ = admin.Exec(cleanCtx, `DROP OWNED BY `+jobQueueRLSTestRole)
		_, _ = admin.Exec(cleanCtx, `DROP ROLE IF EXISTS `+jobQueueRLSTestRole)
	}
	cleanupRole(ctx)
	if _, err := admin.Exec(ctx, `CREATE ROLE `+jobQueueRLSTestRole+` NOLOGIN NOSUPERUSER NOBYPASSRLS`); err != nil {
		t.Fatalf("create queue RLS test role: %v", err)
	}
	// Register role cleanup before pool cleanup so LIFO closes every SET ROLE session first.
	t.Cleanup(func() { cleanupRole(context.Background()) })
	if _, err := admin.Exec(ctx, `GRANT USAGE ON SCHEMA public TO `+jobQueueRLSTestRole); err != nil {
		t.Fatalf("grant queue RLS schema access: %v", err)
	}
	if _, err := admin.Exec(ctx, `GRANT SELECT ON tenants, jobs TO `+jobQueueRLSTestRole); err != nil {
		t.Fatalf("grant queue RLS read access: %v", err)
	}

	cfg, err := pgxpool.ParseConfig(testDSN(t))
	if err != nil {
		t.Fatalf("parse postgres test config: %v", err)
	}
	previousAfterConnect := cfg.AfterConnect
	cfg.AfterConnect = func(connectCtx context.Context, conn *pgx.Conn) error {
		if previousAfterConnect != nil {
			if err := previousAfterConnect(connectCtx, conn); err != nil {
				return err
			}
		}
		_, err := conn.Exec(connectCtx, `SET ROLE `+jobQueueRLSTestRole)
		return err
	}
	restrictedPool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect queue RLS test pool: %v", err)
	}
	t.Cleanup(restrictedPool.Close)
	if err := restrictedPool.Ping(ctx); err != nil {
		t.Fatalf("ping queue RLS test pool: %v", err)
	}
	if err := CheckRLSRuntimeRole(ctx, restrictedPool); err != nil {
		t.Fatalf("queue RLS test role is not production-safe: %v", err)
	}
	return NewJobQueue(restrictedPool, idgen.RandomID{})
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
	const aggregateKind = "aggregate-jobqueue-stats-test"
	_, _ = q.Enqueue(ctx, aggregateKind, []byte("a"))

	otherTenant := shared.ID("other-tenant")
	// The tenants schema requires name, so keep this fixture schema-valid instead of relying on an implicit default.
	if _, err := q.pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, $1) ON CONFLICT DO NOTHING`, otherTenant.String()); err != nil {
		t.Fatalf("seed second tenant: %v", err)
	}
	ctxB := shared.WithTenant(context.Background(), otherTenant)
	if _, err := q.Enqueue(ctxB, aggregateKind, []byte("b")); err != nil {
		t.Fatalf("enqueue tenant b: %v", err)
	}

	reader := jobQueueRLSReader(t, context.Background(), q.pool)
	stats, err := reader.AggregateJobQueueStats(context.Background(), aggregateKind)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Queued != 2 {
		t.Fatalf("aggregate queued = %d, want 2 (across tenant %s and %s)", stats.Queued, tenantA, otherTenant)
	}
}
