package postgres

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ownership"
	ownershipuc "github.com/KKloudTarus/synapse-ce/internal/usecase/ownership"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ownershipQueryCounter struct{ statements atomic.Int64 }

func (c *ownershipQueryCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	c.statements.Add(1)
	return ctx
}
func (*ownershipQueryCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// This representative-scale acceptance test is opt-in because it intentionally
// creates and routes 10,000 rows using the same per-finding atomic commit path as
// production. Run it before release with SYNAPSE_OWNERSHIP_SCALE_TEST=1 and a
// disposable POSTGRES_TEST_DSN; the measured result belongs in the operator guide.
func TestOwnershipRepresentativeScale(t *testing.T) {
	if os.Getenv("SYNAPSE_OWNERSHIP_SCALE_TEST") != "1" {
		t.Skip("set SYNAPSE_OWNERSHIP_SCALE_TEST=1 for the 10k ownership acceptance fixture")
	}
	f := newOwnershipFixture(t)
	rules := make([]ownership.Rule, 200)
	for i := range 199 {
		rules[i] = ownership.Rule{ID: fmt.Sprintf("non-match-%03d", i+1), Priority: i, When: ownership.Conditions{Kinds: []string{"quality"}}, TeamID: "ops"}
	}
	rules[199] = ownership.Rule{ID: "default-team", Priority: 199, TeamID: "pay"}
	policy := ownership.PolicyVersion{TenantID: "own-a", PolicyID: "scale-policy", EngagementID: "own-a-eng", Version: 1, Rules: rules, CreatedBy: "alice", CreatedAt: time.Now().UTC()}
	if err := f.repo.CreatePolicyVersion(f.ctx, policy); err != nil {
		t.Fatal(err)
	}
	if err := f.repo.ActivatePolicy(f.ctx, ports.OwnershipActivation{PolicyID: policy.PolicyID, Version: 1, ExpectedRevision: 1, ExpectedHash: policy.Hash()}); err != nil {
		t.Fatal(err)
	}
	if err := WithTenant(f.ctx, f.pool, "own-a", func(tx pgx.Tx) error {
		_, err := tx.Exec(f.ctx, `INSERT INTO findings(id,tenant_id,engagement_id,title,severity,status,kind,dedup_key,created_at,updated_at) SELECT 'scale-'||lpad(g::text,5,'0'),'own-a','own-a-eng','Scale finding '||g,'high','open',$1,'scale-'||g,now(),now() FROM generate_series(1,10000) g`, finding.KindSAST)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	counter := &ownershipQueryCounter{}
	config := f.pool.Config().Copy()
	config.ConnConfig.Tracer = counter
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	repo, err := NewOwnershipRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	ids := &ownershipTestIDs{}
	queue := NewJobQueue(pool, ids)
	store, err := NewOwnershipExecution(repo, ids, ownershipWallClock{})
	if err != nil {
		t.Fatal(err)
	}
	worker, err := ownershipuc.NewWorker(store, repo, "enforce", false, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	counter.statements.Store(0)
	started := time.Now()
	dispatched, jobs := 0, 0
	maxHeap := before.HeapAlloc
	for dispatched < 10000 {
		n, err := worker.Poll(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		dispatched += n
		job, err := queue.Claim(f.ctx, time.Minute, ownershipuc.RouteJobKind)
		if err != nil {
			t.Fatal(err)
		}
		if job == nil {
			t.Fatalf("dispatcher stopped after %d findings", dispatched)
		}
		if err := worker.Handle(f.ctx, *job); err != nil {
			t.Fatal(err)
		}
		if err := queue.Complete(f.ctx, job.ID, job.Fence); err != nil {
			t.Fatal(err)
		}
		var current runtime.MemStats
		runtime.ReadMemStats(&current)
		if current.HeapAlloc > maxHeap {
			maxHeap = current.HeapAlloc
		}
		jobs++
	}
	duration := time.Since(started)
	statements := counter.statements.Load()
	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc

	var assigned int
	if err := WithTenant(f.ctx, pool, "own-a", func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT count(*) FROM ownership_assignments WHERE tenant_id='own-a' AND finding_id LIKE 'scale-%' AND team_id='pay'`).Scan(&assigned)
	}); err != nil {
		t.Fatal(err)
	}
	if assigned != 10000 || jobs > 103 {
		t.Fatalf("assigned=%d jobs=%d", assigned, jobs)
	}
	t.Logf("ownership scale: findings=10000 rules=200 jobs=%d duration=%s max_heap_bytes=%d total_allocated_bytes=%d traced_sql_statements=%d", jobs, duration, maxHeap, allocated, statements)
	if duration > 3*time.Minute || maxHeap > 512<<20 || allocated > 8<<30 {
		t.Fatalf("scale budget exceeded: duration=%s max_heap=%d total_allocated=%d", duration, maxHeap, allocated)
	}
}
