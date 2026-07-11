package postgres

import (
	"context"
	"testing"
	"time"
)

// TestLeaseRunLockMutualExclusion proves the row-lease run lock serializes runs across owners
// (≈ processes) WITHOUT pinning a connection, and is re-acquirable after release. Gated on
// SYNAPSE_TEST_DB_DSN. Mirrors the advisory RunLock test but for the lease implementation.
func TestLeaseRunLockMutualExclusion(t *testing.T) {
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

	a := NewLeaseRunLock(pool, "owner-A", time.Minute)
	b := NewLeaseRunLock(pool, "owner-B", time.Minute)

	rel, ok, err := a.TryLock(ctx, "runLease1")
	if err != nil || !ok {
		t.Fatalf("first lease should succeed: ok=%v err=%v", ok, err)
	}
	// The lease does NOT hold a pooled connection – verify the pool isn't pinned.
	if got := pool.Stat().AcquiredConns(); got != 0 {
		t.Fatalf("lease must not pin a pooled connection, AcquiredConns=%d", got)
	}
	if _, ok2, _ := b.TryLock(ctx, "runLease1"); ok2 {
		t.Fatal("a second owner must NOT acquire a held, unexpired lease")
	}
	rel()
	rel2, ok3, _ := b.TryLock(ctx, "runLease1")
	if !ok3 {
		t.Fatal("the lease must be re-acquirable by another owner after release")
	}
	rel2()
}
