package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/migrations"
)

func TestLeaderStore(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM leader_leases WHERE resource='sched-test'`)
	})

	s := NewLeaderStore(pool)
	const term = 15 * time.Second
	now := time.Now().UTC()

	// A wins; B (contending under the same live lease) does not.
	heldA, fenceA, err := s.Acquire(ctx, "sched-test", "inst-a", term, now)
	if err != nil || !heldA {
		t.Fatalf("A should acquire: held=%v err=%v", heldA, err)
	}
	heldB, _, err := s.Acquire(ctx, "sched-test", "inst-b", term, now)
	if err != nil {
		t.Fatalf("B acquire err: %v", err)
	}
	if heldB {
		t.Fatalf("B must not hold a live foreign lease")
	}

	// A renews (same holder) without bumping the fence.
	heldA2, fenceA2, err := s.Acquire(ctx, "sched-test", "inst-a", term, now.Add(5*time.Second))
	if err != nil || !heldA2 || fenceA2 != fenceA {
		t.Fatalf("A renewal should keep the lease and fence: held=%v fence=%d/%d err=%v", heldA2, fenceA2, fenceA, err)
	}

	// After the term expires, B takes over and the fence is bumped.
	heldB2, fenceB, err := s.Acquire(ctx, "sched-test", "inst-b", term, now.Add(term+10*time.Second))
	if err != nil || !heldB2 {
		t.Fatalf("B should take over an expired lease: held=%v err=%v", heldB2, err)
	}
	if fenceB <= fenceA {
		t.Fatalf("takeover must bump the fence: %d -> %d", fenceA, fenceB)
	}

	// B resigns; A can acquire immediately even before the term expires, and the fence must NOT
	// go backwards across the resign+reacquire (Resign expires, it does not drop the row).
	if err := s.Resign(ctx, "sched-test", "inst-b", now.Add(term+11*time.Second)); err != nil {
		t.Fatalf("resign: %v", err)
	}
	heldA3, fenceA3, err := s.Acquire(ctx, "sched-test", "inst-a", term, now.Add(term+12*time.Second))
	if err != nil || !heldA3 {
		t.Fatalf("A should acquire immediately after B resigned: held=%v err=%v", heldA3, err)
	}
	if fenceA3 <= fenceB {
		t.Fatalf("fence must not decrease across resign+reacquire: fenceB=%d fenceA3=%d", fenceB, fenceA3)
	}
}

// TestMigration0061 exercises the migration down and back up.
func TestMigration0061(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db := openLockedGooseDB(t, dsn)
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("dialect: %v", err)
	}
	if err := goose.DownTo(db, ".", 60); err != nil {
		t.Fatalf("down to 60: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	_, err = pool.Exec(ctx, `SELECT 1 FROM leader_leases LIMIT 1`)
	var pgErr *pgconn.PgError
	if err == nil || !errors.As(err, &pgErr) || pgErr.Code != "42P01" {
		t.Fatalf("leader_leases should be undefined after down to 60, got %v", err)
	}
	if err := goose.UpTo(db, ".", 61); err != nil {
		t.Fatalf("up to 61: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT 1 FROM leader_leases LIMIT 1`); err != nil {
		t.Fatalf("leader_leases should exist after up to 61: %v", err)
	}
	// It is deliberately NOT under RLS (global control-plane state).
	var forced bool
	if err := pool.QueryRow(ctx, `SELECT relforcerowsecurity FROM pg_class WHERE relname='leader_leases'`).Scan(&forced); err != nil {
		t.Fatalf("relforce: %v", err)
	}
	if forced {
		t.Fatalf("leader_leases must NOT be RLS-forced (global control-plane state)")
	}
}
