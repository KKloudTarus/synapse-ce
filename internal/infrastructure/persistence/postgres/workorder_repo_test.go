package postgres

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
	"github.com/KKloudTarus/synapse-ce/migrations"
)

func newWO(t *testing.T, idem string, bucket int64) *workorder.WorkOrder {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	wo, err := workorder.New(shared.ID("wo-"+idem), "wt", "as1", "ag1", "scan.source", "eng1", idem, now.Add(time.Hour), bucket, now)
	if err != nil {
		t.Fatalf("new wo: %v", err)
	}
	wo.Signature = "sig"
	return wo
}

func TestWorkOrderRepository(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ('wt','WT') ON CONFLICT (id) DO NOTHING`); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM work_orders WHERE tenant_id='wt'`)
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id='wt'`)
	})

	repo := NewWorkOrderRepository(pool)

	// FORCE RLS on the table.
	var forced bool
	if err := pool.QueryRow(ctx, `SELECT relforcerowsecurity FROM pg_class WHERE relname='work_orders'`).Scan(&forced); err != nil {
		t.Fatalf("relforce: %v", err)
	}
	if !forced {
		t.Fatalf("FORCE ROW LEVEL SECURITY not set on work_orders")
	}

	// Issue + roundtrip.
	wo := newWO(t, "idem1", 1)
	got, err := repo.Issue(ctx, wo)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if got.ID != wo.ID || got.State != workorder.StateIssued {
		t.Fatalf("issue roundtrip mismatch: %+v", got)
	}

	// Idempotent re-issue: same order id, no conflict.
	again, err := repo.Issue(ctx, newWO(t, "idem1", 1))
	if err != nil {
		t.Fatalf("re-issue: %v", err)
	}
	if again.ID != wo.ID {
		t.Fatalf("idempotent issue must return the same order: %q vs %q", again.ID, wo.ID)
	}

	// In-flight conflict: different idempotency key, same (asset, capability, bucket) while live.
	conflict := newWO(t, "idem2", 1)
	if _, err := repo.Issue(ctx, conflict); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("expected in-flight ErrConflict, got %v", err)
	}

	// Claim addressed to the agent; another agent claims nothing.
	none, err := repo.Claim(ctx, "wt", "other-agent", 10, time.Now().UTC())
	if err != nil {
		t.Fatalf("claim other: %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("other agent must claim nothing, got %d", len(none))
	}
	claimed, err := repo.Claim(ctx, "wt", "ag1", 10, time.Now().UTC())
	if err != nil {
		t.Fatalf("claim ag1: %v", err)
	}
	if len(claimed) != 1 || claimed[0].State != workorder.StateClaimed {
		t.Fatalf("ag1 should claim one order into claimed, got %+v", claimed)
	}

	// Transition CAS: claimed -> running with correct expected state.
	tnow := time.Now().UTC()
	if err := repo.Transition(ctx, "wt", wo.ID, workorder.StateRunning, "", workorder.StateClaimed, tnow); err != nil {
		t.Fatalf("claimed->running: %v", err)
	}
	// Stale expected state now conflicts.
	if err := repo.Transition(ctx, "wt", wo.ID, workorder.StateSucceeded, "", workorder.StateClaimed, tnow); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale expected state must ErrConflict, got %v", err)
	}
	// A transition on a non-existent order is ErrNotFound, not ErrConflict.
	if err := repo.Transition(ctx, "wt", "missing", workorder.StateRunning, "", workorder.StateClaimed, tnow); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("transition on missing order must ErrNotFound, got %v", err)
	}

	// GetByID + not found.
	if _, err := repo.GetByID(ctx, "wt", wo.ID); err != nil {
		t.Fatalf("get: %v", err)
	}
	if _, err := repo.GetByID(ctx, "wt", "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	// ListByTenant (coverage projection, #413): returns this tenant's orders and is tenant-scoped —
	// a different tenant sees none of them (RLS + explicit tenant_id filter).
	mine, err := repo.ListByTenant(ctx, "wt")
	if err != nil {
		t.Fatalf("list by tenant: %v", err)
	}
	if len(mine) == 0 {
		t.Fatalf("ListByTenant(wt) must return the seeded orders, got 0")
	}
	for _, o := range mine {
		if o.TenantID != "wt" {
			t.Fatalf("ListByTenant leaked a foreign tenant's order: %q", o.TenantID)
		}
	}
	other, err := repo.ListByTenant(ctx, "someone-else")
	if err != nil {
		t.Fatalf("list by other tenant: %v", err)
	}
	if len(other) != 0 {
		t.Fatalf("ListByTenant must be tenant-scoped; foreign tenant saw %d orders", len(other))
	}
}

// TestMigration0059 exercises the migration down and back up.
func TestMigration0059(t *testing.T) {
	sharedDSN := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if sharedDSN == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	dsn := isolatedMigration0059DSN(t, sharedDSN)
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db, err := goose.OpenDBWithDriver("pgx", dsn)
	if err != nil {
		t.Fatalf("goose open: %v", err)
	}
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("dialect: %v", err)
	}
	if err := goose.DownTo(db, ".", 58); err != nil {
		t.Fatalf("down to 58: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	_, err = pool.Exec(ctx, `SELECT 1 FROM work_orders LIMIT 1`)
	var pgErr *pgconn.PgError
	if err == nil || !errors.As(err, &pgErr) || pgErr.Code != "42P01" {
		t.Fatalf("work_orders should be undefined after down to 58, got %v", err)
	}
	if err := goose.UpTo(db, ".", 59); err != nil {
		t.Fatalf("up to 59: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT 1 FROM work_orders LIMIT 1`); err != nil {
		t.Fatalf("work_orders should exist after up to 59: %v", err)
	}
}

// isolatedMigration0059DSN creates a disposable database so this historical down/up test never
// rolls the shared integration schema back while other packages are using it.
func isolatedMigration0059DSN(t *testing.T, sharedDSN string) string {
	t.Helper()

	u, err := url.Parse(sharedDSN)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		t.Fatalf("parse PostgreSQL test DSN for isolated migration test: %v", err)
	}
	name := fmt.Sprintf("synapse_migration_0059_%d", time.Now().UnixNano())
	isolated := *u
	isolated.Path = "/" + name
	isolated.RawPath = ""

	ctx := context.Background()
	admin, err := Connect(ctx, sharedDSN)
	if err != nil {
		t.Fatalf("connect shared PostgreSQL database for isolated migration test: %v", err)
	}
	quotedName := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quotedName); err != nil {
		admin.Close()
		t.Fatalf("create isolated migration database: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = admin.Exec(cleanupCtx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1`, name)
		if _, err := admin.Exec(cleanupCtx, "DROP DATABASE "+quotedName); err != nil {
			t.Errorf("drop isolated migration database: %v", err)
		}
		admin.Close()
	})
	return isolated.String()
}
