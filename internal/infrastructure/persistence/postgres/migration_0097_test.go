package postgres

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerabilityreconcile"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/migrations"
)

func TestMigration0097ReconciliationRunAtomicityCASAndIsolation(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() {
		if err := MigrateLocked(context.Background(), dsn); err != nil {
			t.Errorf("restore migrations: %v", err)
		}
	})
	db := openLockedGooseDB(t, dsn)
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownTo(db, ".", 96); err != nil {
		t.Fatalf("down to 0096: %v", err)
	}
	if err := goose.UpTo(db, ".", 97); err != nil {
		t.Fatalf("up 0097: %v", err)
	}
	if err := goose.UpTo(db, ".", 99); err != nil {
		t.Fatalf("up to current reconciliation store schema: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	var forced bool
	if err := pool.QueryRow(ctx, `SELECT relforcerowsecurity FROM pg_class WHERE relname='vulnerability_reconciliation_runs'`).Scan(&forced); err != nil || !forced {
		t.Fatalf("vulnerability_reconciliation_runs FORCE RLS=%v err=%v", forced, err)
	}

	prefix := "m97-" + randHex(t)
	tenantA, tenantB := shared.ID(prefix+"-a"), shared.ID(prefix+"-b")
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1),($2,$2)`, tenantA.String(), tenantB.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM vulnerability_reconciliation_runs WHERE tenant_id IN ($1,$2)`, tenantA.String(), tenantB.String())
		_, _ = pool.Exec(bg, `DELETE FROM jobs WHERE tenant_id IN ($1,$2)`, tenantA.String(), tenantB.String())
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id IN ($1,$2)`, tenantA.String(), tenantB.String())
	})

	store := NewVulnerabilityReconcileRunStore(pool, idgen.RandomID{})
	ctxA := shared.WithTenant(ctx, tenantA)
	run, created, err := store.Start(ctxA, ports.VulnerabilityReconcileStart{
		Scope: vulnerabilityreconcile.ScopeTenant, ClientIdempotencyKey: "operator-retry", JobPayload: []byte(`{}`), Checkpoint: []byte(`{"phase":"correlate"}`),
	})
	if err != nil || !created {
		t.Fatalf("start run=%+v created=%v err=%v", run, created, err)
	}
	var runCount, jobCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM vulnerability_reconciliation_runs WHERE tenant_id=$1 AND id=$2`, tenantA.String(), run.ID.String()).Scan(&runCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE tenant_id=$1 AND id=$2 AND kind=$3`, tenantA.String(), run.DurableJobID, vulnerabilityreconcile.JobKind).Scan(&jobCount); err != nil {
		t.Fatal(err)
	}
	if runCount != 1 || jobCount != 1 {
		t.Fatalf("atomic run/job counts=%d/%d", runCount, jobCount)
	}
	existing, duplicateCreated, err := store.Start(ctxA, ports.VulnerabilityReconcileStart{
		Scope: vulnerabilityreconcile.ScopeTenant, ClientIdempotencyKey: "operator-retry", JobPayload: []byte(`{}`), Checkpoint: []byte(`{"phase":"correlate"}`),
	})
	if err != nil || duplicateCreated || existing.ID != run.ID || existing.DurableJobID != run.DurableJobID {
		t.Fatalf("duplicate run=%+v created=%v err=%v", existing, duplicateCreated, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE tenant_id=$1 AND kind=$2`, tenantA.String(), vulnerabilityreconcile.JobKind).Scan(&jobCount); err != nil || jobCount != 1 {
		t.Fatalf("duplicate job count=%d err=%v", jobCount, err)
	}

	if err := store.MarkRunning(ctxA, run.ID); err != nil {
		t.Fatal(err)
	}
	_, err = store.Advance(ctxA, run.ID, []byte(`{"phase":"wrong"}`), []byte(`{"phase":"retire"}`), vulnerabilityreconcile.Counts{}, nil)
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale checkpoint must conflict, got %v", err)
	}
	if _, err := store.Get(shared.WithTenant(ctx, tenantB), run.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant get must be not found, got %v", err)
	}
	if _, err := store.Advance(ctxA, run.ID, run.Checkpoint, []byte(`{"phase":"retire"}`), vulnerabilityreconcile.Counts{Processed: 1}, nil); err != nil {
		t.Fatalf("valid CAS advance: %v", err)
	}
	if _, err := store.Finish(ctxA, run.ID, vulnerabilityreconcile.StateSucceeded, vulnerabilityreconcile.Counts{Processed: 1}, nil); err != nil {
		t.Fatalf("finish: %v", err)
	}
}
