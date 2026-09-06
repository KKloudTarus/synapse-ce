package postgres

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	demu "github.com/KKloudTarus/synapse-ce/internal/domain/emulation"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestMigration0073EmulationRuns(t *testing.T) {
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
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	id := randHex(t)
	tenantA, tenantB := shared.ID("em-a-"+id), shared.ID("em-b-"+id)
	engA := "em-eng-" + id
	for _, stmt := range []struct {
		q    string
		args []any
	}{
		{`INSERT INTO tenants(id,name) VALUES($1,$1),($2,$2)`, []any{tenantA.String(), tenantB.String()}},
		{`INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'emu-eng')`, []any{engA, tenantA.String()}},
	} {
		if _, err := pool.Exec(ctx, stmt.q, stmt.args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	t.Cleanup(func() {
		bg := context.Background()
		for _, q := range []string{
			`DELETE FROM emulation_coverage WHERE tenant_id IN ($1,$2)`,
			`DELETE FROM emulation_runs WHERE tenant_id IN ($1,$2)`,
			`DELETE FROM engagements WHERE tenant_id IN ($1,$2)`,
			`DELETE FROM tenants WHERE id IN ($1,$2)`,
		} {
			if _, err := pool.Exec(bg, q, tenantA.String(), tenantB.String()); err != nil {
				t.Errorf("cleanup %q: %v (next run will fail)", q, err)
			}
		}
		_, _ = pool.Exec(bg, `DROP OWNED BY emu_run_runtime`)
		_, _ = pool.Exec(bg, `DROP ROLE IF EXISTS emu_run_runtime`)
	})

	repo := NewEmulationRunRepository(pool)
	ctx = shared.WithTenant(ctx, tenantA)
	run := demu.Run{
		ID: shared.ID("run-" + id), TenantID: tenantA, EngagementID: shared.ID(engA), Target: "asset-x", Actor: "operator",
		Coverage: []demu.CoverageRecord{
			// executed, no detection → gap
			{TechniqueID: "emu.process_discovery", TaxonomyRef: "T1057", Executed: true, Expected: "det.process_enumeration", Actual: "", Gap: true},
			// not executed → not a gap
			{TechniqueID: "emu.service_restart_probe", TaxonomyRef: "T1569.002", Executed: false, Expected: "det.unexpected_service_restart", Actual: "", Gap: false},
		},
	}
	if err := repo.SaveRun(ctx, run); err != nil {
		t.Fatalf("save run: %v", err)
	}

	// RLS under a NOSUPERUSER NOBYPASSRLS role (the pool superuser bypasses RLS).
	role := "emu_run_runtime"
	for _, q := range []string{
		`DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='` + role + `') THEN EXECUTE 'DROP OWNED BY ` + role + `'; EXECUTE 'DROP ROLE ` + role + `'; END IF; END $$`,
		`CREATE ROLE ` + role + ` NOSUPERUSER NOBYPASSRLS`,
		`GRANT USAGE ON SCHEMA public TO ` + role,
		`GRANT SELECT ON emulation_runs, emulation_coverage TO ` + role,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("prepare rls role: %v", err)
		}
	}
	countAs := func(tenant shared.ID) int {
		var n int
		tctx := shared.WithTenant(context.Background(), tenant)
		if err := WithTenant(tctx, pool, tenant.String(), func(tx pgx.Tx) error {
			if _, err := tx.Exec(tctx, `SET LOCAL ROLE `+role); err != nil {
				return err
			}
			return tx.QueryRow(tctx, `SELECT count(*) FROM emulation_coverage`).Scan(&n)
		}); err != nil {
			t.Fatalf("count as %s: %v", tenant, err)
		}
		return n
	}
	if got := countAs(tenantB); got != 0 {
		t.Errorf("tenant B sees %d of tenant A's coverage rows; RLS is not isolating", got)
	}
	if got := countAs(tenantA); got != 2 {
		t.Errorf("tenant A sees %d of its own coverage rows, want 2; RLS is over-filtering", got)
	}

	// Composite FK: a coverage row for a run in another tenant is unstorable.
	_, fkErr := pool.Exec(ctx, `
		INSERT INTO emulation_coverage (tenant_id, run_id, technique_id, taxonomy_ref, executed, expected_detection, gap)
		VALUES ($1,$2,'emu.x','T0',false,'det.x',false)`, tenantB.String(), run.ID.String())
	var pgErr *pgconn.PgError
	if !errors.As(fkErr, &pgErr) || pgErr.Code != "23503" {
		t.Fatalf("a cross-tenant coverage row must fail an FK violation, got %v", fkErr)
	}

	// CHECK: a row that claims gap=true while not executed is inconsistent and must be rejected.
	_, ckErr := pool.Exec(ctx, `
		INSERT INTO emulation_coverage (tenant_id, run_id, technique_id, taxonomy_ref, executed, expected_detection, actual_detection, gap)
		VALUES ($1,$2,'emu.bad','T0',false,'det.x',NULL,true)`, tenantA.String(), run.ID.String())
	if !errors.As(ckErr, &pgErr) || pgErr.Code != "23514" {
		t.Fatalf("a gap inconsistent with executed/detection must fail a CHECK, got %v", ckErr)
	}
	// And a matched detection (actual == expected) recorded as a gap must also be rejected.
	_, ckErr2 := pool.Exec(ctx, `
		INSERT INTO emulation_coverage (tenant_id, run_id, technique_id, taxonomy_ref, executed, expected_detection, actual_detection, gap)
		VALUES ($1,$2,'emu.bad2','T0',true,'det.x','det.x',true)`, tenantA.String(), run.ID.String())
	if !errors.As(ckErr2, &pgErr) || pgErr.Code != "23514" {
		t.Fatalf("a matched detection recorded as a gap must fail a CHECK, got %v", ckErr2)
	}

	// The store derives the write tenant from the context and rejects a run that claims a different one,
	// so a producer cannot write into another tenant's partition (defense in depth over RLS).
	foreign := run
	foreign.TenantID = shared.ID("tenant-foreign-0073")
	if err := repo.SaveRun(ctx, foreign); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("cross-tenant SaveRun = %v, want ErrForbidden", err)
	}
}
