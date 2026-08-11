package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	pcdom "github.com/KKloudTarus/synapse-ce/internal/domain/purplecoverage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestMigration0077PurpleCoverage(t *testing.T) {
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
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	id := randHex(t)
	tenantA, tenantB := shared.ID("pc-a-"+id), shared.ID("pc-b-"+id)
	engA := "pc-eng-" + id
	for _, stmt := range []struct {
		q    string
		args []any
	}{
		{`INSERT INTO tenants(id,name) VALUES($1,$1),($2,$2)`, []any{tenantA.String(), tenantB.String()}},
		{`INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'pc-eng')`, []any{engA, tenantA.String()}},
	} {
		if _, err := pool.Exec(ctx, stmt.q, stmt.args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM purple_coverage WHERE tenant_id IN ($1,$2)`, tenantA.String(), tenantB.String())
		_, _ = pool.Exec(bg, `DELETE FROM engagements WHERE tenant_id IN ($1,$2)`, tenantA.String(), tenantB.String())
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id IN ($1,$2)`, tenantA.String(), tenantB.String())
		_, _ = pool.Exec(bg, `DROP OWNED BY pc_runtime`)
		_, _ = pool.Exec(bg, `DROP ROLE IF EXISTS pc_runtime`)
	})

	repo := NewPurpleRepository(pool)
	tctx := shared.WithTenant(ctx, tenantA)
	when := time.Unix(1700, 0).UTC()
	cov := []pcdom.Coverage{
		{TenantID: tenantA, RunID: shared.ID("run-1"), TechniqueID: "emu.a", EngagementID: shared.ID(engA),
			AssetID: "asset-1", TaxonomyRef: "T1", Expected: "det.a", Actual: []string{"det.a"}, Verdict: pcdom.VerdictCovered, ComputedAt: when},
		{TenantID: tenantA, RunID: shared.ID("run-1"), TechniqueID: "emu.b", EngagementID: shared.ID(engA),
			AssetID: "asset-1", TaxonomyRef: "T2", Expected: "det.b", Actual: nil, Verdict: pcdom.VerdictGap, ComputedAt: when},
	}
	if err := repo.SaveCoverage(tctx, cov); err != nil {
		t.Fatalf("save: %v", err)
	}
	// Round-trip preserves verdict + actual list.
	got, err := repo.ListByRun(tctx, "run-1")
	if err != nil || len(got) != 2 {
		t.Fatalf("list by run = %d (%v), want 2", len(got), err)
	}
	if got[0].TechniqueID != "emu.a" || got[0].Verdict != pcdom.VerdictCovered || len(got[0].Actual) != 1 {
		t.Fatalf("round-trip lost coverage detail: %+v", got[0])
	}
	// Trend by engagement returns the same rows.
	if trend, err := repo.ListByEngagement(tctx, shared.ID(engA)); err != nil || len(trend) != 2 {
		t.Fatalf("trend = %d (%v), want 2", len(trend), err)
	}
	// Re-computation of the same run+technique replaces in place (upsert, not duplicate).
	cov[1].Verdict = pcdom.VerdictCovered
	cov[1].Actual = []string{"det.b"}
	if err := repo.SaveCoverage(tctx, cov); err != nil {
		t.Fatalf("re-save: %v", err)
	}
	if got, _ := repo.ListByRun(tctx, "run-1"); len(got) != 2 || got[1].Verdict != pcdom.VerdictCovered {
		t.Fatalf("upsert must replace in place, got %d rows, emu.b verdict %s", len(got), got[1].Verdict)
	}

	// RLS under a NOSUPERUSER role: tenant B must see none of tenant A's coverage.
	role := "pc_runtime"
	for _, q := range []string{
		`DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='` + role + `') THEN EXECUTE 'DROP OWNED BY ` + role + `'; EXECUTE 'DROP ROLE ` + role + `'; END IF; END $$`,
		`CREATE ROLE ` + role + ` NOSUPERUSER NOBYPASSRLS`,
		`GRANT USAGE ON SCHEMA public TO ` + role,
		`GRANT SELECT ON purple_coverage TO ` + role,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("prepare rls role: %v", err)
		}
	}
	countAs := func(tenant shared.ID) int {
		var n int
		tc := shared.WithTenant(context.Background(), tenant)
		if err := WithTenant(tc, pool, tenant.String(), func(tx pgx.Tx) error {
			if _, err := tx.Exec(tc, `SET LOCAL ROLE `+role); err != nil {
				return err
			}
			return tx.QueryRow(tc, `SELECT count(*) FROM purple_coverage`).Scan(&n)
		}); err != nil {
			t.Fatalf("count as %s: %v", tenant, err)
		}
		return n
	}
	if got := countAs(tenantB); got != 0 {
		t.Errorf("tenant B sees %d of tenant A's coverage; RLS is not isolating", got)
	}
	if got := countAs(tenantA); got != 2 {
		t.Errorf("tenant A sees %d of its own coverage, want 2", got)
	}

	// The taxonomy CHECK: coverage with an empty taxonomy_ref is unstorable (coverage must be expressed
	// against the public taxonomy).
	_, ckErr := pool.Exec(ctx, `INSERT INTO purple_coverage
		(tenant_id, run_id, technique_id, engagement_id, taxonomy_ref, verdict, computed_at)
		VALUES ($1,'run-x','emu.x',$2,'','gap', now())`, tenantA.String(), engA)
	if ckErr == nil {
		t.Error("coverage with no taxonomy reference must fail the CHECK")
	}
}
