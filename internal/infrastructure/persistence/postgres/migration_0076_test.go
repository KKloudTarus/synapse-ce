package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestMigration0076ResponseActions(t *testing.T) {
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
	tenantA, tenantB := shared.ID("rsp-a-"+id), shared.ID("rsp-b-"+id)
	engA := "rsp-eng-" + id
	for _, stmt := range []struct {
		q    string
		args []any
	}{
		{`INSERT INTO tenants(id,name) VALUES($1,$1),($2,$2)`, []any{tenantA.String(), tenantB.String()}},
		{`INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'rsp-eng')`, []any{engA, tenantA.String()}},
	} {
		if _, err := pool.Exec(ctx, stmt.q, stmt.args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM response_actions WHERE tenant_id IN ($1,$2)`, tenantA.String(), tenantB.String())
		_, _ = pool.Exec(bg, `DELETE FROM engagements WHERE tenant_id IN ($1,$2)`, tenantA.String(), tenantB.String())
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id IN ($1,$2)`, tenantA.String(), tenantB.String())
		_, _ = pool.Exec(bg, `DROP OWNED BY rsp_runtime`)
		_, _ = pool.Exec(bg, `DROP ROLE IF EXISTS rsp_runtime`)
	})

	repo := NewResponseRepository(pool)
	tctx := shared.WithTenant(ctx, tenantA)
	sp, _ := rdom.SpecFor(rdom.KindIsolateHost)
	rec := rdom.Record{
		ID: shared.ID("rec-" + id), TenantID: tenantA, EngagementID: shared.ID(engA),
		Action: rdom.Action{ID: shared.ID("rec-" + id), Kind: rdom.KindIsolateHost, Target: "host-1",
			BlastRadius: offensivepolicy.RadiusStateChanging, Argv: []string{"synapse-agent-response", "isolate-host", "host-1"}, Reversal: sp.Reversal},
		State: rdom.StatePending, ApprovedBy: "alice", UpdatedAt: time.Unix(1000, 0).UTC(),
	}
	if err := repo.Put(tctx, rec); err != nil {
		t.Fatalf("put: %v", err)
	}
	// Get round-trips the action incl. its reversal.
	got, found, err := repo.Get(tctx, rec.ID)
	if err != nil || !found {
		t.Fatalf("get: found=%v err=%v", found, err)
	}
	if got.Action.Reversal.Kind != rdom.ReversalRestoreHost || len(got.Action.Argv) != 3 {
		t.Fatalf("round-trip lost action detail: %+v", got.Action)
	}
	// State transition upsert.
	rec.State = rdom.StateApplied
	rec.AppliedAt = time.Unix(1001, 0).UTC()
	if err := repo.Put(tctx, rec); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if applied, _ := repo.ListByState(tctx, rdom.StateApplied); len(applied) != 1 {
		t.Fatalf("want 1 applied record, got %d", len(applied))
	}

	// RLS under a NOSUPERUSER role.
	role := "rsp_runtime"
	for _, q := range []string{
		`DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='` + role + `') THEN EXECUTE 'DROP OWNED BY ` + role + `'; EXECUTE 'DROP ROLE ` + role + `'; END IF; END $$`,
		`CREATE ROLE ` + role + ` NOSUPERUSER NOBYPASSRLS`,
		`GRANT USAGE ON SCHEMA public TO ` + role,
		`GRANT SELECT ON response_actions TO ` + role,
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
			return tx.QueryRow(tc, `SELECT count(*) FROM response_actions`).Scan(&n)
		}); err != nil {
			t.Fatalf("count as %s: %v", tenant, err)
		}
		return n
	}
	if got := countAs(tenantB); got != 0 {
		t.Errorf("tenant B sees %d of tenant A's response actions; RLS is not isolating", got)
	}
	if got := countAs(tenantA); got != 1 {
		t.Errorf("tenant A sees %d of its own actions, want 1", got)
	}

	// The reversal CHECK: a row whose reversal JSON lacks a kind is unstorable.
	_, ckErr := pool.Exec(ctx, `INSERT INTO response_actions
		(tenant_id, id, engagement_id, kind, target, blast_radius, argv, reversal, state)
		VALUES ($1,'bad',$2,'isolate_host','host-1','state_changing','[]'::jsonb,'{}'::jsonb,'pending')`,
		tenantA.String(), engA)
	if ckErr == nil {
		t.Error("a reversal with no kind must fail the CHECK (reversibility is mandatory)")
	}
}
