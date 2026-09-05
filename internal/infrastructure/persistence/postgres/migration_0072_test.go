package postgres

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	dexploit "github.com/KKloudTarus/synapse-ce/internal/domain/exploitation"
	"github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestMigration0072ExploitationChains(t *testing.T) {
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
	tenantA, tenantB := shared.ID("ec-a-"+id), shared.ID("ec-b-"+id)
	engA := "ec-eng-" + id
	for _, stmt := range []struct {
		q    string
		args []any
	}{
		{`INSERT INTO tenants(id,name) VALUES($1,$1),($2,$2)`, []any{tenantA.String(), tenantB.String()}},
		{`INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'chain-eng')`, []any{engA, tenantA.String()}},
	} {
		if _, err := pool.Exec(ctx, stmt.q, stmt.args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	t.Cleanup(func() {
		bg := context.Background()
		for _, q := range []string{
			`DELETE FROM exploitation_steps WHERE tenant_id IN ($1,$2)`,
			`DELETE FROM exploitation_chains WHERE tenant_id IN ($1,$2)`,
			`DELETE FROM engagements WHERE tenant_id IN ($1,$2)`,
			`DELETE FROM tenants WHERE id IN ($1,$2)`,
		} {
			if _, err := pool.Exec(bg, q, tenantA.String(), tenantB.String()); err != nil {
				t.Errorf("cleanup %q: %v (next run will fail)", q, err)
			}
		}
	})

	repo := NewExploitationChainRepository(pool)
	ctx = shared.WithTenant(ctx, tenantA)

	chain, err := dexploit.NewChain(shared.ID("chain-"+id), tenantA, shared.ID(engA), "path-1", []dexploit.Step{
		{Ordinal: 0, Technique: "exploit.web_shell_upload", Target: "asset-1", Proposer: "agent:planner",
			BlastRadius: offensivepolicy.RadiusStateChanging,
			Cleanup:     offensivepolicy.CleanupSpec{Steps: []string{"delete artifact"}, Verification: "verify absence"}},
		{Ordinal: 1, Technique: "recon.service_banner", Target: "asset-1", Proposer: "agent:planner",
			BlastRadius: offensivepolicy.RadiusReadOnly},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.SaveChain(ctx, chain); err != nil {
		t.Fatalf("save chain: %v", err)
	}

	// Round-trip: advance the first step and re-save; the update must persist.
	_ = chain.BeginStep()
	_ = chain.RecordExecuted("ev-0", true)
	if err := repo.SaveChain(ctx, chain); err != nil {
		t.Fatalf("re-save chain: %v", err)
	}
	var executed bool
	if err := WithTenant(ctx, pool, tenantA.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT executed FROM exploitation_steps WHERE tenant_id=$1 AND chain_id=$2 AND ordinal=0`,
			tenantA.String(), chain.ID.String()).Scan(&executed)
	}); err != nil {
		t.Fatalf("read step 0: %v", err)
	}
	if !executed {
		t.Error("step 0 executed flag did not persist")
	}

	// RLS: tenant B sees no chains of tenant A. The pool connects as a superuser, which BYPASSES RLS,
	// so isolation is proven under a NOSUPERUSER NOBYPASSRLS role the way a real runtime connects —
	// the superuser would see everything regardless of the policy.
	role := "exploit_chain_runtime"
	for _, q := range []string{
		`DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='` + role + `') THEN EXECUTE 'DROP OWNED BY ` + role + `'; EXECUTE 'DROP ROLE ` + role + `'; END IF; END $$`,
		`CREATE ROLE ` + role + ` NOSUPERUSER NOBYPASSRLS`,
		`GRANT USAGE ON SCHEMA public TO ` + role,
		`GRANT SELECT ON exploitation_chains, exploitation_steps TO ` + role,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("prepare rls role: %v", err)
		}
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DROP OWNED BY `+role)
		_, _ = pool.Exec(bg, `DROP ROLE IF EXISTS `+role)
	})
	var count int
	bctx := shared.WithTenant(context.Background(), tenantB)
	if err := WithTenant(bctx, pool, tenantB.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(bctx, `SET LOCAL ROLE `+role); err != nil {
			return err
		}
		return tx.QueryRow(bctx, `SELECT count(*) FROM exploitation_chains`).Scan(&count)
	}); err != nil {
		t.Fatalf("count as tenant B: %v", err)
	}
	if count != 0 {
		t.Errorf("tenant B sees %d of tenant A's chains; RLS is not isolating", count)
	}
	// And as tenant A the runtime role sees exactly its own chain — RLS isolates, it does not blind.
	var ownCount int
	actx := shared.WithTenant(context.Background(), tenantA)
	if err := WithTenant(actx, pool, tenantA.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(actx, `SET LOCAL ROLE `+role); err != nil {
			return err
		}
		return tx.QueryRow(actx, `SELECT count(*) FROM exploitation_chains`).Scan(&ownCount)
	}); err != nil {
		t.Fatalf("count as tenant A: %v", err)
	}
	if ownCount != 1 {
		t.Errorf("tenant A sees %d of its own chains, want 1; RLS is over-filtering", ownCount)
	}

	// Composite FK: a step naming a chain in a DIFFERENT tenant is unstorable.
	_, fkErr := pool.Exec(ctx, `
		INSERT INTO exploitation_steps (tenant_id, chain_id, ordinal, technique, target, proposer, blast_radius, cleanup, state, executed)
		VALUES ($1,$2,9,'recon.service_banner','x','p','read_only','{}','pending',false)`,
		tenantB.String(), chain.ID.String())
	var pgErr *pgconn.PgError
	if !errors.As(fkErr, &pgErr) || pgErr.Code != "23503" {
		t.Fatalf("a cross-tenant step must fail with an FK violation, got %v", fkErr)
	}

	// CHECK: a state-changing step with no cleanup path is rejected by the database, mirroring the
	// domain's construction-time refusal.
	_, ckErr := pool.Exec(ctx, `
		INSERT INTO exploitation_steps (tenant_id, chain_id, ordinal, technique, target, proposer, blast_radius, cleanup, state, executed)
		VALUES ($1,$2,8,'exploit.x','x','p','state_changing','{}','pending',false)`,
		tenantA.String(), chain.ID.String())
	if !errors.As(ckErr, &pgErr) || pgErr.Code != "23514" {
		t.Fatalf("a state-changing step with no cleanup must fail a CHECK, got %v", ckErr)
	}
}
