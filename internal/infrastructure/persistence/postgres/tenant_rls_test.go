package postgres

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

// TestRLSFoundation proves the #432 Row-Level-Security foundation against a real Postgres: the
// synapse_enable_tenant_rls procedure produces a policy that isolates by tenant at the database,
// is fail-closed when no tenant is set, and blocks cross-tenant writes via WITH CHECK.
//
// RLS is bypassed by SUPERUSER and BYPASSRLS roles regardless of FORCE ROW LEVEL SECURITY. The
// dev Postgres connects as a superuser, so this test creates a dedicated NOSUPERUSER NOBYPASSRLS
// role and runs every RLS-sensitive statement under it via SET LOCAL ROLE. That both makes the
// test meaningful under any connecting role and documents the production requirement: the app's
// runtime DB role must not be a superuser and must not hold BYPASSRLS, or none of this is enforced.
func TestRLSFoundation(t *testing.T) {
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
	// Register pool.Close first so it runs LAST (t.Cleanup is LIFO): the schema teardown below
	// must run while the pool is still open. A plain `defer pool.Close()` would close the pool
	// before t.Cleanup fires, silently skipping the DROPs and leaking a policy that then breaks
	// the goose DownTo migration tests.
	t.Cleanup(func() { pool.Close() })

	// Fresh probe table + a NOSUPERUSER NOBYPASSRLS role that RLS actually applies to.
	setup := []string{
		`DROP TABLE IF EXISTS rls_probe_432`,
		`DROP OWNED BY rls_probe_role_432`,
		`DROP ROLE IF EXISTS rls_probe_role_432`,
		`CREATE ROLE rls_probe_role_432 NOSUPERUSER NOBYPASSRLS`,
		`CREATE TABLE rls_probe_432 (id text primary key, tenant_id text not null, v text)`,
		`GRANT USAGE ON SCHEMA public TO rls_probe_role_432`,
		`GRANT SELECT, INSERT ON rls_probe_432 TO rls_probe_role_432`,
	}
	for _, stmt := range setup {
		// DROP OWNED/ROLE may fail on first run if the role is absent; that is fine.
		_, _ = pool.Exec(ctx, stmt)
	}
	// Re-run the CREATEs authoritatively so a failure surfaces.
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS rls_probe_432 (id text primary key, tenant_id text not null, v text)`); err != nil {
		t.Fatalf("create probe: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DROP TABLE IF EXISTS rls_probe_432`)
		_, _ = pool.Exec(bg, `DROP OWNED BY rls_probe_role_432`)
		_, _ = pool.Exec(bg, `DROP ROLE IF EXISTS rls_probe_role_432`)
	})

	if _, err := pool.Exec(ctx, `CALL synapse_enable_tenant_rls($1)`, "rls_probe_432"); err != nil {
		t.Fatalf("enable rls: %v", err)
	}

	// underRole runs fn inside a WithTenant transaction, first dropping to the non-privileged role
	// so RLS is enforced. app.current_tenant is set by WithTenant (as the connecting role) before
	// the SET LOCAL ROLE and survives it, so the policy sees the tenant.
	underRole := func(tenant string, fn func(pgx.Tx) error) error {
		return WithTenant(ctx, pool, tenant, func(tx pgx.Tx) error {
			if _, e := tx.Exec(ctx, `SET LOCAL ROLE rls_probe_role_432`); e != nil {
				return e
			}
			return fn(tx)
		})
	}

	// Seed two tenants.
	seed := []struct{ tenant, id string }{{"a", "a1"}, {"a", "a2"}, {"b", "b1"}}
	for _, s := range seed {
		s := s
		if err := underRole(s.tenant, func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `INSERT INTO rls_probe_432 (id, tenant_id, v) VALUES ($1, $2, 'x')`, s.id, s.tenant)
			return e
		}); err != nil {
			t.Fatalf("seed %s: %v", s.id, err)
		}
	}

	// Isolation: tenant "a", via an INTENTIONALLY UNSCOPED select (no WHERE), sees only its rows.
	var seen []string
	if err := underRole("a", func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT id FROM rls_probe_432`)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if e := rows.Scan(&id); e != nil {
				return e
			}
			seen = append(seen, id)
		}
		return rows.Err()
	}); err != nil {
		t.Fatalf("scoped select: %v", err)
	}
	if len(seen) != 2 {
		t.Fatalf("tenant a expected 2 rows via unscoped query, got %v", seen)
	}

	// Fail-closed: under the role but with NO tenant set => zero rows, not all rows.
	failClosed := func() int {
		tx, e := pool.Begin(ctx)
		if e != nil {
			t.Fatalf("begin: %v", e)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, e := tx.Exec(ctx, `SET LOCAL ROLE rls_probe_role_432`); e != nil {
			t.Fatalf("set role: %v", e)
		}
		var n int
		if e := tx.QueryRow(ctx, `SELECT count(*) FROM rls_probe_432`).Scan(&n); e != nil {
			t.Fatalf("count: %v", e)
		}
		return n
	}
	if n := failClosed(); n != 0 {
		t.Fatalf("fail-closed violated: unset tenant saw %d rows", n)
	}

	// WITH CHECK: tenant "a" cannot write a row belonging to tenant "b".
	if err := underRole("a", func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO rls_probe_432 (id, tenant_id, v) VALUES ('x1', 'b', 'y')`)
		return e
	}); err == nil {
		t.Fatalf("WITH CHECK failed: tenant a inserted a row for tenant b")
	}

	// FORCE ROW LEVEL SECURITY is set, so the owning role would also be subject.
	var forced bool
	if err := pool.QueryRow(ctx, `SELECT relforcerowsecurity FROM pg_class WHERE relname = 'rls_probe_432'`).Scan(&forced); err != nil {
		t.Fatalf("relforcerowsecurity: %v", err)
	}
	if !forced {
		t.Fatalf("FORCE ROW LEVEL SECURITY not set on rls_probe_432")
	}

	// The test role must be neither superuser nor BYPASSRLS, or the assertions above are vacuous.
	var super, bypass bool
	if err := pool.QueryRow(ctx, `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'rls_probe_role_432'`).Scan(&super, &bypass); err != nil {
		t.Fatalf("role attrs: %v", err)
	}
	if super || bypass {
		t.Fatalf("test role bypasses RLS (super=%v bypass=%v); assertions would be vacuous", super, bypass)
	}
}

// TestMigration0057 asserts the foundation primitives exist after migrate up.
func TestMigration0057(t *testing.T) {
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
	defer pool.Close()

	for _, name := range []string{"synapse_current_tenant", "synapse_enable_tenant_rls"} {
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_proc WHERE proname = $1)`, name).Scan(&exists); err != nil {
			t.Fatalf("lookup %s: %v", name, err)
		}
		if !exists {
			t.Fatalf("migration 0057 did not create %s", name)
		}
	}
}
