package postgres

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/migrations"
)

// TestFleetAssetsRLS proves tenant isolation on fleet_assets is enforced by the DATABASE (Row
// Level Security), not by the query's WHERE clause: it reads with an intentionally unscoped
// SELECT under a NOSUPERUSER NOBYPASSRLS role and still sees only the current tenant's rows, and
// sees nothing when no tenant is set.
func TestFleetAssetsRLS(t *testing.T) {
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

	// FORCE ROW LEVEL SECURITY is set on every fleet table.
	for _, tbl := range []string{"fleet_assets", "fleet_asset_edges", "fleet_business_services"} {
		var forced bool
		if err := pool.QueryRow(ctx, `SELECT relforcerowsecurity FROM pg_class WHERE relname = $1`, tbl).Scan(&forced); err != nil {
			t.Fatalf("relforcerowsecurity %s: %v", tbl, err)
		}
		if !forced {
			t.Fatalf("FORCE ROW LEVEL SECURITY not set on %s", tbl)
		}
	}

	// A role RLS actually applies to.
	for _, stmt := range []string{
		`DROP OWNED BY rls_asset_role_432`,
		`DROP ROLE IF EXISTS rls_asset_role_432`,
		`CREATE ROLE rls_asset_role_432 NOSUPERUSER NOBYPASSRLS`,
		`GRANT USAGE ON SCHEMA public TO rls_asset_role_432`,
		`GRANT SELECT ON fleet_assets TO rls_asset_role_432`,
	} {
		_, _ = pool.Exec(ctx, stmt)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ('rlsa','A'),('rlsb','B') ON CONFLICT (id) DO NOTHING`); err != nil {
		t.Fatalf("seed tenants: %v", err)
	}
	// Seed as the superuser (RLS bypassed) so both tenants have rows to (not) leak.
	if _, err := pool.Exec(ctx, `
		INSERT INTO fleet_assets (id, tenant_id, kind, "key", name) VALUES
		('ra1','rlsa','host','h1','h1'),('ra2','rlsa','host','h2','h2'),('rb1','rlsb','host','h3','h3')`); err != nil {
		t.Fatalf("seed assets: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM fleet_assets WHERE tenant_id IN ('rlsa','rlsb')`)
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id IN ('rlsa','rlsb')`)
		_, _ = pool.Exec(bg, `DROP OWNED BY rls_asset_role_432`)
		_, _ = pool.Exec(bg, `DROP ROLE IF EXISTS rls_asset_role_432`)
	})

	// countUnscoped runs an UNSCOPED count under the non-privileged role, optionally setting the
	// tenant session variable. RLS, not the query, decides visibility.
	countUnscoped := func(setTenant bool, tenant string) int {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if setTenant {
			if _, err := tx.Exec(ctx, `SELECT set_config('app.current_tenant', $1, true)`, tenant); err != nil {
				t.Fatalf("set_config: %v", err)
			}
		}
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE rls_asset_role_432`); err != nil {
			t.Fatalf("set role: %v", err)
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM fleet_assets`).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}

	if got := countUnscoped(true, "rlsa"); got != 2 {
		t.Fatalf("tenant rlsa should see 2 rows via unscoped query, got %d", got)
	}
	if got := countUnscoped(true, "rlsb"); got != 1 {
		t.Fatalf("tenant rlsb should see 1 row via unscoped query, got %d", got)
	}
	if got := countUnscoped(false, ""); got != 0 {
		t.Fatalf("no tenant set must see 0 rows (fail-closed), got %d", got)
	}
}

// TestMigration0058 exercises the migration down and back up and asserts the table is gone after
// down and present after up.
func TestMigration0058(t *testing.T) {
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

	if err := goose.DownTo(db, ".", 57); err != nil {
		t.Fatalf("down to 57: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	_, err = pool.Exec(ctx, `SELECT 1 FROM fleet_assets LIMIT 1`)
	if err == nil {
		t.Fatalf("fleet_assets should not exist after down to 57")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42P01" { // undefined_table
		t.Fatalf("expected undefined_table after down, got %v", err)
	}

	if err := goose.UpTo(db, ".", 58); err != nil {
		t.Fatalf("up to 58: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT 1 FROM fleet_assets LIMIT 1`); err != nil {
		t.Fatalf("fleet_assets should exist after up to 58: %v", err)
	}
}
