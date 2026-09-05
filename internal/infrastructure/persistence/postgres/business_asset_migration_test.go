package postgres

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestBusinessAssetMigrationIsolation(t *testing.T) {
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
	// t.Cleanup, not defer: a deferred Close runs when this function RETURNS, which is before any
	// t.Cleanup callback -- so the cleanup below was deleting through an already-closed pool and every
	// statement failed. Registered here, LIFO ordering runs the deletes first and closes afterwards.
	t.Cleanup(pool.Close)
	for _, statement := range []string{
		`INSERT INTO tenants(id,name) VALUES('ba-tenant-a','A'),('ba-tenant-b','B') ON CONFLICT DO NOTHING`,
		`INSERT INTO fleet_business_services(id,tenant_id,"key",name,owner) VALUES('ba-a','ba-tenant-a','a','Same display name','team'),('ba-a2','ba-tenant-a','a2','Same display name','team'),('ba-b','ba-tenant-b','b','B','team')`,
		`INSERT INTO projects(id,tenant_id,name,key,source_binding) VALUES('ba-pa','ba-tenant-a','PA','pa','{"kind":"git","value":"https://a"}'),('ba-pb','ba-tenant-b','PB','pb','{"kind":"git","value":"https://b"}')`,
		`INSERT INTO fleet_assets(id,tenant_id,kind,"key",name) VALUES('ba-ta','ba-tenant-a','workload','ta','TA')`,
		`INSERT INTO engagements(id,tenant_id,business_asset_id,name) VALUES('ba-ea','ba-tenant-a','ba-a','EA')`,
	} {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	t.Cleanup(func() {
		bg := context.Background()
		// Cleanup REPORTS its failures. Discarding them (`_, _ = pool.Exec`) is what made this suite
		// un-rerunnable: the seeded pair of same-name assets survived, and migration 0066 cannot be
		// rolled back while any two assets share a display name -- so every later test doing
		// goose.DownTo past 66 failed with a bare 23505 that pointed nowhere near the cause.
		for _, statement := range []string{
			`DELETE FROM engagements WHERE id='ba-ea'`,
			`DELETE FROM business_asset_projects WHERE business_asset_id='ba-a'`,
			`DELETE FROM business_asset_technical_assets WHERE business_asset_id='ba-a'`,
			`DELETE FROM projects WHERE id IN ('ba-pa','ba-pb')`,
			`DELETE FROM fleet_assets WHERE id='ba-ta'`,
			`DELETE FROM fleet_business_services WHERE id IN ('ba-a','ba-a2','ba-b')`,
			`DELETE FROM tenants WHERE id IN ('ba-tenant-a','ba-tenant-b')`,
		} {
			if _, err := pool.Exec(bg, statement); err != nil {
				t.Errorf("cleanup %q: %v (the next run of this suite will fail)", statement, err)
			}
		}
		_, _ = pool.Exec(bg, `DROP OWNED BY ba_runtime`)
		_, _ = pool.Exec(bg, `DROP ROLE IF EXISTS ba_runtime`)
	})

	_, err = pool.Exec(ctx, `INSERT INTO business_asset_projects(tenant_id,business_asset_id,project_id,role,provenance) VALUES('ba-tenant-a','ba-a','ba-pb','primary','test')`)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
		t.Fatalf("cross-tenant project link must fail with FK violation, got %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO business_asset_projects(tenant_id,business_asset_id,project_id,role,provenance) VALUES('ba-tenant-a','ba-a','ba-pa','primary','test')`); err != nil {
		t.Fatalf("valid project link: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO business_asset_technical_assets(tenant_id,business_asset_id,technical_asset_id,role,provenance) VALUES('ba-tenant-a','ba-a','ba-ta','supporting','test')`); err != nil {
		t.Fatalf("valid technical link: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE fleet_business_services SET name='Renamed Asset' WHERE tenant_id='ba-tenant-a' AND id='ba-a'`); err != nil {
		t.Fatalf("rename asset: %v", err)
	}
	var assets, projects, technical, assignments int
	for query, target := range map[string]*int{
		`SELECT count(*) FROM fleet_business_services WHERE tenant_id='ba-tenant-a' AND id='ba-a' AND "key"='a'`:          &assets,
		`SELECT count(*) FROM business_asset_projects WHERE tenant_id='ba-tenant-a' AND business_asset_id='ba-a'`:         &projects,
		`SELECT count(*) FROM business_asset_technical_assets WHERE tenant_id='ba-tenant-a' AND business_asset_id='ba-a'`: &technical,
		`SELECT count(*) FROM engagements WHERE tenant_id='ba-tenant-a' AND business_asset_id='ba-a'`:                     &assignments,
	} {
		if err := pool.QueryRow(ctx, query).Scan(target); err != nil {
			t.Fatalf("rename invariant query: %v", err)
		}
	}
	if assets != 1 || projects != 1 || technical != 1 || assignments != 1 {
		t.Fatalf("rename changed identity or relationships: assets=%d projects=%d technical=%d assignments=%d", assets, projects, technical, assignments)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM fleet_business_services WHERE id='ba-a'`); err == nil {
		t.Fatal("Asset with history must be protected by ON DELETE RESTRICT")
	}

	for _, statement := range []string{
		`DROP ROLE IF EXISTS ba_runtime`,
		`CREATE ROLE ba_runtime NOSUPERUSER NOBYPASSRLS`,
		`GRANT USAGE ON SCHEMA public TO ba_runtime`,
		`GRANT SELECT ON fleet_business_services,business_asset_projects,business_asset_technical_assets TO ba_runtime`,
	} {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatalf("role setup: %v", err)
		}
	}
	count := func(tenant string, set bool) int {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if set {
			if _, err := tx.Exec(ctx, `SELECT set_config('app.current_tenant',$1,true)`, tenant); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE ba_runtime`); err != nil {
			t.Fatal(err)
		}
		var result int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM fleet_business_services WHERE id LIKE 'ba-%'`).Scan(&result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	if count("ba-tenant-a", true) != 2 || count("ba-tenant-b", true) != 1 || count("", false) != 0 {
		t.Fatal("business Asset RLS did not isolate tenants or fail closed")
	}
}
