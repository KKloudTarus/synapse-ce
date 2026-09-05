package postgres

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/migrations"
)

func TestMigration0089BackfillsAndIsolatesScanInventory(t *testing.T) {
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
		t.Fatalf("dialect: %v", err)
	}
	if err := goose.DownTo(db, ".", 88); err != nil {
		t.Fatalf("down to 0088: %v", err)
	}

	prefix := "m89-" + randHex(t)
	tenantA, tenantB := prefix+"-a", prefix+"-b"
	engagementA, engagementB := prefix+"-ea", prefix+"-eb"
	sbomA, sbomB := prefix+"-sa", prefix+"-sb"
	componentA, componentB := prefix+"-ca", prefix+"-cb"
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,name) VALUES($1,$1),($2,$2)`, []any{tenantA, tenantB}},
		{`INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'A'),($3,$4,'B')`, []any{engagementA, tenantA, engagementB, tenantB}},
		{`INSERT INTO sboms(id,tenant_id,engagement_id,target_ref,source) VALUES($1,'default',$2,'a','test'),($3,'default',$4,'b','test')`, []any{sbomA, engagementA, sbomB, engagementB}},
		{`INSERT INTO components(id,sbom_id,name) VALUES($1,$2,'a'),($3,$4,'b')`, []any{componentA, sbomA, componentB, sbomB}},
		{`INSERT INTO vulnerabilities(id,component_id,advisory_id,source) VALUES($1,$2,'CVE-A','test'),($3,$4,'CVE-B','test')`, []any{prefix + "-va", componentA, prefix + "-vb", componentB}},
	}
	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("seed pre-0089 data: %v", err)
		}
	}
	if err := goose.UpTo(db, ".", 89); err != nil {
		t.Fatalf("up 0089: %v", err)
	}

	for _, probe := range []struct {
		table, id, tenant string
	}{
		{"sboms", sbomA, tenantA}, {"sboms", sbomB, tenantB},
		{"components", componentA, tenantA}, {"components", componentB, tenantB},
		{"vulnerabilities", prefix + "-va", tenantA}, {"vulnerabilities", prefix + "-vb", tenantB},
	} {
		var got string
		if err := db.QueryRowContext(ctx, `SELECT tenant_id FROM `+probe.table+` WHERE id=$1`, probe.id).Scan(&got); err != nil || got != probe.tenant {
			t.Fatalf("%s %s tenant=%q err=%v, want %q", probe.table, probe.id, got, err, probe.tenant)
		}
	}

	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	role := uniqueProbeRole(t, dsn, "sbom_rls_probe_0089")
	_, _ = pool.Exec(ctx, `DROP OWNED BY `+role)
	_, _ = pool.Exec(ctx, `DROP ROLE IF EXISTS `+role)
	if _, err := pool.Exec(ctx, `CREATE ROLE `+role+` NOSUPERUSER NOBYPASSRLS`); err != nil {
		t.Fatalf("create probe role: %v", err)
	}
	if _, err := pool.Exec(ctx, `GRANT USAGE ON SCHEMA public TO `+role); err != nil {
		t.Fatalf("grant schema: %v", err)
	}
	if _, err := pool.Exec(ctx, `GRANT SELECT ON sboms, components, vulnerabilities TO `+role); err != nil {
		t.Fatalf("grant inventory: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM sboms WHERE id IN ($1,$2)`, sbomA, sbomB)
		_, _ = pool.Exec(bg, `DELETE FROM engagements WHERE id IN ($1,$2)`, engagementA, engagementB)
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id IN ($1,$2)`, tenantA, tenantB)
		_, _ = pool.Exec(bg, `DROP OWNED BY `+role)
		_, _ = pool.Exec(bg, `DROP ROLE IF EXISTS `+role)
	})

	countComponents := func(tenant string) int {
		t.Helper()
		count := 0
		err := WithTenant(ctx, pool, tenant, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+role); err != nil {
				return err
			}
			return tx.QueryRow(ctx, `SELECT count(*) FROM components WHERE id IN ($1,$2)`, componentA, componentB).Scan(&count)
		})
		if err != nil {
			t.Fatalf("count components for %s: %v", tenant, err)
		}
		return count
	}
	if got := countComponents(tenantA); got != 1 {
		t.Fatalf("tenant A enumerated %d components, want 1", got)
	}
	if got := countComponents(tenantB); got != 1 {
		t.Fatalf("tenant B enumerated %d components, want 1", got)
	}
}
