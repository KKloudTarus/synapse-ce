package postgres

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/migrations"
)

func TestMigration0099ReconciliationDryRunSchema(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() {
		if err := Migrate(context.Background(), dsn); err != nil {
			t.Errorf("restore migrations: %v", err)
		}
	})
	db, err := goose.OpenDBWithDriver("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownTo(db, ".", 98); err != nil {
		t.Fatalf("down to 0098: %v", err)
	}
	if err := goose.UpTo(db, ".", 99); err != nil {
		t.Fatalf("up 0099: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	var nullable, defaultValue string
	if err := pool.QueryRow(ctx, `SELECT is_nullable,COALESCE(column_default,'') FROM information_schema.columns WHERE table_schema='public' AND table_name='vulnerability_reconciliation_runs' AND column_name='dry_run'`).Scan(&nullable, &defaultValue); err != nil {
		t.Fatal(err)
	}
	if nullable != "NO" || !strings.Contains(strings.ToLower(defaultValue), "false") {
		t.Fatalf("dry_run nullable=%s default=%s", nullable, defaultValue)
	}

	var forced bool
	if err := pool.QueryRow(ctx, `SELECT relforcerowsecurity FROM pg_class WHERE relname='vulnerability_reconciliation_diffs'`).Scan(&forced); err != nil || !forced {
		t.Fatalf("vulnerability_reconciliation_diffs FORCE RLS=%v err=%v", forced, err)
	}

	var primaryKey, foreignKey string
	if err := pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='vulnerability_reconciliation_diffs'::regclass AND contype='p'`).Scan(&primaryKey); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='vulnerability_reconciliation_diffs'::regclass AND contype='f' AND confrelid='vulnerability_reconciliation_runs'::regclass`).Scan(&foreignKey); err != nil {
		t.Fatal(err)
	}
	primaryKey, foreignKey = strings.ToLower(primaryKey), strings.ToLower(foreignKey)
	for _, column := range []string{"tenant_id", "run_id", "engagement_id", "advisory_id", "component_fingerprint", "mismatch_class"} {
		if !strings.Contains(primaryKey, column) {
			t.Fatalf("diff primary key=%s missing %s", primaryKey, column)
		}
	}
	if !strings.Contains(foreignKey, "foreign key (tenant_id, run_id)") || !strings.Contains(foreignKey, "references vulnerability_reconciliation_runs(tenant_id, id)") || !strings.Contains(foreignKey, "on delete cascade") {
		t.Fatalf("diff foreign key=%s", foreignKey)
	}

	rows, err := pool.Query(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='vulnerability_reconciliation_diffs'::regclass AND contype='c'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	checks := ""
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			t.Fatal(err)
		}
		checks += " " + strings.ToLower(value)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, class := range []string{"missing_occurrence", "changed_occurrence", "in_sync", "stale_occurrence", "unmatchable_input"} {
		if !strings.Contains(checks, class) {
			t.Fatalf("diff checks=%s missing %s", checks, class)
		}
	}
}
