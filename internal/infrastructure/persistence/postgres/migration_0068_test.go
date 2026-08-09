package postgres

import (
	"context"
	"os"
	"testing"

	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/migrations"
)

func TestMigration0068EdgeConfidence(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db, err := goose.OpenDBWithDriver("pgx", dsn)
	if err != nil {
		t.Fatalf("goose open: %v", err)
	}
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("dialect: %v", err)
	}
	// One below THIS migration (renumbered 0067 -> 0068 after #481 took 0067); going lower would
	// also revert an unrelated feature and change what this test exercises.
	if err := goose.DownTo(db, ".", 67); err != nil {
		t.Fatalf("down to 66: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO tenants (id, name) VALUES ('edge-66', 'edge-66') ON CONFLICT (id) DO NOTHING`); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO fleet_assets (id, tenant_id, kind, "key", name) VALUES
		('edge-66-a', 'edge-66', 'host', 'a', 'a'),
		('edge-66-b', 'edge-66', 'workload', 'b', 'b');
		INSERT INTO fleet_asset_edges (tenant_id, from_asset, to_asset, kind, provenance)
		VALUES ('edge-66', 'edge-66-a', 'edge-66-b', 'runs', 'legacy');`); err != nil {
		t.Fatalf("seed legacy edge: %v", err)
	}
	if err := goose.UpTo(db, ".", 68); err != nil {
		t.Fatalf("up to 67: %v", err)
	}
	var confidence string
	if err := db.QueryRow(`SELECT confidence FROM fleet_asset_edges WHERE tenant_id = 'edge-66'`).Scan(&confidence); err != nil {
		t.Fatalf("read backfill: %v", err)
	}
	if confidence != "inferred" {
		t.Fatalf("legacy edge confidence = %q, want inferred", confidence)
	}
	var defaultExpr *string
	if err := db.QueryRow(`
		SELECT column_default FROM information_schema.columns
		WHERE table_name = 'fleet_asset_edges' AND column_name = 'confidence'`).Scan(&defaultExpr); err != nil {
		t.Fatalf("read confidence default: %v", err)
	}
	if defaultExpr != nil {
		t.Fatalf("confidence must not retain a database default, got %q", *defaultExpr)
	}
	if _, err := db.Exec(`INSERT INTO fleet_asset_edges (tenant_id, from_asset, to_asset, kind, provenance, confidence) VALUES ('edge-66', 'edge-66-a', 'edge-66-b', 'runs', 'invalid', 'certain')`); err == nil {
		t.Fatal("invalid edge confidence must fail the database check")
	}
	if _, err := db.Exec(`INSERT INTO fleet_asset_edges (tenant_id, from_asset, to_asset, kind, provenance) VALUES ('edge-66', 'edge-66-a', 'edge-66-b', 'runs', 'missing')`); err == nil {
		t.Fatal("edge confidence must be required")
	}
	var forced bool
	if err := db.QueryRow(`SELECT relforcerowsecurity FROM pg_class WHERE relname = 'attack_path_edges'`).Scan(&forced); err != nil {
		t.Fatalf("read attack_path_edges RLS: %v", err)
	}
	if !forced {
		t.Fatal("attack_path_edges must FORCE row level security")
	}
	if _, err := db.Exec(`DELETE FROM fleet_asset_edges WHERE tenant_id = 'edge-66'; DELETE FROM fleet_assets WHERE tenant_id = 'edge-66'; DELETE FROM tenants WHERE id = 'edge-66'`); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}
