package postgres

import (
	"context"
	"os"
	"regexp"
	"strconv"
	"testing"

	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/migrations"
)

func TestMigrationInventoryNoDuplicateGooseVersions(t *testing.T) {
	entries, err := migrations.FS.ReadDir(".")
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}

	versionRegex := regexp.MustCompile(`^(\d+)_.*\.sql$`)
	seenVersions := make(map[int64]string)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		matches := versionRegex.FindStringSubmatch(name)
		if len(matches) != 2 {
			continue
		}

		ver, err := strconv.ParseInt(matches[1], 10, 64)
		if err != nil {
			t.Fatalf("parse version in %s: %v", name, err)
		}

		if existingFile, ok := seenVersions[ver]; ok {
			t.Fatalf("duplicate goose migration version %04d found in files %q and %q", ver, existingFile, name)
		}
		seenVersions[ver] = name
	}
}

func TestMigration0129ScanRunProvenanceSchema(t *testing.T) {
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
	defer pool.Close()

	tables := []string{
		"scan_runs",
		"scan_run_lanes",
		"scan_run_lane_versions",
		"scan_run_lane_stages",
	}

	// 1. Verify tables exist
	for _, tbl := range tables {
		var exists bool
		if err := pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.tables
				WHERE table_schema='public' AND table_name=$1
			)`, tbl).Scan(&exists); err != nil {
			t.Fatalf("inspect %s existence: %v", tbl, err)
		}
		if !exists {
			t.Fatalf("table %s was not created by migration 0129", tbl)
		}
	}

	// 2. Verify RLS is enabled and forced on all tables
	for _, tbl := range tables {
		var rlsEnabled, rlsForced bool
		if err := pool.QueryRow(ctx, `
			SELECT relrowsecurity, relforcerowsecurity
			FROM pg_class
			WHERE relname = $1
		`, tbl).Scan(&rlsEnabled, &rlsForced); err != nil {
			t.Fatalf("inspect %s RLS: %v", tbl, err)
		}
		if !rlsEnabled || !rlsForced {
			t.Fatalf("%s RLS not enabled/forced: enabled=%v forced=%v", tbl, rlsEnabled, rlsForced)
		}
	}

	// 3. Inspect PostgreSQL catalogs for foreign keys referencing scan_runs
	rows, err := pool.Query(ctx, `
		SELECT conname, conrelid::regclass::text
		FROM pg_constraint
		WHERE confrelid = 'scan_runs'::regclass
	`)
	if err != nil {
		t.Fatalf("query pg_constraint for scan_runs FKs: %v", err)
	}
	defer rows.Close()

	dependents := make(map[string]bool)
	for rows.Next() {
		var conname, relname string
		if err := rows.Scan(&conname, &relname); err != nil {
			t.Fatalf("scan FK row: %v", err)
		}
		dependents[relname] = true
	}

	expectedDependents := []string{"scan_run_lanes"}
	for _, expected := range expectedDependents {
		if !dependents[expected] {
			t.Errorf("expected foreign key from %q to scan_runs, but was not found in pg_constraint", expected)
		}
	}
}

func TestMigration0129RollbackAndReapply(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() {
		_ = Migrate(context.Background(), dsn)
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

	// 1. Rollback migration 0129 to 0128
	if err := goose.DownTo(db, ".", 128); err != nil {
		t.Fatalf("down to 128: %v", err)
	}

	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	// Verify child tables dropped
	for _, tbl := range []string{"scan_run_lanes", "scan_run_lane_versions", "scan_run_lane_stages"} {
		var exists bool
		_ = pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name=$1)`, tbl).Scan(&exists)
		if exists {
			t.Fatalf("table %s still exists after rollback to 128", tbl)
		}
	}

	// 2. Re-apply migration 0129
	if err := goose.UpTo(db, ".", 129); err != nil {
		t.Fatalf("up to 129: %v", err)
	}

	// Verify child tables restored
	for _, tbl := range []string{"scan_run_lanes", "scan_run_lane_versions", "scan_run_lane_stages"} {
		var exists bool
		_ = pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name=$1)`, tbl).Scan(&exists)
		if !exists {
			t.Fatalf("table %s was not recreated after re-applying 129", tbl)
		}
	}
}
