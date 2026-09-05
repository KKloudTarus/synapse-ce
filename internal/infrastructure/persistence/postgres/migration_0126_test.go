package postgres

import (
	"context"
	"os"
	"testing"

	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/migrations"
)

func TestMigration0126AssessmentCyclesSchema(t *testing.T) {
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
	defer pool.Close()

	// Verify tables exist
	var cyclesExists, membersExists bool
	if err := pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema='public' AND table_name='assessment_cycles'
		)`).Scan(&cyclesExists); err != nil {
		t.Fatalf("inspect assessment_cycles: %v", err)
	}
	if !cyclesExists {
		t.Fatal("0126 did not create assessment_cycles table")
	}

	if err := pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema='public' AND table_name='assessment_cycle_members'
		)`).Scan(&membersExists); err != nil {
		t.Fatalf("inspect assessment_cycle_members: %v", err)
	}
	if !membersExists {
		t.Fatal("0126 did not create assessment_cycle_members table")
	}

	// Verify RLS is enabled and forced on both tables
	for _, tbl := range []string{"assessment_cycles", "assessment_cycle_members"} {
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
}

func TestMigration0126RollbackAndReapply(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() {
		_ = MigrateLocked(context.Background(), dsn)
	})

	db := openLockedGooseDB(t, dsn)
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}

	// 1. Rollback migration 0126 to 0125
	if err := goose.DownTo(db, ".", 125); err != nil {
		t.Fatalf("down to 125: %v", err)
	}

	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	var cyclesExists, membersExists bool
	_ = pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='assessment_cycles')`).Scan(&cyclesExists)
	_ = pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='assessment_cycle_members')`).Scan(&membersExists)

	if cyclesExists || membersExists {
		t.Fatalf("tables still exist after rollback: cycles=%v, members=%v", cyclesExists, membersExists)
	}

	// 2. Re-apply migration 0126
	if err := goose.UpTo(db, ".", 126); err != nil {
		t.Fatalf("up to 126: %v", err)
	}

	_ = pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='assessment_cycles')`).Scan(&cyclesExists)
	_ = pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='assessment_cycle_members')`).Scan(&membersExists)

	if !cyclesExists || !membersExists {
		t.Fatalf("tables not recreated after re-apply: cycles=%v, members=%v", cyclesExists, membersExists)
	}
}
