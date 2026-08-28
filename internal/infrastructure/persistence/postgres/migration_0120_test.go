package postgres

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestMigration0120CoverageEvidenceGuards(t *testing.T) {
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
	t.Cleanup(pool.Close)

	for _, table := range []string{"coverage_windows", "telemetry_batch_commits"} {
		var rls, forced bool
		if err := pool.QueryRow(ctx, `SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid=$1::regclass`, table).Scan(&rls, &forced); err != nil {
			t.Fatalf("inspect %s RLS: %v", table, err)
		}
		if !rls || !forced {
			t.Fatalf("%s RLS/forced = %t/%t, want true/true", table, rls, forced)
		}
	}
	for table, triggers := range map[string][]string{
		"coverage_windows":        {"coverage_windows_append_only", "coverage_windows_no_truncate"},
		"telemetry_batch_commits": {"telemetry_batch_commits_immutable_commitment", "telemetry_batch_commits_no_truncate"},
	} {
		for _, trigger := range triggers {
			var exists bool
			if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=$1::regclass AND tgname=$2 AND NOT tgisinternal)`, table, trigger).Scan(&exists); err != nil {
				t.Fatalf("inspect %s trigger %s: %v", table, trigger, err)
			}
			if !exists {
				t.Fatalf("migration 0120 did not install %s on %s", trigger, table)
			}
		}
	}
}

func TestMigration0120CoverageDigestConstraintsAndNoTruncate(t *testing.T) {
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
	t.Cleanup(pool.Close)

	for name, fragment := range map[string]string{
		"coverage_windows_revision_sha256":     "revision ~ '^[0-9a-f]{64}$'",
		"coverage_windows_input_digest_sha256": "input_digest ~ '^[0-9a-f]{64}$'",
	} {
		var definition string
		if err := pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='coverage_windows'::regclass AND conname=$1`, name).Scan(&definition); err != nil {
			t.Fatalf("inspect %s: %v", name, err)
		}
		if !strings.Contains(definition, fragment) {
			t.Fatalf("%s = %q, want %q", name, definition, fragment)
		}
	}
	for _, table := range []string{"coverage_windows", "telemetry_batch_commits"} {
		if _, err := pool.Exec(ctx, `TRUNCATE `+table); err == nil {
			t.Fatalf("TRUNCATE %s unexpectedly succeeded", table)
		}
	}
}
