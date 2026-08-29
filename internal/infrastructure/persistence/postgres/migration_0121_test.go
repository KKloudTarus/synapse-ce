package postgres

import (
	"context"
	"os"
	"testing"
)

func TestMigration0121PrivacyPolicyGuards(t *testing.T) {
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

	for _, table := range []string{"privacy_policies", "privacy_active_policies"} {
		var rls, forced bool
		if err := pool.QueryRow(ctx, `SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid=$1::regclass`, table).Scan(&rls, &forced); err != nil {
			t.Fatalf("inspect %s RLS: %v", table, err)
		}
		if !rls || !forced {
			t.Fatalf("%s RLS/forced=%t/%t, want true/true", table, rls, forced)
		}
	}
	for table, triggers := range map[string][]string{
		"privacy_policies":        {"privacy_policies_append_only", "privacy_policies_no_truncate"},
		"privacy_active_policies": {"privacy_active_policies_no_truncate"},
	} {
		for _, trigger := range triggers {
			var exists bool
			if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=$1::regclass AND tgname=$2 AND NOT tgisinternal)`, table, trigger).Scan(&exists); err != nil {
				t.Fatalf("inspect %s trigger %s: %v", table, trigger, err)
			}
			if !exists {
				t.Fatalf("migration 0121 did not install %s on %s", trigger, table)
			}
		}
	}

	var deleteAction string
	if err := pool.QueryRow(ctx, `SELECT confdeltype::text FROM pg_constraint WHERE conrelid='privacy_policies'::regclass AND confrelid='tenants'::regclass`).Scan(&deleteAction); err != nil {
		t.Fatalf("inspect privacy policy tenant foreign key: %v", err)
	}
	if deleteAction != "a" {
		t.Fatalf("privacy policy tenant FK delete action=%q, want restrictive no action", deleteAction)
	}
}
