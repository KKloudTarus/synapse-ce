package postgres

import (
	"context"
	"os"
	"testing"
)

func TestMigration0094AdvisoryRevisionSyncRuns(t *testing.T) {
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
	var table, index bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('advisory_revision_sync_runs') IS NOT NULL,to_regclass('idx_advisory_revision_sync_runs_run') IS NOT NULL`).Scan(&table, &index); err != nil || !table || !index {
		t.Fatalf("table=%v index=%v err=%v", table, index, err)
	}
}
