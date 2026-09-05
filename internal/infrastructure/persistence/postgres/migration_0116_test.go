package postgres

import (
	"context"
	"os"
	"testing"
)

func TestMigration0116FindingDataFlowColumn(t *testing.T) {
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
	var exists bool
	if err := pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema='public' AND table_name='findings'
			  AND column_name='data_flow' AND data_type='jsonb' AND is_nullable='YES'
		)`).Scan(&exists); err != nil {
		t.Fatalf("inspect 0116: %v", err)
	}
	if !exists {
		t.Fatal("0116 did not add nullable findings.data_flow JSONB")
	}
}
