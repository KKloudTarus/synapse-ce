package postgres

import (
	"context"
	"testing"

	"github.com/pressly/goose/v3"
)

// TestMigration0166AccuracyRuns verifies migration 0166 creates the global accuracy_runs table
// (EPIC #860 D8.6) with no tenant_id column, and that down removes it.
func TestMigration0166AccuracyRuns(t *testing.T) {
	ctx := context.Background()
	db, dsn := newAssessmentMigrationDB(t)
	if err := goose.UpTo(db, ".", 166); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	tableExists := func() bool {
		var n int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM information_schema.tables WHERE table_name='accuracy_runs'`).Scan(&n); err != nil {
			t.Fatalf("query table: %v", err)
		}
		return n == 1
	}
	if !tableExists() {
		t.Fatal("accuracy_runs table must exist after migration 0166")
	}

	// It is global engine data: it must NOT carry a tenant_id column.
	var tenantCols int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM information_schema.columns WHERE table_name='accuracy_runs' AND column_name='tenant_id'`).
		Scan(&tenantCols); err != nil {
		t.Fatalf("query tenant column: %v", err)
	}
	if tenantCols != 0 {
		t.Error("accuracy_runs must be global (no tenant_id column)")
	}

	// A round-trip insert + read confirms the column set matches the store.
	if _, err := pool.Exec(ctx,
		`INSERT INTO accuracy_runs(id,ran_at,corpus_version,schema_version,cases,overall_tp,overall_fp,overall_fn,overall_precision,overall_recall,overall_f1,overall_fdr,overall_fnr,groups)
		 VALUES('run-1', now(), 'detection-golden-v1', 'synapse-accuracy-report-v1', 9, 10, 0, 1, 0.9, 0.95, 0.92, 0.1, 0.05, '[]'::jsonb)`); err != nil {
		t.Fatalf("insert: %v", err)
	}
	var cases int
	if err := pool.QueryRow(ctx, `SELECT cases FROM accuracy_runs WHERE id='run-1'`).Scan(&cases); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if cases != 9 {
		t.Errorf("cases = %d, want 9", cases)
	}

	if err := goose.Down(db, "."); err != nil {
		t.Fatalf("migrate down: %v", err)
	}
	if tableExists() {
		t.Fatal("accuracy_runs table must be dropped after down migration")
	}
}
