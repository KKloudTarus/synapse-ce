package postgres

import (
	"context"
	"testing"

	"github.com/pressly/goose/v3"
)

// TestMigration0167FindingEPSSPercentile verifies migration 0167 adds the findings.epss_percentile column
// (EPIC #860 D1.3, the persisted EPSS rank) with a NOT NULL default, and that down removes it.
func TestMigration0167FindingEPSSPercentile(t *testing.T) {
	ctx := context.Background()
	db, dsn := newAssessmentMigrationDB(t)
	if err := goose.UpTo(db, ".", 167); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	colExists := func() bool {
		var n int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM information_schema.columns WHERE table_name='findings' AND column_name='epss_percentile'`).
			Scan(&n); err != nil {
			t.Fatalf("query column: %v", err)
		}
		return n == 1
	}
	if !colExists() {
		t.Fatal("findings.epss_percentile must exist after migration 0167")
	}
	var def string
	if err := pool.QueryRow(ctx,
		`SELECT column_default FROM information_schema.columns WHERE table_name='findings' AND column_name='epss_percentile'`).
		Scan(&def); err != nil {
		t.Fatalf("query default: %v", err)
	}
	if def == "" {
		t.Error("epss_percentile must have a NOT NULL default so existing rows stay valid")
	}

	if err := goose.Down(db, "."); err != nil {
		t.Fatalf("migrate down: %v", err)
	}
	if colExists() {
		t.Fatal("findings.epss_percentile must be dropped after down migration")
	}
}
