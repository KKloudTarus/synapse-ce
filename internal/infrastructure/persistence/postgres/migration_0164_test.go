package postgres

import (
	"context"
	"testing"

	"github.com/pressly/goose/v3"
)

// TestMigration0164FindingDirectBumps verifies migration 0164 adds the findings.direct_bumps column
// (EPIC #860 D3.8, the persisted minimal-upgrade remediation set) with a NOT NULL default, and that down
// removes it.
func TestMigration0164FindingDirectBumps(t *testing.T) {
	ctx := context.Background()
	db, dsn := newAssessmentMigrationDB(t)
	if err := goose.UpTo(db, ".", 164); err != nil {
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
			`SELECT count(*) FROM information_schema.columns WHERE table_name='findings' AND column_name='direct_bumps'`).
			Scan(&n); err != nil {
			t.Fatalf("query column: %v", err)
		}
		return n == 1
	}
	if !colExists() {
		t.Fatal("findings.direct_bumps must exist after migration 0164")
	}
	// The column is NOT NULL with a default, so an INSERT omitting it succeeds and reads back as ''.
	var def string
	if err := pool.QueryRow(ctx,
		`SELECT column_default FROM information_schema.columns WHERE table_name='findings' AND column_name='direct_bumps'`).
		Scan(&def); err != nil {
		t.Fatalf("query default: %v", err)
	}
	if def == "" {
		t.Errorf("findings.direct_bumps must carry a default so existing rows and older writers stay valid; got none")
	}

	if err := goose.DownTo(db, ".", 163); err != nil {
		t.Fatalf("migrate down: %v", err)
	}
	if colExists() {
		t.Fatal("findings.direct_bumps must be removed after down to 163")
	}
}
