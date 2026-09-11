package postgres

import (
	"context"
	"testing"

	"github.com/pressly/goose/v3"
)

// TestMigration0165FindingPublicExploit verifies migration 0165 adds the findings.public_exploit column
// (EPIC #860 D1.3, the persisted "a public exploit exists" signal) with a NOT NULL default, and that down
// removes it.
func TestMigration0165FindingPublicExploit(t *testing.T) {
	ctx := context.Background()
	db, dsn := newAssessmentMigrationDB(t)
	if err := goose.UpTo(db, ".", 165); err != nil {
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
			`SELECT count(*) FROM information_schema.columns WHERE table_name='findings' AND column_name='public_exploit'`).
			Scan(&n); err != nil {
			t.Fatalf("query column: %v", err)
		}
		return n == 1
	}
	if !colExists() {
		t.Fatal("findings.public_exploit must exist after migration 0165")
	}
	var def string
	if err := pool.QueryRow(ctx,
		`SELECT column_default FROM information_schema.columns WHERE table_name='findings' AND column_name='public_exploit'`).
		Scan(&def); err != nil {
		t.Fatalf("query default: %v", err)
	}
	if def == "" {
		t.Errorf("findings.public_exploit must carry a default so existing rows and older writers stay valid; got none")
	}

	if err := goose.DownTo(db, ".", 164); err != nil {
		t.Fatalf("migrate down: %v", err)
	}
	if colExists() {
		t.Fatal("findings.public_exploit must be removed after down to 164")
	}
}
