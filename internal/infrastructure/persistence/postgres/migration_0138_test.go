package postgres

import (
	"context"
	"testing"

	"github.com/pressly/goose/v3"
)

func TestMigration0138EmptyRoundTrip(t *testing.T) {
	db, _ := newAssessmentMigrationDB(t)
	if err := goose.UpTo(db, ".", 137); err != nil {
		t.Fatalf("up to 0137: %v", err)
	}
	if err := goose.DownTo(db, ".", 136); err != nil {
		t.Fatalf("rollback to 0136: %v", err)
	}
	var exists bool
	if err := db.QueryRowContext(context.Background(), `SELECT to_regclass('public.assessment_comparisons') IS NOT NULL`).Scan(&exists); err != nil || exists {
		t.Fatalf("assessment comparisons after rollback exists=%v err=%v", exists, err)
	}
}
