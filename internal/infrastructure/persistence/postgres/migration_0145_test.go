package postgres

import (
	"testing"

	"github.com/pressly/goose/v3"
)

func TestMigration0145AdvisoryAliasIndex(t *testing.T) {
	isolated := newIsolatedMigrationDB(t, 145, 144)
	db := isolated.db
	if err := goose.UpTo(db, ".", 145); err != nil {
		t.Fatalf("apply 0145: %v", err)
	}
	requireAliasIndex := func(want bool) {
		t.Helper()
		var exists bool
		if err := db.QueryRow(
			`SELECT EXISTS(SELECT 1 FROM pg_indexes WHERE indexname = 'idx_advisories_aliases')`,
		).Scan(&exists); err != nil {
			t.Fatalf("check index: %v", err)
		}
		if exists != want {
			t.Fatalf("idx_advisories_aliases exists=%v, want %v", exists, want)
		}
	}
	requireAliasIndex(true)

	// The index backs the alias-closure query the matcher runs (data->'Aliases' ?| array[...]).
	if _, err := db.Exec(`INSERT INTO advisories(id, data, created_at, updated_at) VALUES
		('CVE-2026-1', '{"ID":"CVE-2026-1","Aliases":["GHSA-a","OSV-9"]}'::jsonb, now(), now())`); err != nil {
		t.Fatalf("seed advisory: %v", err)
	}
	var id string
	if err := db.QueryRow(
		`SELECT id FROM advisories WHERE data->'Aliases' ?| array['GHSA-a']`,
	).Scan(&id); err != nil {
		t.Fatalf("alias query: %v", err)
	}
	if id != "CVE-2026-1" {
		t.Fatalf("alias query returned %q, want CVE-2026-1", id)
	}

	if err := goose.DownTo(db, ".", 144); err != nil {
		t.Fatalf("roll back 0145: %v", err)
	}
	requireAliasIndex(false)
	if err := goose.UpTo(db, ".", 145); err != nil {
		t.Fatalf("reapply 0145: %v", err)
	}
	requireAliasIndex(true)
}
