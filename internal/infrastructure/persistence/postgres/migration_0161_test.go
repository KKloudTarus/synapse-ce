package postgres

import (
	"context"
	"testing"

	"github.com/pressly/goose/v3"
)

// TestMigration0161GHSAAdapterType verifies migration 0161 widens the vulnerability_sources.adapter_type
// CHECK to allow the direct GitHub Advisory provider (EPIC #860 D1.10) while still rejecting an unknown
// adapter type, and that the down migration restores the narrower set.
func TestMigration0161GHSAAdapterType(t *testing.T) {
	ctx := context.Background()
	db, dsn := newAssessmentMigrationDB(t)
	if err := goose.UpTo(db, ".", 161); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	insert := `INSERT INTO vulnerability_sources
		(id,source_key,display_name,adapter_type,endpoint,cadence_seconds,stale_after_seconds,sync_mode)
		VALUES ($1,$1,'GHSA','ghsa',$2,3600,7200,'incremental')`
	id := "ghsa-mig-" + randHex(t)
	if _, err := pool.Exec(ctx, insert, id, "https://api.github.com/advisories?"+id); err != nil {
		t.Fatalf("ghsa adapter_type must be allowed after 0161: %v", err)
	}
	// An unknown adapter type is still rejected by the widened constraint.
	if _, err := pool.Exec(ctx, `INSERT INTO vulnerability_sources
		(id,source_key,display_name,adapter_type,endpoint,cadence_seconds,stale_after_seconds,sync_mode)
		VALUES ('ghsa-mig-bogus','ghsa-mig-bogus','x','bogus','http://x/bogus',3600,7200,'incremental')`); err == nil {
		t.Fatal("an unknown adapter_type must still be rejected")
	}

	// Down restores the narrower set: a ghsa row can no longer be inserted. Remove the ghsa row first, else
	// re-adding the narrow constraint fails on it (which is itself the correct guard, but not what we assert).
	if _, err := pool.Exec(ctx, `DELETE FROM vulnerability_sources WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownTo(db, ".", 160); err != nil {
		t.Fatalf("migrate down: %v", err)
	}
	if _, err := pool.Exec(ctx, insert, "ghsa-mig-after-down-"+randHex(t), "http://x/after"); err == nil {
		t.Fatal("ghsa adapter_type must be rejected again after down to 160")
	}
}
