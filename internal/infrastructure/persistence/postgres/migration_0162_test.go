package postgres

import (
	"context"
	"testing"

	"github.com/pressly/goose/v3"
)

// TestMigration0162GitLabAdapterType verifies migration 0162 widens the adapter_type CHECK to allow the
// direct GitLab provider (EPIC #860 D1.10), still rejects an unknown type, and restores the narrower set on
// down.
func TestMigration0162GitLabAdapterType(t *testing.T) {
	ctx := context.Background()
	db, dsn := newAssessmentMigrationDB(t)
	if err := goose.UpTo(db, ".", 162); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	insert := `INSERT INTO vulnerability_sources
		(id,source_key,display_name,adapter_type,endpoint,cadence_seconds,stale_after_seconds,sync_mode)
		VALUES ($1,$1,'GitLab','gitlab',$2,3600,7200,'full')`
	id := "gitlab-mig-" + randHex(t)
	if _, err := pool.Exec(ctx, insert, id, "https://gitlab.com/advisories?"+id); err != nil {
		t.Fatalf("gitlab adapter_type must be allowed after 0162: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO vulnerability_sources
		(id,source_key,display_name,adapter_type,endpoint,cadence_seconds,stale_after_seconds,sync_mode)
		VALUES ('gitlab-mig-bogus','gitlab-mig-bogus','x','bogus','http://x/g-bogus',3600,7200,'full')`); err == nil {
		t.Fatal("an unknown adapter_type must still be rejected")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM vulnerability_sources WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownTo(db, ".", 161); err != nil {
		t.Fatalf("migrate down: %v", err)
	}
	if _, err := pool.Exec(ctx, insert, "gitlab-mig-after-"+randHex(t), "http://x/after-g"); err == nil {
		t.Fatal("gitlab adapter_type must be rejected again after down to 161")
	}
}
