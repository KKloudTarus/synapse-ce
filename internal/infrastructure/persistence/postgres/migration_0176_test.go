package postgres

import (
	"context"
	"testing"

	"github.com/pressly/goose/v3"
)

func TestMigration0176VulnCheckKEVAdapterType(t *testing.T) {
	ctx := context.Background()
	db, dsn := newAssessmentMigrationDB(t)
	if err := goose.UpTo(db, ".", 176); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	insert := `INSERT INTO vulnerability_sources
		(id,source_key,display_name,adapter_type,endpoint,cadence_seconds,stale_after_seconds,sync_mode,credential_ref)
		VALUES ($1,$1,'VulnCheck KEV','vulncheck_kev',$2,3600,7200,'incremental','secret://vulnerability/vulncheck')`
	id := "vulncheck-kev-mig-" + randHex(t)
	if _, err := pool.Exec(ctx, insert, id, "https://api.vulncheck.com/v3/backup/vulncheck-kev?"+id); err != nil {
		t.Fatalf("vulncheck_kev adapter_type must be allowed after 0176: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO vulnerability_sources
		(id,source_key,display_name,adapter_type,endpoint,cadence_seconds,stale_after_seconds,sync_mode)
		VALUES ('vulncheck-mig-bogus','vulncheck-mig-bogus','x','bogus','https://example.invalid/bogus',3600,7200,'full')`); err == nil {
		t.Fatal("an unknown adapter_type must still be rejected")
	}

	if _, err := pool.Exec(ctx, `DELETE FROM vulnerability_sources WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownTo(db, ".", 175); err != nil {
		t.Fatalf("migrate down: %v", err)
	}
	if _, err := pool.Exec(ctx, insert, "vulncheck-kev-after-down-"+randHex(t), "https://example.invalid/after"); err == nil {
		t.Fatal("vulncheck_kev adapter_type must be rejected again after down to 0175")
	}
}
