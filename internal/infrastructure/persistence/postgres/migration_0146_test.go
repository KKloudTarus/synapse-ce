package postgres

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pressly/goose/v3"
)

func TestMigration0146EmptyRoundTrip(t *testing.T) {
	db, _ := newMigration0140DB(t)
	if err := goose.UpTo(db, ".", 146); err != nil {
		t.Fatalf("up to 0146: %v", err)
	}
	ctx := context.Background()
	for _, table := range []string{"assessment_cycle_backfill_runs", "assessment_cycle_backfill_items"} {
		var exists, forcedRLS bool
		if err := db.QueryRowContext(ctx, `SELECT to_regclass('public.' || $1) IS NOT NULL`, table).Scan(&exists); err != nil || !exists {
			t.Fatalf("%s exists=%v err=%v", table, exists, err)
		}
		if err := db.QueryRowContext(ctx, `SELECT relforcerowsecurity FROM pg_class WHERE oid=$1::regclass`, table).Scan(&forcedRLS); err != nil || !forcedRLS {
			t.Fatalf("%s FORCE RLS=%v err=%v", table, forcedRLS, err)
		}
	}
	if err := goose.DownTo(db, ".", 145); err != nil {
		t.Fatalf("rollback to 0145: %v", err)
	}
}

func TestMigration0146UpgradePaths(t *testing.T) {
	for _, from := range []int64{128, 140, 145} {
		t.Run(strconv.FormatInt(from, 10), func(t *testing.T) {
			db, _ := newMigration0140DB(t)
			if err := goose.UpTo(db, ".", from); err != nil {
				t.Fatalf("up to %d: %v", from, err)
			}
			if err := goose.UpTo(db, ".", 146); err != nil {
				t.Fatalf("upgrade %d to 146: %v", from, err)
			}
		})
	}
}

func TestMigration0146RollbackGuard(t *testing.T) {
	db, _ := newMigration0140DB(t)
	if err := goose.UpTo(db, ".", 146); err != nil {
		t.Fatalf("up to 0146: %v", err)
	}
	now := time.Now().UTC()
	if _, err := db.Exec(`INSERT INTO tenants(id,name) VALUES('m146-tenant','Migration 146 tenant')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO assessment_cycle_backfill_runs(tenant_id,id,schema_version,dry_run,batch_size,snapshot_at,state,lease_owner,lease_expires_at,created_by,created_at,updated_at)
		VALUES('m146-tenant','m146-run',1,true,500,$1::timestamptz,'running','migration-test',$1::timestamptz + interval '10 minutes','operator',$1::timestamptz,$1::timestamptz)`, now); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownTo(db, ".", 145); err == nil || !strings.Contains(err.Error(), "cannot roll back assessment cycle backfill state") {
		t.Fatalf("rollback guard error=%v", err)
	}
}
