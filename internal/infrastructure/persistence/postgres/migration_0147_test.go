package postgres

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pressly/goose/v3"
)

func TestMigration0147EmptyRoundTrip(t *testing.T) {
	db, _ := newMigration0140DB(t)
	if err := goose.UpTo(db, ".", 147); err != nil {
		t.Fatalf("up to 0147: %v", err)
	}
	ctx := context.Background()
	for _, table := range []string{"assessment_cycle_integrity_runs", "assessment_cycle_integrity_subjects", "assessment_cycle_integrity_findings"} {
		var exists, forcedRLS bool
		if err := db.QueryRowContext(ctx, `SELECT to_regclass('public.' || $1) IS NOT NULL`, table).Scan(&exists); err != nil || !exists {
			t.Fatalf("%s exists=%v err=%v", table, exists, err)
		}
		if err := db.QueryRowContext(ctx, `SELECT relforcerowsecurity FROM pg_class WHERE oid=$1::regclass`, table).Scan(&forcedRLS); err != nil || !forcedRLS {
			t.Fatalf("%s FORCE RLS=%v err=%v", table, forcedRLS, err)
		}
	}
	if err := goose.DownTo(db, ".", 146); err != nil {
		t.Fatalf("rollback to 0146: %v", err)
	}
}

func TestMigration0147UpgradePaths(t *testing.T) {
	for _, from := range []int64{140, 145, 146} {
		t.Run(strconv.FormatInt(from, 10), func(t *testing.T) {
			db, _ := newMigration0140DB(t)
			if err := goose.UpTo(db, ".", from); err != nil {
				t.Fatalf("up to %d: %v", from, err)
			}
			if err := goose.UpTo(db, ".", 147); err != nil {
				t.Fatalf("upgrade %d to 147: %v", from, err)
			}
		})
	}
}

func TestMigration0147RollbackGuard(t *testing.T) {
	db, _ := newMigration0140DB(t)
	if err := goose.UpTo(db, ".", 147); err != nil {
		t.Fatalf("up to 0147: %v", err)
	}
	now := time.Now().UTC()
	if _, err := db.Exec(`INSERT INTO tenants(id,name) VALUES('m147-tenant','Migration 147 tenant')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO assessment_cycle_integrity_runs(tenant_id,id,batch_size,snapshot_at,state,lease_owner,lease_expires_at,created_by,created_at,updated_at)
		VALUES('m147-tenant','m147-run',500,$1::timestamptz,'running','migration-test',$1::timestamptz + interval '10 minutes','operator',$1::timestamptz,$1::timestamptz)`, now); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownTo(db, ".", 146); err == nil || !strings.Contains(err.Error(), "cannot roll back assessment cycle integrity state") {
		t.Fatalf("rollback guard error=%v", err)
	}
}
