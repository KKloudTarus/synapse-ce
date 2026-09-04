package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestMigration0136EmptyRoundTrip(t *testing.T) {
	db, _ := newAssessmentMigrationDB(t)
	if err := goose.UpTo(db, ".", 135); err != nil {
		t.Fatalf("up to 0135: %v", err)
	}
	if err := goose.DownTo(db, ".", 134); err != nil {
		t.Fatalf("empty rollback to 0134: %v", err)
	}
	var exists bool
	if err := db.QueryRowContext(context.Background(), `SELECT to_regclass('public.finding_identities') IS NOT NULL`).Scan(&exists); err != nil || exists {
		t.Fatalf("finding identities after rollback exists=%v err=%v", exists, err)
	}
	if err := goose.UpTo(db, ".", 135); err != nil {
		t.Fatalf("reapply 0135: %v", err)
	}
}

func TestMigration0136UpgradeFixtureAndRollbackGuard(t *testing.T) {
	ctx := context.Background()
	db, dsn := newAssessmentMigrationDB(t)
	if err := goose.UpTo(db, ".", 134); err != nil {
		t.Fatalf("up to 0134: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	tenantID := shared.ID("m135-tenant")
	cycleID, snapshotID := createFindingLineageSnapshot(t, ctx, pool, tenantID, "m135")
	pool.Close()

	if err := goose.UpTo(db, ".", 135); err != nil {
		t.Fatalf("upgrade fixture to 0135: %v", err)
	}
	pool, err = Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	identity, observation := postgresFindingLineagePair(t, tenantID, cycleID, snapshotID, "m135-identity", "m135-observation", "m135-source", "m135-rule", time.Now().UTC())
	if err := NewFindingLineageRepository(pool).CreateIdentityWithObservation(ctx, identity, observation); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	pool.Close()
	if err := goose.DownTo(db, ".", 134); err == nil || !strings.Contains(err.Error(), "cannot roll back finding lineage while lineage rows exist") {
		t.Fatalf("rollback with lineage rows error=%v", err)
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM finding_identities`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("finding identities after refused rollback count=%d err=%v", count, err)
	}
}
