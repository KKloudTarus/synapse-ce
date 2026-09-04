package postgres

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/migrations"
)

func TestMigration0140DefinesAppendOnlyTenantSafeReviewArtifacts(t *testing.T) {
	data, err := migrations.FS.ReadFile("0140_assessment_relationship_candidates.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(data)
	for _, required := range []string{
		"assessment_relationship_candidates", "assessment_relationship_repair_plans", "assessment_relationship_decisions",
		"FOREIGN KEY (tenant_id, predecessor_cycle_id, predecessor_assessment_id, predecessor_snapshot_id)",
		"FOREIGN KEY (tenant_id, successor_cycle_id, successor_assessment_id, successor_snapshot_id)",
		"body          BYTEA NOT NULL", "execution' = 'blocked'", "separately_approved_move_merge_command", "synapse_forbid_mutation",
		"synapse_enable_tenant_rls('assessment_relationship_candidates')", "cannot roll back assessment relationship review while artifacts exist",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("migration missing %q", required)
		}
	}
}

func TestMigration0140EmptyRoundTrip(t *testing.T) {
	db, _ := newAssessmentMigrationDB(t)
	if err := goose.UpTo(db, ".", 139); err != nil {
		t.Fatalf("up to 0139: %v", err)
	}
	ctx := context.Background()
	for _, table := range []string{"assessment_relationship_candidates", "assessment_relationship_repair_plans", "assessment_relationship_decisions"} {
		var exists, forcedRLS bool
		if err := db.QueryRowContext(ctx, `SELECT to_regclass('public.' || $1) IS NOT NULL`, table).Scan(&exists); err != nil || !exists {
			t.Fatalf("%s exists=%v err=%v", table, exists, err)
		}
		if err := db.QueryRowContext(ctx, `SELECT relforcerowsecurity FROM pg_class WHERE oid=$1::regclass`, table).Scan(&forcedRLS); err != nil || !forcedRLS {
			t.Fatalf("%s FORCE RLS=%v err=%v", table, forcedRLS, err)
		}
	}
	if err := goose.DownTo(db, ".", 138); err != nil {
		t.Fatalf("rollback to 0138: %v", err)
	}
}

func TestMigration0140UpgradePaths(t *testing.T) {
	for _, from := range []int64{128, 129, 138} {
		t.Run(strconv.FormatInt(from, 10), func(t *testing.T) {
			db, _ := newAssessmentMigrationDB(t)
			if err := goose.UpTo(db, ".", from); err != nil {
				t.Fatalf("up to %d: %v", from, err)
			}
			if err := goose.UpTo(db, ".", 139); err != nil {
				t.Fatalf("upgrade %d to 150: %v", from, err)
			}
		})
	}
}

func TestMigration0140RollbackGuard(t *testing.T) {
	db, dsn := newAssessmentMigrationDB(t)
	if err := goose.UpTo(db, ".", 139); err != nil {
		t.Fatalf("up to 0139: %v", err)
	}
	pool, err := Connect(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	tenantID, candidate := seedPostgresRelationshipSubjects(t, context.Background(), pool, "migration-0139")
	if _, created, err := NewAssessmentRelationshipRepository(pool).CreateCandidate(context.Background(), candidate); err != nil || !created {
		pool.Close()
		t.Fatalf("seed candidate tenant=%s created=%v err=%v", tenantID, created, err)
	}
	pool.Close()
	if err := goose.DownTo(db, ".", 138); err == nil || !strings.Contains(err.Error(), "cannot roll back assessment relationship review while artifacts exist") {
		t.Fatalf("rollback guard error=%v", err)
	}
}
