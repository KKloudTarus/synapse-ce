package postgres

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/migrations"
)

func TestMigration0141DefinesImmutableTenantSafeClosureReports(t *testing.T) {
	data, err := migrations.FS.ReadFile("0141_assessment_closure_reports.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(data)
	for _, required := range []string{
		"assessment_cycle_closure_reports", "PRIMARY KEY (tenant_id, cycle_id, manifest_id, renderer_contract_version)",
		"REFERENCES assessment_cycle_closure_manifests(tenant_id, cycle_id, id) ON DELETE RESTRICT",
		"content_hash ~ '^[0-9a-f]{64}$'", "octet_length(content) BETWEEN 2 AND 16777216",
		"synapse_forbid_mutation", "synapse_enable_tenant_rls('assessment_cycle_closure_reports')",
		"cannot roll back assessment closure reports while report rows exist",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("migration missing %q", required)
		}
	}
}

func TestMigration0141EmptyRoundTrip(t *testing.T) {
	db, _ := newAssessmentMigrationDB(t)
	if err := goose.UpTo(db, ".", 140); err != nil {
		t.Fatalf("up to 0140: %v", err)
	}
	ctx := context.Background()
	var exists, forcedRLS bool
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('public.assessment_cycle_closure_reports') IS NOT NULL`).Scan(&exists); err != nil || !exists {
		t.Fatalf("closure report table exists=%v err=%v", exists, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT relforcerowsecurity FROM pg_class WHERE oid='assessment_cycle_closure_reports'::regclass`).Scan(&forcedRLS); err != nil || !forcedRLS {
		t.Fatalf("closure report FORCE RLS=%v err=%v", forcedRLS, err)
	}
	if err := goose.DownTo(db, ".", 139); err != nil {
		t.Fatalf("rollback to 0139: %v", err)
	}
}

func TestMigration0141UpgradePaths(t *testing.T) {
	for _, from := range []int64{128, 129, 139} {
		t.Run(strconv.FormatInt(from, 10), func(t *testing.T) {
			db, _ := newAssessmentMigrationDB(t)
			if err := goose.UpTo(db, ".", from); err != nil {
				t.Fatalf("up to %d: %v", from, err)
			}
			if err := goose.UpTo(db, ".", 140); err != nil {
				t.Fatalf("upgrade %d to 151: %v", from, err)
			}
		})
	}
}
