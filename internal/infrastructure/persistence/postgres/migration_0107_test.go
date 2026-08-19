package postgres

import (
	"context"
	"os"
	"testing"

	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/migrations"
)

func TestMigration0107FleetDesiredState(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() {
		if err := Migrate(context.Background(), dsn); err != nil {
			t.Errorf("restore migrations: %v", err)
		}
	})

	db, err := goose.OpenDBWithDriver("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownTo(db, ".", 106); err != nil {
		t.Fatalf("down to 0106: %v", err)
	}
	if err := goose.UpTo(db, ".", 107); err != nil {
		t.Fatalf("up 0107: %v", err)
	}

	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	var table, validator, rlsEnabled, rlsForced, assetFK, canonicalCheck, policyIDColumn, policyUnique, versionColumn, versionCheck, actorCheck bool
	if err := pool.QueryRow(ctx, `
		SELECT
			to_regclass('fleet_desired_state') IS NOT NULL,
			to_regprocedure('synapse_fleet_desired_capabilities_valid(text[])') IS NOT NULL,
			COALESCE((SELECT relrowsecurity FROM pg_class WHERE oid=to_regclass('fleet_desired_state')), false),
			COALESCE((SELECT relforcerowsecurity FROM pg_class WHERE oid=to_regclass('fleet_desired_state')), false),
			EXISTS (
				SELECT 1 FROM pg_constraint
				WHERE conrelid=to_regclass('fleet_desired_state')
				  AND contype='f' AND confrelid=to_regclass('fleet_assets')
			),
			EXISTS (
				SELECT 1 FROM pg_constraint
				WHERE conrelid=to_regclass('fleet_desired_state')
				  AND conname='fleet_desired_state_capabilities_canonical' AND contype='c'
			),
			EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema='public' AND table_name='fleet_desired_state'
				  AND column_name='policy_id' AND data_type='text' AND is_nullable='NO'
			),
			EXISTS (
				SELECT 1 FROM pg_constraint
				WHERE conrelid=to_regclass('fleet_desired_state') AND contype='u'
				  AND pg_get_constraintdef(oid) = 'UNIQUE (tenant_id, policy_id)'
			),
			EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema='public' AND table_name='fleet_desired_state'
				  AND column_name='version' AND data_type='bigint' AND is_nullable='NO'
			),
			EXISTS (
				SELECT 1 FROM pg_constraint
				WHERE conrelid=to_regclass('fleet_desired_state') AND contype='c'
				  AND pg_get_constraintdef(oid) LIKE '%version >= 1%'
			),
			EXISTS (
				SELECT 1 FROM pg_constraint
				WHERE conrelid=to_regclass('fleet_desired_state') AND contype='c'
				  AND pg_get_constraintdef(oid) LIKE '%btrim(updated_by)%'
			)
	`).Scan(&table, &validator, &rlsEnabled, &rlsForced, &assetFK, &canonicalCheck, &policyIDColumn, &policyUnique, &versionColumn, &versionCheck, &actorCheck); err != nil {
		t.Fatalf("inspect migration 0107: %v", err)
	}
	if !table || !validator || !rlsEnabled || !rlsForced || !assetFK || !canonicalCheck || !policyIDColumn || !policyUnique || !versionColumn || !versionCheck || !actorCheck {
		t.Fatalf("0107 objects incomplete: table=%v validator=%v rls=%v force=%v asset_fk=%v canonical_check=%v policy_id=%v policy_unique=%v version_column=%v version_check=%v actor_check=%v",
			table, validator, rlsEnabled, rlsForced, assetFK, canonicalCheck, policyIDColumn, policyUnique, versionColumn, versionCheck, actorCheck)
	}
}
