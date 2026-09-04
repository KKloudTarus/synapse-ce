package postgres

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestMigration0139EmptyRoundTrip(t *testing.T) {
	db, _ := newAssessmentMigrationDB(t)
	if err := goose.UpTo(db, ".", 138); err != nil {
		t.Fatalf("up to 0138: %v", err)
	}

	ctx := context.Background()
	for _, table := range []string{
		"assessment_cycle_closure_manifests",
		"assessment_cycle_closure_path_members",
		"assessment_cycle_closure_references",
	} {
		var exists, forcedRLS bool
		if err := db.QueryRowContext(ctx, `SELECT to_regclass('public.' || $1) IS NOT NULL`, table).Scan(&exists); err != nil || !exists {
			t.Fatalf("%s exists=%v err=%v", table, exists, err)
		}
		if err := db.QueryRowContext(ctx, `SELECT relforcerowsecurity FROM pg_class WHERE oid=$1::regclass`, table).Scan(&forcedRLS); err != nil || !forcedRLS {
			t.Fatalf("%s FORCE RLS=%v err=%v", table, forcedRLS, err)
		}
	}

	var activeManifestColumn bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1 FROM information_schema.columns
		WHERE table_schema='public' AND table_name='assessment_cycles' AND column_name='active_closure_manifest_id'
	)`).Scan(&activeManifestColumn); err != nil || !activeManifestColumn {
		t.Fatalf("active closure manifest column exists=%v err=%v", activeManifestColumn, err)
	}

	if err := goose.DownTo(db, ".", 137); err != nil {
		t.Fatalf("rollback to 0137: %v", err)
	}
	var exists bool
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('public.assessment_cycle_closure_manifests') IS NOT NULL`).Scan(&exists); err != nil || exists {
		t.Fatalf("closure manifests after rollback exists=%v err=%v", exists, err)
	}
}

func TestMigration0139UpgradePaths(t *testing.T) {
	for _, from := range []int64{128, 129, 137} {
		t.Run(strconv.FormatInt(from, 10), func(t *testing.T) {
			db, _ := newAssessmentMigrationDB(t)
			if err := goose.UpTo(db, ".", from); err != nil {
				t.Fatalf("up to %d: %v", from, err)
			}
			if err := goose.UpTo(db, ".", 138); err != nil {
				t.Fatalf("upgrade %d to 145: %v", from, err)
			}
		})
	}
}

func TestMigration0139ClosureManifestGuards(t *testing.T) {
	ctx := context.Background()
	db, dsn := newAssessmentMigrationDB(t)
	if err := goose.UpTo(db, ".", 138); err != nil {
		t.Fatalf("up to 0138: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}

	tenantID := shared.ID("m138-tenant")
	cycleID, baseline, current := createAssessmentComparisonSnapshots(t, ctx, pool, tenantID, "m138")
	comparison := postgresQueuedComparison(t, tenantID, cycleID, "m138-comparison", baseline, current, 1, time.Now().UTC())
	if _, created, err := NewAssessmentComparisonRepository(pool).CreateQueued(ctx, comparison); err != nil || !created {
		t.Fatalf("create comparison created=%v err=%v", created, err)
	}
	assessmentID := shared.ID("lineage-assessment-m138")
	manifestID := shared.ID("m138-manifest")
	now := time.Now().UTC().Truncate(time.Microsecond)
	if err := WithTenant(ctx, pool, tenantID.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO assessment_cycle_closure_manifests (
			tenant_id,cycle_id,id,manifest_version,lifecycle,cycle_version,root_assessment_id,final_assessment_id,
			initial_snapshot_id,final_snapshot_id,comparison_id,initial_snapshot_hash,final_snapshot_hash,comparison_hash,
			canonical_input_hash,policy_version,algorithm_version,fingerprint_version,risk_version,renderer_contract_version,
			as_of_at,created_at,created_by
		) VALUES ($1,$2,$3,1,'building',1,$4,$4,$5,$6,$7,$8,$9,$10,$11,'policy-v1','comparison-v1','fingerprint-v1','risk-v1','renderer-v1',$12,$12,'reviewer')`,
			tenantID.String(), cycleID.String(), manifestID.String(), assessmentID.String(), baseline.ID.String(), current.ID.String(), comparison.ID.String(),
			baseline.ContentHash, current.ContentHash, strings.Repeat("c", 64), comparison.InputHash, now)
		return err
	}); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	if err := WithTenant(ctx, pool, tenantID.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO assessment_cycle_closure_path_members
			(tenant_id,cycle_id,manifest_id,path_position,assessment_id,assessment_type,retest_number,relationship_version,snapshot_id)
			VALUES ($1,$2,$3,0,$4,'initial',0,1,$5)`, tenantID.String(), cycleID.String(), manifestID.String(), assessmentID.String(), baseline.ID.String()); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO assessment_cycle_closure_references
			(tenant_id,cycle_id,manifest_id,reference_kind,reference_id,reference_version,content_hash)
			VALUES ($1,$2,$3,'policy_input','policy-v1',1,$4)`, tenantID.String(), cycleID.String(), manifestID.String(), strings.Repeat("d", 64))
		return err
	}); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	if err := WithTenant(ctx, pool, tenantID.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE assessment_cycle_closure_manifests
			SET lifecycle='active',content_hash=$4,sealed_at=$5,sealed_by='reviewer'
			WHERE tenant_id=$1 AND cycle_id=$2 AND id=$3`, tenantID.String(), cycleID.String(), manifestID.String(), strings.Repeat("e", 64), now)
		return err
	}); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	if err := WithTenant(ctx, pool, tenantID.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE assessment_cycles SET active_closure_manifest_id=$3,active_closure_cycle_version=version
			WHERE tenant_id=$1 AND id=$2`, tenantID.String(), cycleID.String(), manifestID.String())
		return err
	}); err != nil {
		pool.Close()
		t.Fatal(err)
	}

	for name, statement := range map[string]string{
		"manifest mutation": `UPDATE assessment_cycle_closure_manifests SET reason='mutated' WHERE tenant_id=$1 AND cycle_id=$2 AND id=$3`,
		"late child": `INSERT INTO assessment_cycle_closure_references
			(tenant_id,cycle_id,manifest_id,reference_kind,reference_id,reference_version)
			VALUES ($1,$2,$3,'waiver','late',1)`,
		"cycle version drift": `UPDATE assessment_cycles SET version=version+1 WHERE tenant_id=$1 AND id=$2`,
	} {
		err := WithTenant(ctx, pool, tenantID.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, statement, tenantID.String(), cycleID.String(), manifestID.String())
			return err
		})
		if err == nil {
			pool.Close()
			t.Fatalf("%s unexpectedly succeeded", name)
		}
	}

	const rlsRole = "synapse_m138_rls"
	if _, err := pool.Exec(ctx, `CREATE ROLE `+rlsRole+` NOLOGIN NOSUPERUSER NOBYPASSRLS`); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `GRANT USAGE ON SCHEMA public TO `+rlsRole); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `GRANT SELECT ON assessment_cycle_closure_manifests TO `+rlsRole); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		pool.Close()
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+rlsRole); err != nil {
		_ = tx.Rollback(ctx)
		pool.Close()
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('app.current_tenant','m138-other-tenant',true)`); err != nil {
		_ = tx.Rollback(ctx)
		pool.Close()
		t.Fatal(err)
	}
	var crossTenantCount int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM assessment_cycle_closure_manifests`).Scan(&crossTenantCount); err != nil || crossTenantCount != 0 {
		_ = tx.Rollback(ctx)
		pool.Close()
		t.Fatalf("cross-tenant manifest count=%d err=%v", crossTenantCount, err)
	}
	_ = tx.Rollback(ctx)
	_, _ = pool.Exec(ctx, `DROP OWNED BY `+rlsRole)
	_, _ = pool.Exec(ctx, `DROP ROLE IF EXISTS `+rlsRole)
	pool.Close()

	if err := goose.DownTo(db, ".", 137); err == nil || !strings.Contains(err.Error(), "cannot roll back assessment closure manifests") {
		t.Fatalf("rollback guard error=%v", err)
	}
}

func TestAssessmentCycleScaleTargets(t *testing.T) {
	ctx := context.Background()
	db, dsn := newAssessmentMigrationDB(t)
	if err := goose.UpTo(db, ".", 138); err != nil {
		t.Fatalf("up to 0138: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	const cycleCount = 10_000
	tenantID := shared.ID("m138-scale-tenant")
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO tenants (id,name) VALUES ($1,'Assessment scale tenant')`, tenantID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO engagements (id,tenant_id,name,created_at,updated_at)
		SELECT 'm138-scale-eng-' || lpad(n::text,5,'0'),$1,'Scale assessment ' || n,
		       clock_timestamp() - make_interval(secs => $2 - n),clock_timestamp() - make_interval(secs => $2 - n)
		FROM generate_series(1,$2) AS n`, tenantID.String(), cycleCount); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO assessment_cycles
		(tenant_id,id,name,boundary_kind,status,root_assessment_id,selected_head_assessment_id,next_retest_number,version,created_at,updated_at,created_by,updated_by)
		SELECT $1,'m138-scale-cycle-' || lpad(n::text,5,'0'),'Scale cycle ' || n,'standalone','open',
		       'm138-scale-eng-' || lpad(n::text,5,'0'),'m138-scale-eng-' || lpad(n::text,5,'0'),1,1,
		       clock_timestamp() - make_interval(secs => $2 - n),clock_timestamp() - make_interval(secs => $2 - n),'scale','scale'
		FROM generate_series(1,$2) AS n`, tenantID.String(), cycleCount); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO assessment_cycle_members
		(tenant_id,cycle_id,assessment_id,assessment_type,retest_number,relationship_version,created_at,created_by)
		SELECT $1,'m138-scale-cycle-' || lpad(n::text,5,'0'),'m138-scale-eng-' || lpad(n::text,5,'0'),'initial',0,1,
		       clock_timestamp() - make_interval(secs => $2 - n),'scale'
		FROM generate_series(1,$2) AS n`, tenantID.String(), cycleCount); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `ANALYZE engagements; ANALYZE assessment_cycles; ANALYZE assessment_cycle_members`); err != nil {
		t.Fatal(err)
	}

	repository := NewAssessmentCycleRepository(pool)
	listDurations := make([]time.Duration, 0, 20)
	detailDurations := make([]time.Duration, 0, 20)
	for range 20 {
		started := time.Now()
		records, err := repository.ListCycles(ctx, ports.AssessmentCycleListQuery{TenantID: tenantID, Limit: 100})
		listDurations = append(listDurations, time.Since(started))
		if err != nil || len(records) != 100 {
			t.Fatalf("scale list records=%d err=%v", len(records), err)
		}
		started = time.Now()
		cycle, err := repository.GetCycle(ctx, tenantID, records[0].Cycle.ID)
		if err == nil {
			_, err = repository.ListMembers(ctx, tenantID, cycle.ID)
		}
		detailDurations = append(detailDurations, time.Since(started))
		if err != nil {
			t.Fatal(err)
		}
	}
	assertP95Within(t, "Cycle list", listDurations, 500*time.Millisecond)
	assertP95Within(t, "Cycle detail", detailDurations, 750*time.Millisecond)
}

func assertP95Within(t *testing.T, label string, durations []time.Duration, limit time.Duration) {
	t.Helper()
	sort.Slice(durations, func(left, right int) bool { return durations[left] < durations[right] })
	p95 := durations[(len(durations)*95+99)/100-1]
	if p95 > limit {
		t.Fatalf("%s p95=%s exceeds %s (%v)", label, p95, limit, durations)
	}
	t.Logf("%s p95=%s at %d rows", label, p95, 10_000)
}
