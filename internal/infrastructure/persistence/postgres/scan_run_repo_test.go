package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestPostgresScanRunStoreSealingRLSAtomicityAndConcurrency(t *testing.T) {
	sharedDSN := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if sharedDSN == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	dsn := isolatedMigration0140DSN(t, sharedDSN)
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	store := NewScanRunStore(pool)
	suffix := time.Now().UnixNano()
	tenantA := shared.ID(fmt.Sprintf("scan-tenant-a-%d", suffix))
	tenantB := shared.ID(fmt.Sprintf("scan-tenant-b-%d", suffix))
	engagementA := shared.ID(fmt.Sprintf("scan-eng-a-%d", suffix))
	engagementB := shared.ID(fmt.Sprintf("scan-eng-b-%d", suffix))
	ensureTestTenantAndEngagement(t, ctx, pool, tenantA, engagementA, "", "")
	ensureTestTenantAndEngagement(t, ctx, pool, tenantB, engagementB, "", "")

	run := postgresNativeRun(t, tenantA, engagementA, shared.ID(fmt.Sprintf("scan-run-%d", suffix)), strings.Repeat("b", 64))
	if err := store.Begin(ctx, beginningPostgresScanRun(run)); err != nil {
		t.Fatal(err)
	}
	differentStart := beginningPostgresScanRun(run)
	differentStart.CreatedAt = differentStart.CreatedAt.Add(time.Second)
	if err := store.Begin(ctx, differentStart); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("changed begin timestamp = %v", err)
	}
	if err := run.Seal(scanrun.StatusSucceeded, 1, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := store.Seal(ctx, run); err != nil {
		t.Fatal(err)
	}
	if err := store.Seal(ctx, run); err != nil {
		t.Fatalf("idempotent seal: %v", err)
	}
	stored, err := store.Get(ctx, tenantA, run.ID)
	if err != nil || stored.ManifestHash != run.ManifestHash || len(stored.Lanes) != 1 || len(stored.Lanes[0].Versions) == 0 || len(stored.Lanes[0].Stages) == 0 {
		t.Fatalf("stored run = %+v, %v", stored, err)
	}
	if _, err := store.Get(ctx, tenantB, run.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant get = %v", err)
	}
	assertScanRunRLS(t, ctx, pool, tenantA, tenantB, engagementA, run.ID)
	if err := WithTenant(ctx, pool, tenantA.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE scan_runs SET manifest='{}'::jsonb WHERE tenant_id=$1 AND id=$2`, tenantA.String(), run.ID)
		return err
	}); err == nil {
		t.Fatal("sealed header update succeeded")
	}
	for name, query := range map[string]string{
		"lane":    `UPDATE scan_run_lanes SET producer='tampered' WHERE tenant_id=$1 AND scan_run_id=$2`,
		"version": `UPDATE scan_run_lane_versions SET version='tampered' WHERE tenant_id=$1 AND scan_run_id=$2`,
		"stage":   `UPDATE scan_run_lane_stages SET reason_code='tampered' WHERE tenant_id=$1 AND scan_run_id=$2`,
	} {
		if err := WithTenant(ctx, pool, tenantA.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, query, tenantA.String(), run.ID)
			return err
		}); err == nil {
			t.Fatalf("sealed %s update succeeded", name)
		}
	}
	if err := WithTenant(ctx, pool, tenantA.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO scan_run_lanes
			(tenant_id,engagement_id,scan_run_id,lane_key,producer,terminal_status,target_kind,target_identity_schema_version,
			 target_identity_canonical,evaluated_revision,authoritative_finding_kinds,included_scope,excluded_scope,started_at,
			 result_ref,evidence_ref,manifest_schema_version,manifest_hash)
			VALUES($1,$2,$3,'late','late','building','host',1,'host:late','',ARRAY[]::text[],'[]'::jsonb,'[]'::jsonb,now(),'','',1,$4)`,
			tenantA.String(), engagementA.String(), run.ID, strings.Repeat("a", 64))
		return err
	}); err == nil {
		t.Fatal("sealed header accepted a new lane")
	}

	crossTenant := postgresNativeRun(t, tenantA, engagementB, shared.ID(fmt.Sprintf("cross-run-%d", suffix)), strings.Repeat("c", 64))
	if err := store.Begin(ctx, beginningPostgresScanRun(crossTenant)); err == nil {
		t.Fatal("cross-tenant engagement FK accepted")
	}

	rollbackRun := postgresNativeRun(t, tenantA, engagementA, shared.ID(fmt.Sprintf("rollback-run-%d", suffix)), strings.Repeat("d", 64))
	rollbackRun.Lanes[0].Versions = append(rollbackRun.Lanes[0].Versions, rollbackRun.Lanes[0].Versions[0])
	if err := store.Begin(ctx, beginningPostgresScanRun(rollbackRun)); err != nil {
		t.Fatal(err)
	}
	if err := rollbackRun.Seal(scanrun.StatusSucceeded, 1, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := store.Seal(ctx, rollbackRun); err == nil {
		t.Fatal("duplicate lane version did not roll back")
	}
	building, err := store.Get(ctx, tenantA, rollbackRun.ID)
	if err != nil || building.TerminalStatus != scanrun.StatusBuilding || len(building.Lanes) != 0 {
		t.Fatalf("transaction rollback = %+v, %v", building, err)
	}

	concurrentID := shared.ID(fmt.Sprintf("concurrent-run-%d", suffix))
	first := postgresNativeRun(t, tenantA, engagementA, concurrentID, strings.Repeat("e", 64))
	if err := store.Begin(ctx, beginningPostgresScanRun(first)); err != nil {
		t.Fatal(err)
	}
	second := first
	second.Manifest.SBOMSHA256 = strings.Repeat("f", 64)
	second.Lanes = append([]scanrun.Lane(nil), first.Lanes...)
	second.Lanes[0].ResultSHA256 = strings.Repeat("f", 64)
	if err := first.Seal(scanrun.StatusSucceeded, 1, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := second.Seal(scanrun.StatusSucceeded, 1, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	errorsSeen := make(chan error, 2)
	for _, candidate := range []ports.ScanRun{first, second} {
		wait.Add(1)
		go func(candidate ports.ScanRun) {
			defer wait.Done()
			errorsSeen <- store.Seal(context.Background(), candidate)
		}(candidate)
	}
	wait.Wait()
	close(errorsSeen)
	var successes, conflicts int
	for err := range errorsSeen {
		if err == nil {
			successes++
		} else if errors.Is(err, shared.ErrConflict) {
			conflicts++
		} else {
			t.Fatalf("concurrent seal error = %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent seals successes=%d conflicts=%d", successes, conflicts)
	}
}

func assertScanRunRLS(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantA, tenantB, engagementA shared.ID, runID string) {
	t.Helper()
	role := "scan_run_runtime_" + randHex(t)
	quotedRole := pgx.Identifier{role}.Sanitize()
	if _, err := pool.Exec(ctx, `CREATE ROLE `+quotedRole+` NOSUPERUSER NOBYPASSRLS`); err != nil {
		t.Fatalf("create scan-run RLS role: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := pool.Exec(cleanupCtx, `DROP OWNED BY `+quotedRole); err != nil {
			t.Errorf("drop scan-run RLS role ownership: %v", err)
		}
		if _, err := pool.Exec(cleanupCtx, `DROP ROLE IF EXISTS `+quotedRole); err != nil {
			t.Errorf("drop scan-run RLS role: %v", err)
		}
	})
	for _, statement := range []string{
		`GRANT USAGE ON SCHEMA public TO ` + quotedRole,
		`GRANT SELECT,INSERT ON scan_runs,scan_run_lanes,scan_run_lane_versions,scan_run_lane_stages TO ` + quotedRole,
	} {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatalf("grant scan-run RLS role: %v", err)
		}
	}
	var superuser, bypassRLS bool
	if err := pool.QueryRow(ctx, `SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=$1`, role).Scan(&superuser, &bypassRLS); err != nil || superuser || bypassRLS {
		t.Fatalf("runtime role superuser=%v bypassrls=%v err=%v", superuser, bypassRLS, err)
	}

	for _, table := range []string{"scan_runs", "scan_run_lanes", "scan_run_lane_versions", "scan_run_lane_stages"} {
		var enabled, forced bool
		if err := pool.QueryRow(ctx, `SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid=$1::regclass`, table).Scan(&enabled, &forced); err != nil || !enabled || !forced {
			t.Fatalf("%s RLS enabled=%v forced=%v err=%v", table, enabled, forced, err)
		}
		column := "scan_run_id"
		if table == "scan_runs" {
			column = "id"
		}
		countVisible := func(tenantID shared.ID) int {
			t.Helper()
			var count int
			err := WithTenant(ctx, pool, tenantID.String(), func(tx pgx.Tx) error {
				if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+quotedRole); err != nil {
					return err
				}
				return tx.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE `+column+`=$1`, runID).Scan(&count)
			})
			if err != nil {
				t.Fatalf("count %s for tenant %q: %v", table, tenantID, err)
			}
			return count
		}
		if countVisible(tenantA) != 1 || countVisible(tenantB) != 0 || countVisible("") != 0 {
			t.Fatalf("%s RLS did not isolate run %s", table, runID)
		}
	}

	if err := WithTenant(ctx, pool, tenantB.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+quotedRole); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO scan_runs
			(id,tenant_id,engagement_id,created_at,manifest,finding_keys,provenance,terminal_status)
			VALUES($1,$2,$3,now(),'{}'::jsonb,'[]'::jsonb,'native','building')`,
			"rls-forged-"+runID, tenantA.String(), engagementA.String())
		return err
	}); err == nil {
		t.Fatal("runtime role inserted a row for another tenant")
	}
}

func postgresNativeRun(t *testing.T, tenantID, engagementID, runID shared.ID, resultHash string) ports.ScanRun {
	t.Helper()
	started := time.Now().UTC().Add(-time.Minute)
	finished := time.Now().UTC()
	target, err := scanrun.CanonicalTarget(scanrun.TargetInput{Kind: scanrun.TargetRepository, Raw: "https://github.com/org/repo", EvaluatedRevision: strings.Repeat("a", 40), SchemaVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	return ports.ScanRun{
		TenantID: tenantID.String(), ID: runID.String(), EngagementID: engagementID.String(), CreatedAt: started,
		Provenance: scanrun.ProvenanceNative, TerminalStatus: scanrun.StatusBuilding,
		Manifest: ports.ScanManifest{SBOMSHA256: resultHash}, FindingKeys: []string{"finding-1"},
		Lanes: []scanrun.Lane{{
			Key: "sca", Producer: "synapse-sca", TerminalStatus: scanrun.StatusSucceeded, Target: target,
			AuthoritativeFindingKinds: []string{"sca"}, IncludedScope: []string{"repo:https://github.com/org/repo"},
			StartedAt: started, FinishedAt: &finished, ResultRef: "scan-result/" + runID.String(), EvidenceRef: "evidence-1", ResultSHA256: resultHash, ManifestSchemaVersion: 1,
			Versions: []scanrun.Version{{Kind: scanrun.VersionTool, Name: "synapse", Version: "v1"}},
			Stages:   []scanrun.Stage{{Key: "pipeline", Status: scanrun.StageSucceeded}},
		}},
	}
}

func beginningPostgresScanRun(run ports.ScanRun) ports.ScanRun {
	run.Manifest = ports.ScanManifest{}
	run.FindingKeys = nil
	run.Lanes = nil
	return run
}
