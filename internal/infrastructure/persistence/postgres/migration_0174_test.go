package postgres

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"testing"

	"github.com/pressly/goose/v3"
)

func TestMigration0174FindingBackfillPreservesSingletonAndQuarantinesConflict(t *testing.T) {
	db, _ := newAssessmentMigrationDB(t)
	if err := goose.UpTo(db, ".", 173); err != nil {
		t.Fatalf("migrate to 0173: %v", err)
	}
	prefix := "m174-" + randHex(t)
	tenant, engagement := prefix+"-tenant", prefix+"-engagement"
	advisory := "CVE-2026-" + prefix
	conflictTarget, singletonTarget := "registry.example/app:1", "registry.example/worker:1"
	if _, err := db.Exec(`INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'Migration 0174')`, engagement, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO advisories(id,data) VALUES($1,'{}')`, advisory); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct {
		sbom, target, component, occurrence, finding, dedup, status, assignee string
	}{
		{prefix + "-sbom-a", conflictTarget, prefix + "-component-a", prefix + "-occurrence-a", prefix + "-finding-a", "vuln:" + advisory + ":pkg-a:1", "accepted_risk", "alice"},
		{prefix + "-sbom-a", conflictTarget, prefix + "-component-b", prefix + "-occurrence-b", prefix + "-finding-b", "vuln:" + advisory + ":pkg-b:1", "open", "bob"},
		{prefix + "-sbom-b", singletonTarget, prefix + "-component-c", prefix + "-occurrence-c", prefix + "-finding-c", "vuln:" + advisory + ":pkg-c:1", "accepted_risk", "carol"},
	} {
		if _, err := db.Exec(`INSERT INTO sboms(id,tenant_id,engagement_id,target_ref,source) VALUES($1,$2,$3,$4,'migration-test') ON CONFLICT (id) DO NOTHING`, fixture.sbom, tenant, engagement, fixture.target); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO components(id,tenant_id,sbom_id,name,version,purl,ecosystem,package_name,identity_hash,identity_status)
			VALUES($1,$2,$3,$1,'1.0','pkg:npm/example@1.0','npm',$1,$1,'resolved')`, fixture.component, tenant, fixture.sbom); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO vulnerability_occurrences(tenant_id,id,engagement_id,advisory_id,component_id,sbom_id,component_fingerprint,ecosystem,package_name,component_version,match_method,confidence,advisory_revision,state,match_evidence)
			VALUES($1,$2,$3,$4,$5,$6,$5,'npm',$5,'1.0','package_range','high',1,'detected','[{"method":"package_range","confidence":"high","criteria":"npm/example@1.0"}]')`, tenant, fixture.occurrence, engagement, advisory, fixture.component, fixture.sbom); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO findings(id,tenant_id,engagement_id,title,status,dedup_key,kind,assignee,advisory_id,occurrence_id,component_fingerprint)
			VALUES($1,$2,$3,$1,$4,$5,'sca',$6,$7,$8,$9)`, fixture.finding, tenant, engagement, fixture.status, fixture.dedup, fixture.assignee, advisory, fixture.occurrence, fixture.component); err != nil {
			t.Fatal(err)
		}
	}

	if err := goose.UpTo(db, ".", 174); err != nil {
		t.Fatalf("migrate to 0174: %v", err)
	}
	requireMigrationRLS(t, db, "vulnerability_finding_occurrences")
	requireMigrationRLS(t, db, "vulnerability_finding_backfill_conflicts")
	requireMigrationRLS(t, db, "vulnerability_primary_findings")

	var links int
	if err := db.QueryRow(`SELECT count(*) FROM vulnerability_finding_occurrences WHERE tenant_id=$1`, tenant).Scan(&links); err != nil || links != 3 {
		t.Fatalf("legacy evidence links=%d err=%v", links, err)
	}
	var reason string
	var findingCount int
	if err := db.QueryRow(`SELECT reason,cardinality(finding_ids) FROM vulnerability_finding_backfill_conflicts WHERE tenant_id=$1 AND inventory_scope=$2`, tenant, inventoryScopeForTest(conflictTarget)).Scan(&reason, &findingCount); err != nil {
		t.Fatalf("load conflict quarantine: %v", err)
	}
	if reason != "multiple_historical_workflows" || findingCount != 2 {
		t.Fatalf("conflict reason=%q findings=%d", reason, findingCount)
	}

	var id, status, assignee, dedup string
	if err := db.QueryRow(`SELECT id,status,assignee,dedup_key FROM findings WHERE id=$1`, prefix+"-finding-c").Scan(&id, &status, &assignee, &dedup); err != nil {
		t.Fatal(err)
	}
	wantDedup := targetDedupForTest(advisory, singletonTarget)
	if id != prefix+"-finding-c" || status != "accepted_risk" || assignee != "carol" || dedup != wantDedup {
		t.Fatalf("singleton workflow id=%q status=%q assignee=%q dedup=%q want=%q", id, status, assignee, dedup, wantDedup)
	}
	var mapped string
	if err := db.QueryRow(`SELECT finding_id FROM vulnerability_primary_findings WHERE tenant_id=$1 AND engagement_id=$2 AND inventory_scope=$3 AND advisory_id=$4`, tenant, engagement, inventoryScopeForTest(singletonTarget), advisory).Scan(&mapped); err != nil || mapped != prefix+"-finding-c" {
		t.Fatalf("singleton primary mapping=%q err=%v", mapped, err)
	}
	var conflictMappings int
	if err := db.QueryRow(`SELECT count(*) FROM vulnerability_primary_findings WHERE tenant_id=$1 AND engagement_id=$2 AND inventory_scope=$3 AND advisory_id=$4`, tenant, engagement, inventoryScopeForTest(conflictTarget), advisory).Scan(&conflictMappings); err != nil || conflictMappings != 0 {
		t.Fatalf("conflicted primary mappings=%d err=%v", conflictMappings, err)
	}
	var untouched string
	if err := db.QueryRow(`SELECT dedup_key FROM findings WHERE id=$1`, prefix+"-finding-a").Scan(&untouched); err != nil || untouched != "vuln:"+advisory+":pkg-a:1" {
		t.Fatalf("conflicting workflow changed: dedup=%q err=%v", untouched, err)
	}
}

func TestMigration0174NewTablesEnforceTenantRLSForNonSuperuser(t *testing.T) {
	isolated := newIsolatedMigrationDB(t, 174, 173)
	db := isolated.db
	for _, tenant := range []string{"m174-rls-a", "m174-rls-b"} {
		if _, err := db.Exec(`INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
			t.Fatal(err)
		}
		withMigrationTenant(t, db, tenant, func(tx *sql.Tx) {
			if _, err := tx.Exec(`INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,$1)`, tenant+"-eng", tenant); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(`INSERT INTO sboms(id,tenant_id,engagement_id,target_ref,source) VALUES($1,$2,$3,$4,'rls-test')`, tenant+"-sbom", tenant, tenant+"-eng", tenant+"-target"); err != nil {
				t.Fatal(err)
			}
		})
	}
	if err := goose.UpTo(db, ".", 174); err != nil {
		t.Fatalf("migrate to 0174: %v", err)
	}
	for _, table := range []string{"vulnerability_inventory_scopes", "vulnerability_inventory_work", "vulnerability_finding_occurrences", "vulnerability_finding_backfill_conflicts", "vulnerability_primary_findings"} {
		requireMigrationRLS(t, db, table)
	}
	var superuser, bypass bool
	if err := db.QueryRow(`SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user`).Scan(&superuser, &bypass); err != nil || superuser || bypass {
		t.Fatalf("migration role super=%v bypass=%v err=%v", superuser, bypass, err)
	}
	for _, tenant := range []string{"m174-rls-a", "m174-rls-b"} {
		withMigrationTenant(t, db, tenant, func(tx *sql.Tx) {
			scope := "scope-" + tenant
			if _, err := tx.Exec(`UPDATE sboms SET inventory_scope=$2,inventory_generation=1,inventory_completeness='complete',inventory_authoritative=true,
				inventory_authority_reason='rls-test',inventory_admitted_at=now(),inventory_published_at=now() WHERE tenant_id=$1 AND id=$3`, tenant, scope, tenant+"-sbom"); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(`INSERT INTO vulnerability_inventory_scopes(tenant_id,engagement_id,inventory_scope,latest_admitted_generation,current_generation,current_sbom_id,current_published_at)
				VALUES($1,$2,$3,1,1,$4,now())`, tenant, tenant+"-eng", scope, tenant+"-sbom"); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(`INSERT INTO vulnerability_inventory_work(tenant_id,engagement_id,inventory_scope,inventory_generation,sbom_id)
				VALUES($1,$2,$3,1,$4)`, tenant, tenant+"-eng", scope, tenant+"-sbom"); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(`INSERT INTO vulnerability_finding_backfill_conflicts(tenant_id,engagement_id,inventory_scope,advisory_id,desired_dedup_key,finding_ids,occurrence_ids,reason)
				VALUES($1,$2,$3,$4,$5,ARRAY[$6],ARRAY[$7],'multiple_historical_workflows')`, tenant, tenant+"-eng", scope, "CVE-2026-"+tenant, "dedup-"+tenant, "finding-"+tenant, "occurrence-"+tenant); err != nil {
				t.Fatal(err)
			}
		})
	}
	withMigrationTenant(t, db, "m174-rls-a", func(tx *sql.Tx) {
		for _, table := range []string{"vulnerability_inventory_scopes", "vulnerability_inventory_work", "vulnerability_finding_backfill_conflicts"} {
			var count int
			if err := tx.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); err != nil || count != 1 {
				t.Fatalf("tenant-a unscoped %s count=%d err=%v", table, count, err)
			}
		}
		requireMigrationWriteRejected(t, tx, `INSERT INTO vulnerability_inventory_scopes(tenant_id,engagement_id,inventory_scope,latest_admitted_generation) VALUES('m174-rls-b','m174-rls-b-eng','forged',0)`)
	})
}

func inventoryScopeForTest(target string) string {
	digest := sha256.Sum256([]byte(target))
	return "target:" + hex.EncodeToString(digest[:16])
}

func targetDedupForTest(advisory, target string) string {
	digest := sha256.Sum256([]byte(inventoryScopeForTest(target)))
	return "vuln:" + advisory + ":target-" + hex.EncodeToString(digest[:16]) + ":all"
}
