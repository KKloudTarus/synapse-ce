package postgres

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/migrations"
)

func TestMigration0066PreservesLegacyAssessmentGraph(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db, err := goose.OpenDBWithDriver("pgx", dsnForMigrate(dsn))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownTo(db, ".", 65); err != nil {
		t.Fatalf("down to 65: %v", err)
	}

	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	prefix := "m66-" + uuid.NewString()
	engagementID, findingID := prefix+"-eng", prefix+"-finding"
	assetID, projectID, technicalID := prefix+"-asset", prefix+"-project", prefix+"-technical"
	evidenceID, jobID := prefix+"-evidence", prefix+"-job"
	sessionID := prefix + "-session"
	evidenceHash, auditHash := prefix+"-evidence-hash", prefix+"-audit-hash"
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO fleet_business_services(id,tenant_id,name,owner) VALUES($1,'','Legacy Product','legacy-team')`, []any{assetID}},
		{`INSERT INTO projects(id,tenant_id,name,key,source_binding) VALUES($1,'','Legacy Project',$1,'{}')`, []any{projectID}},
		{`INSERT INTO fleet_assets(id,tenant_id,kind,"key",name) VALUES($1,'','workload',$1,'Legacy Workload')`, []any{technicalID}},
		{`INSERT INTO engagements(id,tenant_id,name,status) VALUES($1,'','Legacy Engagement','completed')`, []any{engagementID}},
		{`INSERT INTO scope_targets(id,engagement_id,in_scope,kind,value) VALUES($1,$2,true,'url','https://legacy.example')`, []any{prefix + "-scope", engagementID}},
		{`INSERT INTO findings(id,tenant_id,engagement_id,title) VALUES($1,'',$2,'Legacy Finding')`, []any{findingID, engagementID}},
		{`INSERT INTO evidence(id,tenant_id,finding_id,engagement_id,kind,sha256,storage_ref,content) VALUES($1,'',$2,$3,'artifact',$4,'legacy-ref','legacy')`, []any{evidenceID, findingID, engagementID, evidenceHash}},
		{`INSERT INTO finding_comments(id,tenant_id,engagement_id,finding_id,author,body) VALUES($1,'',$2,$3,'alice','legacy comment')`, []any{prefix + "-comment", engagementID, findingID}},
		{`INSERT INTO finding_retests(id,tenant_id,engagement_id,finding_id,outcome,tester) VALUES($1,'',$2,$3,'still_open','alice')`, []any{prefix + "-retest", engagementID, findingID}},
		{`INSERT INTO imported_sboms(id,tenant_id,engagement_id,spec_version,target_ref,component_count,sha256,raw_json) VALUES($1,'',$2,'1.5','legacy',1,'legacy-sbom','{}')`, []any{prefix + "-sbom", engagementID}},
		{`INSERT INTO writeup_drafts(id,tenant_id,engagement_id,finding_id,state) VALUES($1,'',$2,$3,'proposed')`, []any{prefix + "-draft", engagementID, findingID}},
		{`INSERT INTO agent_sessions(id,tenant_id,engagement_id,initiated_by,goal) VALUES($1,NULL,$2,'alice','legacy session')`, []any{sessionID, engagementID}},
		{`INSERT INTO jobs(id,kind,payload,status) VALUES($1,'sca','{}','queued')`, []any{jobID}},
		{`INSERT INTO audit_log(tenant_id,actor,action,target,hash,previous_hash) VALUES('','alice','legacy.action',$1,$2,$3)`, []any{engagementID, auditHash, prefix + "-audit-prev"}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("seed legacy graph: %v", err)
		}
	}
	if err := goose.UpTo(db, ".", 66); err != nil {
		t.Fatalf("up to 66: %v", err)
	}

	for _, table := range []string{"fleet_business_services", "projects", "fleet_assets", "engagements", "scope_targets", "findings", "evidence", "finding_comments", "finding_retests", "imported_sboms", "writeup_drafts", "agent_sessions", "jobs", "audit_log"} {
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE tenant_id='default'`).Scan(&count); err != nil {
			t.Fatalf("count migrated %s: %v", table, err)
		}
		if count == 0 {
			t.Fatalf("legacy %s row was not migrated to default tenant", table)
		}
	}
	var businessAssetID *string
	if err := pool.QueryRow(ctx, `SELECT business_asset_id FROM engagements WHERE id=$1`, engagementID).Scan(&businessAssetID); err != nil {
		t.Fatal(err)
	}
	if businessAssetID != nil {
		t.Fatalf("legacy Engagement must remain Unassigned, got %q", *businessAssetID)
	}
	var key string
	if err := pool.QueryRow(ctx, `SELECT "key" FROM fleet_business_services WHERE id=$1`, assetID).Scan(&key); err != nil || key != assetID {
		t.Fatalf("legacy Business Service key=%q err=%v", key, err)
	}
	var migratedEvidenceHash, migratedAuditHash string
	if err := pool.QueryRow(ctx, `SELECT sha256 FROM evidence WHERE id=$1`, evidenceID).Scan(&migratedEvidenceHash); err != nil || migratedEvidenceHash != evidenceHash {
		t.Fatalf("evidence custody changed: hash=%q err=%v", migratedEvidenceHash, err)
	}
	if err := pool.QueryRow(ctx, `SELECT hash FROM audit_log WHERE target=$1`, engagementID).Scan(&migratedAuditHash); err != nil || migratedAuditHash != auditHash {
		t.Fatalf("audit custody changed: hash=%q err=%v", migratedAuditHash, err)
	}
}
