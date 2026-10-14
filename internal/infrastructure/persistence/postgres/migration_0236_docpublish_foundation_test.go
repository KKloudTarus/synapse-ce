package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pressly/goose/v3"
)

func TestMigration0236DocpublishFoundationUpgradeRollbackAndReapply(t *testing.T) {
	isolate := newIsolatedMigrationDB(t, 236, 235)
	db := isolate.db
	const tenant = "doc-migration"
	const engagement = "doc-migration-engagement"
	const integration = "doc-migration-integration"
	const project = "doc-migration-project"
	const otherTenant = "doc-migration-other"
	const otherEngagement = "doc-migration-other-engagement"

	if _, err := db.Exec(`INSERT INTO tenants (id,name) VALUES ($1,$1)`, tenant); err != nil {
		t.Fatalf("seed pre-upgrade tenant: %v", err)
	}
	withMigrationTenant(t, db, tenant, func(tx *sql.Tx) {
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO engagements (id,tenant_id,name) VALUES ($1,$2,'Document migration engagement')`, []any{engagement, tenant}},
			{`INSERT INTO integrations (id,tenant_id,provider,display_name,endpoint,created_at,updated_at)
                VALUES ($1,$2,'jenkins','Document migration integration','https://jenkins.example',now(),now())`, []any{integration, tenant}},
			{`INSERT INTO projects (id,tenant_id,name,key,source_binding) VALUES ($1,$2,'Document migration project','doc-migration','{}'::jsonb)`, []any{project, tenant}},
		} {
			if _, err := tx.Exec(statement.query, statement.args...); err != nil {
				t.Fatalf("seed pre-upgrade dependency: %v", err)
			}
		}
	})
	if _, err := db.Exec(`INSERT INTO tenants (id,name) VALUES ($1,$1)`, otherTenant); err != nil {
		t.Fatalf("seed second pre-upgrade tenant: %v", err)
	}
	withMigrationTenant(t, db, otherTenant, func(tx *sql.Tx) {
		if _, err := tx.Exec(`INSERT INTO engagements (id,tenant_id,name) VALUES ($1,$2,'Second document migration engagement')`, otherEngagement, otherTenant); err != nil {
			t.Fatalf("seed second pre-upgrade dependency: %v", err)
		}
	})

	if err := goose.UpTo(db, ".", 236); err != nil {
		t.Fatalf("upgrade documentation publishing foundation: %v", err)
	}
	for _, table := range []string{"document_links", "document_intents"} {
		requireMigrationTable(t, db, table, true)
		requireMigrationRLS(t, db, table)
	}
	requireMigrationIndexes(t, db, "document_links_engagement_idx", "document_links_project_idx",
		"document_intents_due_idx", "document_intents_target_idx")

	withMigrationTenant(t, db, tenant, func(tx *sql.Tx) {
		for _, table := range []string{"engagements", "integrations", "projects"} {
			var count int
			if err := tx.QueryRow(`SELECT count(*) FROM `+table+` WHERE tenant_id=$1`, tenant).Scan(&count); err != nil || count != 1 {
				t.Fatalf("pre-upgrade %s survived=%d err=%v", table, count, err)
			}
		}
		rejectStatement := func(statement, code, constraint string, args ...any) {
			t.Helper()
			if _, err := tx.Exec("SAVEPOINT rejected_document_statement"); err != nil {
				t.Fatalf("save rejected document statement: %v", err)
			}
			_, err := tx.Exec(statement, args...)
			var state interface{ SQLState() string }
			if !errors.As(err, &state) || state.SQLState() != code ||
				(constraint != "" && !strings.Contains(err.Error(), constraint)) {
				t.Fatalf("expected document constraint %s/%s: %v", code, constraint, err)
			}
			if _, err := tx.Exec("ROLLBACK TO SAVEPOINT rejected_document_statement"); err != nil {
				t.Fatalf("restore after rejected document statement: %v", err)
			}
			if _, err := tx.Exec("RELEASE SAVEPOINT rejected_document_statement"); err != nil {
				t.Fatalf("release rejected document statement: %v", err)
			}
		}
		const linkInsert = `INSERT INTO document_links
            (id,tenant_id,integration_id,source_kind,source_ref,engagement_id,project_id,container,remote_page_id,remote_version,remote_url,content_hash,revision,created_at,updated_at)
            VALUES `
		rejectStatement(linkInsert+`('doc-migration-wrong-scope',$1,$2,'engagement_report','r',NULL,$3,'SEC','1',1,'https://wiki.example/p',repeat('a',64),1,now(),now())`,
			"23514", "document_links_kind_scope_check", tenant, integration, project)
		rejectStatement(linkInsert+`('doc-migration-both-scopes',$1,$2,'engagement_report','r',$3,$4,'SEC','1',1,'https://wiki.example/p',repeat('a',64),1,now(),now())`,
			"23514", "document_links_scope_check", tenant, integration, engagement, project)
		rejectStatement(linkInsert+`('doc-migration-credential-url',$1,$2,'engagement_report','r',$3,NULL,'SEC','1',1,'https://user:pw@wiki.example/p',repeat('a',64),1,now(),now())`,
			"23514", "", tenant, integration, engagement)
		if _, err := tx.Exec(linkInsert+`('doc-migration-link',$1,$2,'engagement_report','r',$3,NULL,'SEC','1',1,'https://wiki.example/p',repeat('a',64),1,now(),now())`,
			tenant, integration, engagement); err != nil {
			t.Fatalf("insert document link: %v", err)
		}
		rejectStatement(linkInsert+`('doc-migration-twin',$1,$2,'engagement_report','r',$3,NULL,'SEC','2',1,'https://wiki.example/p',repeat('b',64),1,now(),now())`,
			"23505", "document_links_target_unique", tenant, integration, engagement)
		// The same artifact in another container is another page.
		if _, err := tx.Exec(linkInsert+`('doc-migration-other-container',$1,$2,'engagement_report','r',$3,NULL,'OPS','3',1,'https://wiki.example/q',repeat('b',64),1,now(),now())`,
			tenant, integration, engagement); err != nil {
			t.Fatalf("another container is another link: %v", err)
		}
		rejectStatement(`DELETE FROM engagements WHERE tenant_id=$1 AND id=$2`,
			"23503", "document_links_engagement_fk", tenant, engagement)
		if _, err := tx.Exec(`INSERT INTO document_links
            (id,tenant_id,integration_id,source_kind,source_ref,project_id,container,remote_page_id,remote_version,remote_url,content_hash,revision,created_at,updated_at)
            VALUES ('doc-migration-project-link',$1,$2,'assessment_closure_report','cycle-1',$3,'SEC','4',1,'https://wiki.example/c',repeat('c',64),1,now(),now())`,
			tenant, integration, project); err != nil {
			t.Fatalf("insert project scoped link: %v", err)
		}
		rejectStatement(`DELETE FROM projects WHERE tenant_id=$1 AND id=$2`,
			"23503", "document_links_project_fk", tenant, project)

		const intentInsert = `INSERT INTO document_intents
            (id,tenant_id,integration_id,source_kind,source_ref,engagement_id,container,link_id,action,request_key,payload_digest,content_hash,correlation_marker,state,remote_id,remote_url,remote_version,created_at,updated_at)
            VALUES `
		rejectStatement(intentInsert+`('doc-migration-i1',$1,$2,'engagement_report','r',$3,'SEC',NULL,'update','k1',repeat('a',64),repeat('b',64),'synapse-intent-doc-migration-i1','pending','','',0,now(),now())`,
			"23514", "", tenant, integration, engagement)
		rejectStatement(intentInsert+`('doc-migration-i2',$1,$2,'engagement_report','r',$3,'SEC','doc-migration-link','create','k2',repeat('a',64),repeat('b',64),'synapse-intent-doc-migration-i2','pending','','',0,now(),now())`,
			"23514", "", tenant, integration, engagement)
		rejectStatement(intentInsert+`('doc-migration-i3',$1,$2,'engagement_report','r',$3,'SEC',NULL,'create','k3',repeat('a',64),repeat('b',64),'synapse-intent-doc-migration-i3','done','1','https://wiki.example/p',0,now(),now())`,
			"23514", "", tenant, integration, engagement)
		if _, err := tx.Exec(intentInsert+`('doc-migration-done',$1,$2,'engagement_report','r',$3,'SEC',NULL,'create','done',repeat('c',64),repeat('b',64),'synapse-intent-doc-migration-done','done','1','https://wiki.example/p',1,now(),now())`,
			tenant, integration, engagement); err != nil {
			t.Fatalf("insert completed durable document intent: %v", err)
		}
		// An intent is evidence of a remote write: the link it wrote to may go, the intent stays.
		if _, err := tx.Exec(`DELETE FROM document_links WHERE tenant_id=$1 AND id='doc-migration-project-link'`, tenant); err != nil {
			t.Fatalf("link removal is not blocked by intents: %v", err)
		}
	})
	withMigrationTenant(t, db, otherTenant, func(tx *sql.Tx) {
		var count int
		if err := tx.QueryRow(`SELECT count(*) FROM document_links`).Scan(&count); err != nil || count != 0 {
			t.Fatalf("second tenant sees %d document links err=%v", count, err)
		}
	})

	if err := goose.DownTo(db, ".", 235); err == nil {
		t.Fatal("rollback with durable document data succeeded")
	}
	withMigrationTenant(t, db, tenant, func(tx *sql.Tx) {
		var links, intents int
		if err := tx.QueryRow(`SELECT count(*) FROM document_links WHERE tenant_id=$1`, tenant).Scan(&links); err != nil || links != 2 {
			t.Fatalf("failed rollback changed durable links count=%d err=%v", links, err)
		}
		if err := tx.QueryRow(`SELECT count(*) FROM document_intents WHERE tenant_id=$1`, tenant).Scan(&intents); err != nil || intents != 1 {
			t.Fatalf("failed rollback changed durable intents count=%d err=%v", intents, err)
		}
		for _, table := range []string{"document_intents", "document_links"} {
			if _, err := tx.Exec(`DELETE FROM `+table+` WHERE tenant_id=$1`, tenant); err != nil {
				t.Fatalf("clear %s for reversible rollback: %v", table, err)
			}
		}
	})
	if err := goose.DownTo(db, ".", 235); err != nil {
		t.Fatalf("rollback empty documentation publishing foundation: %v", err)
	}
	for _, table := range []string{"document_links", "document_intents"} {
		requireMigrationTable(t, db, table, false)
	}
	if err := goose.UpTo(db, ".", 236); err != nil {
		t.Fatalf("reapply documentation publishing foundation: %v", err)
	}
	withMigrationTenant(t, db, tenant, func(tx *sql.Tx) {
		var count int
		if err := tx.QueryRow(`SELECT count(*) FROM projects WHERE tenant_id=$1 AND id=$2`, tenant, project).Scan(&count); err != nil || count != 1 {
			t.Fatalf("pre-existing project after reapply count=%d err=%v", count, err)
		}
	})
}

func TestMigration0236RollbackWaitsForConcurrentDocumentData(t *testing.T) {
	isolate := newIsolatedMigrationDB(t, 236, 235)
	db := isolate.db
	if err := goose.UpTo(db, ".", 236); err != nil {
		t.Fatalf("apply documentation publishing foundation: %v", err)
	}
	const tenant = "doc-rollback-race"
	const integration = "doc-rollback-race-integration"
	const engagement = "doc-rollback-race-engagement"
	if _, err := db.Exec(`INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatalf("seed rollback-race tenant: %v", err)
	}
	withMigrationTenant(t, db, tenant, func(tx *sql.Tx) {
		if _, err := tx.Exec(`INSERT INTO integrations(id,tenant_id,provider,display_name,endpoint,created_at,updated_at)
            VALUES($1,$2,'jenkins','Document rollback race','https://jenkins.example',now(),now())`, integration, tenant); err != nil {
			t.Fatalf("seed rollback-race integration: %v", err)
		}
		if _, err := tx.Exec(`INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'Document rollback race')`, engagement, tenant); err != nil {
			t.Fatalf("seed rollback-race engagement: %v", err)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	writer, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("reserve concurrent document writer: %v", err)
	}
	defer writer.Close()
	writerTx, err := writer.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin concurrent document writer: %v", err)
	}
	defer func() { _ = writerTx.Rollback() }()
	if _, err := writerTx.ExecContext(ctx, `SELECT set_config('app.current_tenant',$1,true)`, tenant); err != nil {
		t.Fatalf("scope concurrent document writer: %v", err)
	}
	if _, err := writerTx.ExecContext(ctx, `INSERT INTO document_links
        (id,tenant_id,integration_id,source_kind,source_ref,engagement_id,container,remote_page_id,remote_version,remote_url,content_hash,revision,created_at,updated_at)
        VALUES ('doc-rollback-race-link',$1,$2,'engagement_report','r',$3,'SEC','1',1,'https://wiki.example/p',repeat('a',64),1,now(),now())`,
		tenant, integration, engagement); err != nil {
		t.Fatalf("record uncommitted document link: %v", err)
	}

	downResult := make(chan error, 1)
	go func() { downResult <- goose.DownTo(db, ".", 235) }()
	waitForMigration0236ExclusiveLock(t, ctx, db)
	if err := writerTx.Commit(); err != nil {
		t.Fatalf("commit concurrent document link: %v", err)
	}
	select {
	case err := <-downResult:
		if err == nil || !strings.Contains(err.Error(), "durable document data") {
			t.Fatalf("rollback error = %v, want durable-document-data refusal", err)
		}
	case <-ctx.Done():
		t.Fatalf("rollback did not finish after the concurrent link committed: %v", ctx.Err())
	}
	for _, table := range []string{"document_links", "document_intents"} {
		requireMigrationRLS(t, db, table)
	}
	withMigrationTenant(t, db, tenant, func(tx *sql.Tx) {
		var count int
		if err := tx.QueryRow(`SELECT count(*) FROM document_links WHERE id='doc-rollback-race-link'`).Scan(&count); err != nil || count != 1 {
			t.Fatalf("concurrent link after rejected rollback count=%d err=%v", count, err)
		}
	})
}

func waitForMigration0236ExclusiveLock(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	const query = `SELECT EXISTS (
		SELECT 1 FROM pg_locks
		WHERE relation = 'document_links'::regclass
		  AND mode = 'AccessExclusiveLock'
		  AND NOT granted
	)`
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		if err := db.QueryRowContext(ctx, query).Scan(&waiting); err != nil {
			t.Fatalf("inspect documentation migration lock request: %v", err)
		}
		if waiting {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("rollback never requested an exclusive document_links lock: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}
