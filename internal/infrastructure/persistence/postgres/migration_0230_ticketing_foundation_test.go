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

func TestMigration0230TicketingFoundationUpgradeRollbackAndReapply(t *testing.T) {
	isolate := newIsolatedMigrationDB(t, 230, 229)
	db := isolate.db
	const tenant = "ticket-migration"
	const engagement = "ticket-migration-engagement"
	const finding = "ticket-migration-finding"
	const integration = "ticket-migration-integration"
	const project = "ticket-migration-project"
	const otherTenant = "ticket-migration-other"
	const otherEngagement = "ticket-migration-other-engagement"
	const otherIntegration = "ticket-migration-other-integration"
	const otherProject = "ticket-migration-other-project"

	if _, err := db.Exec(`INSERT INTO tenants (id,name) VALUES ($1,$1)`, tenant); err != nil {
		t.Fatalf("seed pre-upgrade tenant: %v", err)
	}
	withMigrationTenant(t, db, tenant, func(tx *sql.Tx) {
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO engagements (id,tenant_id,name) VALUES ($1,$2,'Ticket migration engagement')`, []any{engagement, tenant}},
			{`INSERT INTO findings (id,tenant_id,engagement_id,title) VALUES ($1,$2,$3,'Ticket migration finding')`, []any{finding, tenant, engagement}},
			{`INSERT INTO integrations (id,tenant_id,provider,display_name,endpoint,created_at,updated_at)
                VALUES ($1,$2,'jenkins','Ticket migration integration','https://jenkins.example',now(),now())`, []any{integration, tenant}},
			{`INSERT INTO projects (id,tenant_id,name,key,source_binding) VALUES ($1,$2,'Ticket migration project','ticket-migration','{}'::jsonb)`, []any{project, tenant}},
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
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO engagements (id,tenant_id,name) VALUES ($1,$2,'Second ticket migration engagement')`, []any{otherEngagement, otherTenant}},
			{`INSERT INTO integrations (id,tenant_id,provider,display_name,endpoint,created_at,updated_at)
                VALUES ($1,$2,'jenkins','Second ticket migration integration','https://jenkins.example',now(),now())`, []any{otherIntegration, otherTenant}},
			{`INSERT INTO projects (id,tenant_id,name,key,source_binding) VALUES ($1,$2,'Second ticket migration project','ticket-migration-other','{}'::jsonb)`, []any{otherProject, otherTenant}},
		} {
			if _, err := tx.Exec(statement.query, statement.args...); err != nil {
				t.Fatalf("seed second pre-upgrade dependency: %v", err)
			}
		}
	})

	if err := goose.UpTo(db, ".", 230); err != nil {
		t.Fatalf("upgrade ticketing foundation: %v", err)
	}
	for _, table := range []string{"ticket_mappings", "ticket_links", "ticket_intents"} {
		requireMigrationTable(t, db, table, true)
		requireMigrationRLS(t, db, table)
	}
	requireMigrationIndexes(t, db, "ticket_mappings_project_unique", "ticket_mappings_engagement_unique", "ticket_links_finding_idx", "ticket_intents_due_idx", "ticket_intents_finding_idx")

	withMigrationTenant(t, db, tenant, func(tx *sql.Tx) {
		for _, table := range []string{"engagements", "findings", "integrations", "projects"} {
			var count int
			if err := tx.QueryRow(`SELECT count(*) FROM `+table+` WHERE tenant_id=$1`, tenant).Scan(&count); err != nil || count != 1 {
				t.Fatalf("pre-upgrade %s survived=%d err=%v", table, count, err)
			}
		}
		_, err := tx.Exec(`INSERT INTO ticket_mappings
            (id,tenant_id,integration_id,project_id,project_key,issue_type,labels,priority_map,version,created_at,updated_at)
            VALUES (
                'ticket-migration-mapping',$1,$2,$3,'SEC','Bug',
                (SELECT jsonb_agg(CASE WHEN n <= 31 THEN repeat('x',255) ELSE repeat('y',190) END ORDER BY n)
                    FROM generate_series(1,32) AS n),
                (SELECT jsonb_object_agg(lpad(n::text,64,'k'), CASE WHEN n = 32 THEN repeat('v',216) ELSE repeat('v',185) END)
                    FROM generate_series(1,32) AS n),
                1,now(),now())`, tenant, integration, project)
		if err != nil {
			t.Fatalf("insert project-scoped mapping with domain-sized JSON: %v", err)
		}
		var labelsCompact, labelsStored, prioritiesCompact, prioritiesStored int
		if err := tx.QueryRow(`SELECT
            octet_length(replace(labels::text, ', ', ',')), octet_length(labels::text),
            octet_length(replace(replace(priority_map::text, ', ', ','), ': ', ':')), octet_length(priority_map::text)
            FROM ticket_mappings WHERE tenant_id=$1 AND id='ticket-migration-mapping'`, tenant).
			Scan(&labelsCompact, &labelsStored, &prioritiesCompact, &prioritiesStored); err != nil {
			t.Fatalf("read normalized JSON sizes: %v", err)
		}
		if labelsCompact != 8192 || labelsStored != 8223 || prioritiesCompact != 8192 || prioritiesStored != 8255 {
			t.Fatalf("domain JSON size compatibility labels=%d/%d priorities=%d/%d", labelsCompact, labelsStored, prioritiesCompact, prioritiesStored)
		}
		rejectStatement := func(statement, code, constraint string, args ...any) {
			t.Helper()
			if _, err := tx.Exec("SAVEPOINT rejected_ticket_statement"); err != nil {
				t.Fatalf("save rejected ticket statement: %v", err)
			}
			_, err := tx.Exec(statement, args...)
			var state interface{ SQLState() string }
			if !errors.As(err, &state) || state.SQLState() != code ||
				(constraint != "" && !strings.Contains(err.Error(), constraint)) {
				t.Fatalf("expected ticket constraint %s/%s: %v", code, constraint, err)
			}
			if _, err := tx.Exec("ROLLBACK TO SAVEPOINT rejected_ticket_statement"); err != nil {
				t.Fatalf("restore after rejected ticket statement: %v", err)
			}
			if _, err := tx.Exec("RELEASE SAVEPOINT rejected_ticket_statement"); err != nil {
				t.Fatalf("release rejected ticket statement: %v", err)
			}
		}
		for _, statement := range []string{
			`INSERT INTO ticket_intents
                (id,tenant_id,integration_id,mapping_id,finding_id,engagement_id,action,request_key,payload_digest,correlation_marker,state,created_at,updated_at)
                VALUES ('ticket-migration-missing-remote',$1,$2,'ticket-migration-mapping',$3,$4,'create','missing-remote',repeat('a',64),'synapse-intent-ticket-migration-missing-remote','done',now(),now())`,
			`INSERT INTO ticket_intents
                (id,tenant_id,integration_id,mapping_id,finding_id,engagement_id,action,request_key,payload_digest,correlation_marker,state,created_at,updated_at)
                VALUES ('ticket-migration-missing-error',$1,$2,'ticket-migration-mapping',$3,$4,'create','missing-error',repeat('b',64),'synapse-intent-ticket-migration-missing-error','failed',now(),now())`,
			`INSERT INTO ticket_intents
                (id,tenant_id,integration_id,mapping_id,finding_id,engagement_id,action,request_key,payload_digest,correlation_marker,state,remote_id,created_at,updated_at)
                VALUES ('ticket-migration-partial-remote',$1,$2,'ticket-migration-mapping',$3,$4,'create','partial-remote',repeat('d',64),'synapse-intent-ticket-migration-partial-remote','pending','SEC-2',now(),now())`,
		} {
			rejectStatement(statement, "23514", "", tenant, integration, finding, engagement)
		}
		if _, err := tx.Exec(`INSERT INTO ticket_intents
            (id,tenant_id,integration_id,mapping_id,finding_id,engagement_id,action,request_key,payload_digest,correlation_marker,state,remote_id,remote_url,created_at,updated_at)
            VALUES ('ticket-migration-done',$1,$2,'ticket-migration-mapping',$3,$4,'create','done',repeat('c',64),'synapse-intent-ticket-migration-done','done','SEC-1','https://jira.example/browse/SEC-1',now(),now())`,
			tenant, integration, finding, engagement); err != nil {
			t.Fatalf("insert completed durable ticket intent: %v", err)
		}
		rejectStatement(`DELETE FROM findings WHERE tenant_id=$1 AND id=$2`,
			"23503", "ticket_intents_finding_fk", tenant, finding)
		if _, err := tx.Exec(`DELETE FROM ticket_intents WHERE tenant_id=$1 AND id='ticket-migration-done'`, tenant); err != nil {
			t.Fatalf("clear durable ticket intent for mapping retention test: %v", err)
		}
		if _, err := tx.Exec(`INSERT INTO ticket_mappings
            (id,tenant_id,integration_id,engagement_id,project_key,issue_type,version,created_at,updated_at)
            VALUES ('ticket-migration-engagement-mapping',$1,$2,$3,'SEC','Bug',1,now(),now())`,
			tenant, integration, engagement); err != nil {
			t.Fatalf("seed retained engagement mapping: %v", err)
		}
		rejectStatement(`DELETE FROM engagements WHERE tenant_id=$1 AND id=$2`,
			"23503", "ticket_mappings_engagement_fk", tenant, engagement)
		if _, err := tx.Exec(`DELETE FROM ticket_mappings WHERE tenant_id=$1 AND id='ticket-migration-engagement-mapping'`, tenant); err != nil {
			t.Fatalf("clear retained engagement mapping: %v", err)
		}
	})
	withMigrationTenant(t, db, otherTenant, func(tx *sql.Tx) {
		if _, err := tx.Exec(`INSERT INTO ticket_mappings
            (id,tenant_id,integration_id,project_id,project_key,issue_type,version,created_at,updated_at)
            VALUES ('ticket-migration-other-mapping',$1,$2,$3,'OPS','Task',1,now(),now())`, otherTenant, otherIntegration, otherProject); err != nil {
			t.Fatalf("insert second tenant mapping: %v", err)
		}
	})

	if err := goose.DownTo(db, ".", 229); err == nil {
		t.Fatal("rollback with durable ticket data succeeded")
	}
	withMigrationTenant(t, db, tenant, func(tx *sql.Tx) {
		var count int
		if err := tx.QueryRow(`SELECT count(*) FROM ticket_mappings WHERE tenant_id=$1`, tenant).Scan(&count); err != nil || count != 1 {
			t.Fatalf("failed rollback changed durable ticket mapping count=%d err=%v", count, err)
		}
		if _, err := tx.Exec(`DELETE FROM ticket_mappings WHERE tenant_id=$1`, tenant); err != nil {
			t.Fatalf("clear first tenant mapping for reversible rollback: %v", err)
		}
	})
	withMigrationTenant(t, db, otherTenant, func(tx *sql.Tx) {
		var count int
		if err := tx.QueryRow(`SELECT count(*) FROM ticket_mappings WHERE tenant_id=$1`, otherTenant).Scan(&count); err != nil || count != 1 {
			t.Fatalf("failed rollback changed second tenant mapping count=%d err=%v", count, err)
		}
		if _, err := tx.Exec(`DELETE FROM ticket_mappings WHERE tenant_id=$1`, otherTenant); err != nil {
			t.Fatalf("clear second tenant mapping for reversible rollback: %v", err)
		}
	})
	if err := goose.DownTo(db, ".", 229); err != nil {
		t.Fatalf("rollback empty ticketing foundation: %v", err)
	}
	for _, table := range []string{"ticket_mappings", "ticket_links", "ticket_intents"} {
		requireMigrationTable(t, db, table, false)
	}
	if err := goose.UpTo(db, ".", 230); err != nil {
		t.Fatalf("reapply ticketing foundation: %v", err)
	}
	withMigrationTenant(t, db, tenant, func(tx *sql.Tx) {
		var count int
		if err := tx.QueryRow(`SELECT count(*) FROM projects WHERE tenant_id=$1 AND id=$2`, tenant, project).Scan(&count); err != nil || count != 1 {
			t.Fatalf("pre-ticketing project after reapply count=%d err=%v", count, err)
		}
	})
}

func TestMigration0230RollbackWaitsForConcurrentTicketData(t *testing.T) {
	isolate := newIsolatedMigrationDB(t, 230, 229)
	db := isolate.db
	if err := goose.UpTo(db, ".", 230); err != nil {
		t.Fatalf("apply ticketing foundation: %v", err)
	}
	const tenant = "ticket-rollback-race"
	const integration = "ticket-rollback-race-integration"
	const project = "ticket-rollback-race-project"
	if _, err := db.Exec(`INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatalf("seed rollback-race tenant: %v", err)
	}
	withMigrationTenant(t, db, tenant, func(tx *sql.Tx) {
		if _, err := tx.Exec(`INSERT INTO integrations(id,tenant_id,provider,display_name,endpoint,created_at,updated_at)
            VALUES($1,$2,'jenkins','Ticket rollback race','https://jenkins.example',now(),now())`, integration, tenant); err != nil {
			t.Fatalf("seed rollback-race integration: %v", err)
		}
		if _, err := tx.Exec(`INSERT INTO projects(id,tenant_id,name,key,source_binding)
            VALUES($1,$2,'Ticket rollback race','ticket-rollback-race','{}'::jsonb)`, project, tenant); err != nil {
			t.Fatalf("seed rollback-race project: %v", err)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	writer, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("reserve concurrent ticket writer: %v", err)
	}
	defer writer.Close()
	writerTx, err := writer.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin concurrent ticket writer: %v", err)
	}
	defer func() { _ = writerTx.Rollback() }()
	if _, err := writerTx.ExecContext(ctx, `SELECT set_config('app.current_tenant',$1,true)`, tenant); err != nil {
		t.Fatalf("scope concurrent ticket writer: %v", err)
	}
	if _, err := writerTx.ExecContext(ctx, `INSERT INTO ticket_mappings
        (id,tenant_id,integration_id,project_id,project_key,issue_type,version,created_at,updated_at)
        VALUES ('ticket-rollback-race-mapping',$1,$2,$3,'SEC','Bug',1,now(),now())`, tenant, integration, project); err != nil {
		t.Fatalf("record uncommitted ticket mapping: %v", err)
	}

	downResult := make(chan error, 1)
	go func() { downResult <- goose.DownTo(db, ".", 229) }()
	waitForMigration0230ExclusiveLock(t, ctx, db)
	if err := writerTx.Commit(); err != nil {
		t.Fatalf("commit concurrent ticket mapping: %v", err)
	}
	select {
	case err := <-downResult:
		if err == nil || !strings.Contains(err.Error(), "durable ticket data") {
			t.Fatalf("rollback error = %v, want durable-ticket-data refusal", err)
		}
	case <-ctx.Done():
		t.Fatalf("rollback did not finish after concurrent ticket mapping commit: %v", ctx.Err())
	}
	for _, table := range []string{"ticket_mappings", "ticket_links", "ticket_intents"} {
		requireMigrationRLS(t, db, table)
	}
	withMigrationTenant(t, db, tenant, func(tx *sql.Tx) {
		var count int
		if err := tx.QueryRow(`SELECT count(*) FROM ticket_mappings WHERE id='ticket-rollback-race-mapping'`).Scan(&count); err != nil || count != 1 {
			t.Fatalf("concurrent ticket mapping after rejected rollback count=%d err=%v", count, err)
		}
	})
}

func waitForMigration0230ExclusiveLock(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	const query = `SELECT EXISTS (
		SELECT 1 FROM pg_locks
		WHERE relation = 'ticket_mappings'::regclass
		  AND mode = 'AccessExclusiveLock'
		  AND NOT granted
	)`
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		if err := db.QueryRowContext(ctx, query).Scan(&waiting); err != nil {
			t.Fatalf("inspect ticketing migration lock request: %v", err)
		}
		if waiting {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("rollback never requested an exclusive ticket_mappings lock: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}
