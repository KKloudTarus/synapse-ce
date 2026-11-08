package postgres

import (
	"context"
	"database/sql"
	"testing"

	"github.com/pressly/goose/v3"
)

func TestTicketWorkflowMigrationRollbackPreservesTenantPolicy(t *testing.T) {
	isolated := newIsolatedMigrationDB(t, 237, 235)
	if err := Migrate(context.Background(), isolated.dsn); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownTo(isolated.db, ".", 235); err != nil {
		t.Fatalf("empty rollback: %v", err)
	}
	if err := goose.UpTo(isolated.db, ".", 237); err != nil {
		t.Fatalf("reapply: %v", err)
	}
	if _, err := isolated.db.Exec(`INSERT INTO tenants(id,name) VALUES('workflow-owner','Workflow owner'),('workflow-other','Other tenant')`); err != nil {
		t.Fatal(err)
	}
	withMigrationTenant(t, isolated.db, "workflow-other", func(tx *sql.Tx) {
		statements := []string{
			`INSERT INTO integrations(id,tenant_id,provider,display_name,endpoint,created_at,updated_at) VALUES('workflow-jira','workflow-other','jira-cloud','Jira','https://example.atlassian.net',now(),now())`,
			`INSERT INTO engagements(id,tenant_id,name) VALUES('workflow-eng','workflow-other','Assessment')`,
			`INSERT INTO ticket_mappings(id,tenant_id,integration_id,engagement_id,project_key,issue_type,version,created_at,updated_at,locale,waiver_reason) VALUES('workflow-map','workflow-other','workflow-jira','workflow-eng','SEC','10001',1,now(),now(),'vi','admin approved exception')`,
		}
		for _, statement := range statements {
			if _, err := tx.Exec(statement); err != nil {
				t.Fatal(err)
			}
		}
	})
	// No current-tenant setting: the non-superuser migration owner must still
	// detect policy data belonging to a different tenant before dropping it.
	if err := goose.DownTo(isolated.db, ".", 235); err == nil {
		t.Fatal("rollback erased retained policy")
	}
	withMigrationTenant(t, isolated.db, "workflow-other", func(tx *sql.Tx) {
		var locale, reason string
		if err := tx.QueryRow(`SELECT locale,waiver_reason FROM ticket_mappings WHERE id='workflow-map'`).Scan(&locale, &reason); err != nil || locale != "vi" || reason != "admin approved exception" {
			t.Fatalf("retained mapping %q %q: %v", locale, reason, err)
		}
	})
	for _, table := range []string{"ticket_mappings", "ticket_intents", "ticket_dispatch_breakers"} {
		var forced bool
		if err := isolated.db.QueryRow(`SELECT relforcerowsecurity FROM pg_class WHERE oid=$1::regclass`, table).Scan(&forced); err != nil || !forced {
			t.Fatalf("RLS after refused rollback %s: %t %v", table, forced, err)
		}
	}
}
