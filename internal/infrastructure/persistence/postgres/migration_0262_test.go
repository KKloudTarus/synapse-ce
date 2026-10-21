package postgres

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
)

func TestMigration0262DocumentRemoteRevisionUpgradeRollbackAndReapply(t *testing.T) {
	isolate := newIsolatedMigrationDB(t, 262, 261)
	db := isolate.db
	const tenant = "migration-0262"
	const otherTenant = "migration-0262-other"

	seedDocumentRemoteRevisionLegacyRows(t, db, tenant)
	seedDocumentRemoteRevisionLegacyRows(t, db, otherTenant)

	if err := goose.UpTo(db, ".", 262); err != nil {
		t.Fatalf("upgrade document remote revisions: %v", err)
	}
	for _, table := range []string{"document_links", "document_intents"} {
		requireMigrationColumn(t, db, table, "remote_revision")
		requireMigrationRLS(t, db, table)
	}

	withMigrationTenant(t, db, tenant, func(tx *sql.Tx) {
		assertDocumentRemoteRevisionRow(t, tx, tenant, "", "", 17, 23)
		if _, err := tx.Exec(`UPDATE document_links SET remote_revision=$1 WHERE tenant_id=$2`, "etag:tenant-link", tenant); err != nil {
			t.Fatalf("persist link opaque remote revision: %v", err)
		}
		if _, err := tx.Exec(`UPDATE document_intents SET remote_revision=$1 WHERE tenant_id=$2`, "version:tenant-intent", tenant); err != nil {
			t.Fatalf("persist intent opaque remote revision: %v", err)
		}
		assertDocumentRemoteRevisionRow(t, tx, tenant, "etag:tenant-link", "version:tenant-intent", 17, 23)
	})
	withMigrationTenant(t, db, otherTenant, func(tx *sql.Tx) {
		if _, err := tx.Exec(`UPDATE document_links SET remote_revision=$1 WHERE tenant_id=$2`, "etag:other-tenant", otherTenant); err != nil {
			t.Fatalf("persist other tenant opaque remote revision: %v", err)
		}
		assertDocumentRemoteRevisionRow(t, tx, otherTenant, "etag:other-tenant", "", 17, 23)
	})

	// The rollback guard must inspect every tenant. Clearing the current tenant's
	// values leaves only the other tenant's opaque token to block the rollback.
	withMigrationTenant(t, db, tenant, func(tx *sql.Tx) {
		if _, err := tx.Exec(`UPDATE document_links SET remote_revision='' WHERE tenant_id=$1`, tenant); err != nil {
			t.Fatalf("clear current tenant link opaque remote revision: %v", err)
		}
		if _, err := tx.Exec(`UPDATE document_intents SET remote_revision='' WHERE tenant_id=$1`, tenant); err != nil {
			t.Fatalf("clear current tenant intent opaque remote revision: %v", err)
		}
	})
	if err := goose.DownTo(db, ".", 261); err == nil || !strings.Contains(err.Error(), "opaque revision data exists") {
		t.Fatalf("rollback with another tenant opaque remote revision err=%v", err)
	}
	for _, table := range []string{"document_links", "document_intents"} {
		requireMigrationColumn(t, db, table, "remote_revision")
		requireMigrationRLS(t, db, table)
	}
	withMigrationTenant(t, db, tenant, func(tx *sql.Tx) {
		assertDocumentRemoteRevisionRow(t, tx, tenant, "", "", 17, 23)
	})
	withMigrationTenant(t, db, otherTenant, func(tx *sql.Tx) {
		assertDocumentRemoteRevisionRow(t, tx, otherTenant, "etag:other-tenant", "", 17, 23)
		if _, err := tx.Exec(`UPDATE document_links SET remote_revision='' WHERE tenant_id=$1`, otherTenant); err != nil {
			t.Fatalf("clear other tenant opaque remote revision: %v", err)
		}
	})

	if err := goose.DownTo(db, ".", 261); err != nil {
		t.Fatalf("rollback empty document remote revisions: %v", err)
	}
	if err := goose.UpTo(db, ".", 262); err != nil {
		t.Fatalf("reapply document remote revisions: %v", err)
	}
	for _, table := range []string{"document_links", "document_intents"} {
		requireMigrationColumn(t, db, table, "remote_revision")
		requireMigrationRLS(t, db, table)
	}
	withMigrationTenant(t, db, tenant, func(tx *sql.Tx) {
		assertDocumentRemoteRevisionRow(t, tx, tenant, "", "", 17, 23)
	})
	withMigrationTenant(t, db, otherTenant, func(tx *sql.Tx) {
		assertDocumentRemoteRevisionRow(t, tx, otherTenant, "", "", 17, 23)
	})
}

func seedDocumentRemoteRevisionLegacyRows(t *testing.T, db *sql.DB, tenant string) {
	t.Helper()
	engagement := tenant + "-engagement"
	integration := tenant + "-integration"
	if _, err := db.Exec(`INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatalf("seed %s tenant: %v", tenant, err)
	}
	withMigrationTenant(t, db, tenant, func(tx *sql.Tx) {
		if _, err := tx.Exec(`INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'Document remote revision migration engagement')`, engagement, tenant); err != nil {
			t.Fatalf("seed %s engagement: %v", tenant, err)
		}
		if _, err := tx.Exec(`INSERT INTO integrations(id,tenant_id,provider,display_name,endpoint,created_at,updated_at)
            VALUES($1,$2,'confluence-cloud','Document remote revision migration integration','https://wiki.example',now(),now())`, integration, tenant); err != nil {
			t.Fatalf("seed %s integration: %v", tenant, err)
		}
		if _, err := tx.Exec(`INSERT INTO document_links
            (id,tenant_id,integration_id,source_kind,source_ref,engagement_id,container,remote_page_id,remote_version,remote_url,content_hash,revision,created_at,updated_at)
            VALUES($1,$2,$3,'engagement_report','legacy-link',$4,'SEC','legacy-page',17,'https://wiki.example/legacy',repeat('a',64),4,now(),now())`,
			tenant+"-link", tenant, integration, engagement); err != nil {
			t.Fatalf("seed %s legacy document link: %v", tenant, err)
		}
		if _, err := tx.Exec(`INSERT INTO document_intents
            (id,tenant_id,integration_id,source_kind,source_ref,engagement_id,container,action,request_key,payload_digest,content_hash,correlation_marker,state,remote_id,remote_url,remote_version,created_at,updated_at)
            VALUES($1,$2,$3,'engagement_report','legacy-intent',$4,'SEC','create',$5,repeat('a',64),repeat('b',64),$6,'done','legacy-page','https://wiki.example/legacy',23,now(),now())`,
			tenant+"-intent", tenant, integration, engagement, tenant+"-request", "synapse-intent-"+tenant+"-intent"); err != nil {
			t.Fatalf("seed %s legacy document intent: %v", tenant, err)
		}
	})
}

func assertDocumentRemoteRevisionRow(t *testing.T, tx *sql.Tx, tenant, wantLinkRevision, wantIntentRevision string, wantLinkVersion, wantIntentVersion int) {
	t.Helper()
	var linkVersion int
	var linkRevision string
	if err := tx.QueryRow(`SELECT remote_version,remote_revision FROM document_links WHERE tenant_id=$1`, tenant).Scan(&linkVersion, &linkRevision); err != nil {
		t.Fatalf("read %s document link revisions: %v", tenant, err)
	}
	if linkVersion != wantLinkVersion || linkRevision != wantLinkRevision {
		t.Fatalf("%s document link versions=(%d,%q), want (%d,%q)", tenant, linkVersion, linkRevision, wantLinkVersion, wantLinkRevision)
	}
	var intentVersion int
	var intentRevision string
	if err := tx.QueryRow(`SELECT remote_version,remote_revision FROM document_intents WHERE tenant_id=$1`, tenant).Scan(&intentVersion, &intentRevision); err != nil {
		t.Fatalf("read %s document intent revisions: %v", tenant, err)
	}
	if intentVersion != wantIntentVersion || intentRevision != wantIntentRevision {
		t.Fatalf("%s document intent versions=(%d,%q), want (%d,%q)", tenant, intentVersion, intentRevision, wantIntentVersion, wantIntentRevision)
	}
}
