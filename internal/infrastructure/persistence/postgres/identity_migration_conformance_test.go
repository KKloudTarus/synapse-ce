package postgres

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
)

const identityMigrationCurrent = 218

func TestIdentityMigrationsForwardEmptyDownForward(t *testing.T) {
	isolated := newIsolatedMigrationDB(t, identityMigrationCurrent, 206)
	db := isolated.db
	if err := goose.UpTo(db, ".", identityMigrationCurrent); err != nil {
		t.Fatalf("migrate identity additions forward: %v", err)
	}
	requireIdentityMigrationReadiness(t, db)
	if err := goose.DownTo(db, ".", 206); err != nil {
		t.Fatalf("migrate empty identity additions down: %v", err)
	}
	for _, table := range []string{
		"identity_session_switch_retries",
		"identity_cutover_ledger",
		"identity_connection_tests",
		"identity_invitation_challenges",
		"identity_invitation_code_routes",
	} {
		requireMigrationTable(t, db, table, false)
	}
	if err := goose.UpTo(db, ".", identityMigrationCurrent); err != nil {
		t.Fatalf("migrate identity additions forward after empty rollback: %v", err)
	}
	requireIdentityMigrationReadiness(t, db)
}

func TestIdentityMigration0218BackfillsExistingRetryRoute(t *testing.T) {
	isolation := newIsolatedMigrationDB(t, identityMigrationCurrent, 217)
	seedMigrationAcceptedInvitation(t, isolation)
	const (
		tenant      = "migration-retry"
		retryKey    = "existing-retry"
		payloadHash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		sourceHash  = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	)
	withMigrationTenant(t, isolation.db, tenant, func(tx *sql.Tx) {
		if _, err := tx.Exec(`INSERT INTO identity_session_switch_retries(tenant_id,retry_key,payload_hash,source_credential_id,source_digest,destination_tenant_id,destination_session_id,response_ciphertext,expires_at)
			VALUES($1,$2,$3,'credential',$4,$1,'session','ciphertext',now()+interval '1 minute')`, tenant, retryKey, payloadHash, sourceHash); err != nil {
			t.Fatal(err)
		}
	})
	if err := goose.UpTo(isolation.db, ".", identityMigrationCurrent); err != nil {
		t.Fatalf("upgrade populated retry route: %v", err)
	}
	var destination string
	if err := isolation.db.QueryRow(`SELECT synapse_identity_switch_retry_destination_tenant($1,$2,$3)`, sourceHash, retryKey, payloadHash).Scan(&destination); err != nil {
		t.Fatalf("read upgraded retry destination: %v", err)
	}
	if destination != tenant {
		t.Fatalf("upgraded retry destination=%q, want %q", destination, tenant)
	}
	requireMigrationRLS(t, isolation.db, "identity_session_switch_retries")
	requireMigrationRLS(t, isolation.db, "identity_session_switch_retry_routes")
}

func TestIdentityMigrationDownRefusesPopulatedEvidence(t *testing.T) {
	t.Run("accepted invitation retry", func(t *testing.T) {
		isolated := newIsolatedMigrationDB(t, identityMigrationCurrent, identityMigrationCurrent)
		seedMigrationAcceptedInvitation(t, isolated)
		err := goose.DownTo(isolated.db, ".", 216)
		if err == nil || !strings.Contains(err.Error(), "populated invitation retry evidence") {
			t.Fatalf("down with accepted invitation retry = %v, want refusal", err)
		}
		requireIdentityMigrationVersion(t, isolated.db, 217)
		requireMigrationRLS(t, isolated.db, "identity_invitations")
	})

	t.Run("admission evidence", func(t *testing.T) {
		isolated := newIsolatedMigrationDB(t, identityMigrationCurrent, identityMigrationCurrent)
		seedMigrationAdmissionEvidence(t, isolated)
		err := goose.DownTo(isolated.db, ".", 211)
		if err == nil || !strings.Contains(err.Error(), "identity admission evidence requires a forward fix") {
			t.Fatalf("down with admission evidence = %v, want refusal", err)
		}
		requireIdentityMigrationVersion(t, isolated.db, 212)
		requireMigrationRLS(t, isolated.db, "identity_transactions")
		requireMigrationRLS(t, isolated.db, "identity_invitation_challenges")
	})

	t.Run("declared cutover", func(t *testing.T) {
		isolated := newIsolatedMigrationDB(t, identityMigrationCurrent, identityMigrationCurrent)
		seedMigrationDeclaredCutover(t, isolated)
		err := goose.DownTo(isolated.db, ".", 212)
		if err == nil || !strings.Contains(err.Error(), "writer fence rollback refused") {
			t.Fatalf("down with declared cutover = %v, want refusal", err)
		}
		requireIdentityMigrationVersion(t, isolated.db, 213)
		requireMigrationRLS(t, isolated.db, "identity_cutover_ledger")
	})
}

func requireIdentityMigrationReadiness(t *testing.T, db *sql.DB) {
	t.Helper()
	var tables int
	if err := db.QueryRow(`SELECT count(*) FROM pg_class WHERE relname IN (
		'identity_sessions', 'identity_session_switch_retries', 'identity_cutover_ledger',
		'identity_connection_tests', 'identity_invitation_challenges', 'identity_invitation_code_routes'
	) AND relkind='r'`).Scan(&tables); err != nil {
		t.Fatalf("inspect identity migration tables: %v", err)
	}
	if tables != 6 {
		t.Fatalf("identity migration tables=%d, want 6", tables)
	}
	var functions int
	if err := db.QueryRow(`SELECT count(*) FROM pg_proc WHERE proname IN (
		'synapse_identity_usable_admin_access',
		'synapse_identity_invitation_tenant',
		'synapse_identity_admission_source',
		'synapse_identity_revoke_admission_source'
	)`).Scan(&functions); err != nil {
		t.Fatalf("inspect identity migration functions: %v", err)
	}
	if functions != 4 {
		t.Fatalf("identity migration functions=%d, want 4", functions)
	}
	var destinationLocator int
	if err := db.QueryRow(`SELECT count(*) FROM pg_proc WHERE proname='synapse_identity_switch_retry_destination_tenant'`).Scan(&destinationLocator); err != nil {
		t.Fatalf("inspect switch retry destination locator: %v", err)
	}
	if destinationLocator != 1 {
		t.Fatalf("switch retry destination locator=%d, want 1", destinationLocator)
	}
	requireIdentityMigrationVersion(t, db, identityMigrationCurrent)
}

func requireIdentityMigrationVersion(t *testing.T, db *sql.DB, want int64) {
	t.Helper()
	version, err := goose.GetDBVersion(db)
	if err != nil {
		t.Fatalf("read migration version: %v", err)
	}
	if version != want {
		t.Fatalf("migration version=%d, want %d", version, want)
	}
}

func seedMigrationAdmissionEvidence(t *testing.T, isolated isolatedMigrationDB) {
	t.Helper()
	const tenant = "migration-admission"
	if _, err := isolated.db.Exec(`INSERT INTO tenants(id,name) VALUES($1,'Migration admission')`, tenant); err != nil {
		t.Fatal(err)
	}
	withMigrationTenant(t, isolated.db, tenant, func(tx *sql.Tx) {
		if _, err := tx.Exec(`INSERT INTO identity_invitations(tenant_id,id,code_digest,recipient,role,created_by,expires_at)
			VALUES($1,'admission-invitation',repeat('a',64),'migration@example.test','member','migration',now()+interval '1 hour')`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`INSERT INTO identity_invitation_challenges(tenant_id,invitation_id,invitation_version,subject,prospective_person_id,challenge_digest,expires_at)
			VALUES($1,'admission-invitation',1,'subject','prospective-person',repeat('b',64),now()+interval '10 minutes')`, tenant); err != nil {
			t.Fatal(err)
		}
	})
}

func seedMigrationDeclaredCutover(t *testing.T, isolated isolatedMigrationDB) {
	t.Helper()
	const tenant = "migration-cutover"
	if _, err := isolated.db.Exec(`INSERT INTO tenants(id,name) VALUES($1,'Migration cutover')`, tenant); err != nil {
		t.Fatal(err)
	}
	withMigrationTenant(t, isolated.db, tenant, func(tx *sql.Tx) {
		if _, err := tx.Exec(`INSERT INTO identity_policies(tenant_id,id) VALUES($1,'policy')`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`INSERT INTO identity_cutover_ledger(tenant_id,action,actor,policy_version,created_at)
			VALUES($1,'declared','migration',1,now())`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`UPDATE identity_policies SET cutover_phase='shadow' WHERE tenant_id=$1`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`UPDATE identity_policies SET cutover_phase='declared' WHERE tenant_id=$1`, tenant); err != nil {
			t.Fatal(err)
		}
	})
}

func seedMigrationAcceptedInvitation(t *testing.T, isolated isolatedMigrationDB) {
	t.Helper()
	const tenant = "migration-retry"
	if _, err := isolated.db.Exec(`INSERT INTO tenants(id,name) VALUES($1,'Migration retry')`, tenant); err != nil {
		t.Fatal(err)
	}
	withMigrationTenant(t, isolated.db, tenant, func(tx *sql.Tx) {
		if _, err := tx.Exec(`INSERT INTO identity_policies(tenant_id,id) VALUES($1,'policy')`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`INSERT INTO identity_cutover_ledger(tenant_id,action,actor,policy_version,created_at)
			VALUES($1,'declared','migration',1,now())`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`UPDATE identity_policies SET cutover_phase='shadow' WHERE tenant_id=$1`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`UPDATE identity_policies SET cutover_phase='declared' WHERE tenant_id=$1`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`INSERT INTO identity_persons(id) VALUES('migration-person')`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`INSERT INTO identity_connections(tenant_id,id,protocol,trust_namespace,display_name,enabled)
			VALUES($1,'connection','oidc','https://migration.example.test','Migration',true)`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`INSERT INTO identity_connection_revisions(tenant_id,connection_id,revision,settings,actor)
			VALUES($1,'connection',1,'{}','migration')`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`INSERT INTO identity_memberships(tenant_id,id,person_id,role)
			VALUES($1,'membership','migration-person','member')`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`INSERT INTO identity_credentials(tenant_id,id,kind,digest,membership_id,person_id,source)
			VALUES($1,'credential','browser_session',repeat('c',64),'membership','migration-person','native')`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`INSERT INTO identity_sessions(tenant_id,id,credential_id,membership_id,person_id,connection_id,lineage_id,
			authenticated_at,origin_at,expires_at,person_epoch,membership_epoch,connection_epoch)
			VALUES($1,'session','credential','membership','migration-person','connection','lineage',now()-interval '1 minute',now()-interval '1 minute',now()+interval '1 hour',1,1,1)`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`INSERT INTO identity_invitations(tenant_id,id,code_digest,recipient,role,state,created_by,expires_at,accepted_membership_id,accepted_person_id,accepted_session_id,accepted_payload_hash)
			VALUES($1,'invitation',repeat('d',64),'migration@example.test','member','accepted','migration',now()+interval '1 hour','membership','migration-person','session',repeat('e',64))`, tenant); err != nil {
			t.Fatal(err)
		}
	})
}
