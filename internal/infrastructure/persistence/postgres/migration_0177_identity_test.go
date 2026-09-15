package postgres

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/orgidentity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestMigration0177IdentityRLSInventory(t *testing.T) {
	_, db := ownershipTestDatabase(t, 0, nil)

	tenantTables := []string{"memberships", "sso_connections", "sso_connection_revisions", "authentication_identities", "identity_fanout_obligations"}
	for _, table := range tenantTables {
		requireMigrationTable(t, db, table, true)
		requireMigrationRLS(t, db, table)
	}
	globalTables := []string{"persons", "person_organization_index", "credential_index", "platform_identity_audit"}
	for _, table := range globalTables {
		requireMigrationTable(t, db, table, true)
		var enabled, forced bool
		if err := db.QueryRow(`SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid=$1::regclass`, table).Scan(&enabled, &forced); err != nil {
			t.Fatalf("inspect global identity table %s: %v", table, err)
		}
		if enabled || forced {
			t.Fatalf("global identity exception %s unexpectedly uses tenant RLS; keep it privileged and exact-surface instead", table)
		}
	}
}

// This compile/static surface guard is intentionally boring: if someone later adds List, Prefix,
// Email, Subject or tenant discovery to the raw credential resolver port, the test forces an
// explicit security review rather than silently broadening pre-authentication enumeration.
func TestCredentialLocatorResolverPortIsExactOnly(t *testing.T) {
	typ := reflect.TypeOf((*ports.CredentialLocatorResolver)(nil)).Elem()
	if typ.NumMethod() != 1 {
		t.Fatalf("raw credential resolver has %d methods; want exact-hash resolution only", typ.NumMethod())
	}
	method := typ.Method(0)
	if method.Name != "ResolveExactHash" {
		t.Fatalf("raw credential resolver method = %s, want ResolveExactHash", method.Name)
	}
}

func seedIdentityTenant(t *testing.T, db *sql.DB, tenant, person, membership string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO tenants(id,name) VALUES($1,$2) ON CONFLICT(id) DO NOTHING`, tenant, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO persons(id,display_name,status,credential_epoch,version,created_at,updated_at)
		VALUES($1,$2,'active',1,1,now(),now())`, person, person); err != nil {
		t.Fatal(err)
	}
	withMigrationTenant(t, db, tenant, func(tx *sql.Tx) {
		if _, err := tx.Exec(`INSERT INTO memberships(tenant_id,id,person_id,role,status,epoch,version,created_at,updated_at)
			VALUES($1,$2,$3,'admin','active',1,1,now(),now())`, tenant, membership, person); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`INSERT INTO person_organization_index(person_id,tenant_id) VALUES($1,$2)`, person, tenant); err != nil {
			t.Fatal(err)
		}
	})
}

func TestIdentityRuntimeRLSAndCompositeOwnership(t *testing.T) {
	pool, db := ownershipTestDatabase(t, 0, nil)
	seedIdentityTenant(t, db, "identity-a", "person-a", "membership-a")
	seedIdentityTenant(t, db, "identity-b", "person-b", "membership-b")

	withMigrationTenant(t, db, "identity-a", func(tx *sql.Tx) {
		if _, err := tx.Exec(`INSERT INTO sso_connections(tenant_id,id,protocol,trust_identifier,enabled,connection_epoch,version,created_at,updated_at)
			VALUES('identity-a','conn-a','oidc','https://issuer-a.example',true,1,1,now(),now())`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`INSERT INTO sso_connection_revisions(tenant_id,connection_id,revision,protocol,configuration,encrypted_secret_ref,test_status,test_result,created_by,created_at,tested_at)
			VALUES('identity-a','conn-a',1,'oidc','{}','','passed','{}','bootstrap',now(),now())`); err != nil {
			t.Fatal(err)
		}
	})

	var seen int
	if err := WithTenant(context.Background(), pool, "identity-a", func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT count(*) FROM memberships`).Scan(&seen)
	}); err != nil {
		t.Fatal(err)
	}
	if seen != 1 {
		t.Fatalf("tenant A runtime sees %d memberships, want exactly its own one", seen)
	}

	// No tenant binding is fail-closed for the runtime role.
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM memberships`).Scan(&seen); err != nil {
		t.Fatal(err)
	}
	if seen != 0 {
		t.Fatalf("unbound runtime sees %d membership rows, want 0", seen)
	}

	// A tenant-A identity cannot point at a tenant-B membership even though person/membership ids
	// are globally knowable to the migration owner. RLS plus the composite FK rejects it in DB.
	err := WithTenant(context.Background(), pool, "identity-a", func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `INSERT INTO authentication_identities
			(tenant_id,id,membership_id,person_id,connection_id,protocol_subject,creation_revision,created_at)
			VALUES('identity-a','bad-link','membership-b','person-b','conn-a','subject-b',1,now())`)
		return err
	})
	if err == nil {
		t.Fatal("foreign membership was attached to authentication identity")
	}
}

func TestCredentialLocatorExactHashAndCrossTenantShape(t *testing.T) {
	pool, db := ownershipTestDatabase(t, 0, nil)
	for _, tenant := range []string{"locator-a", "locator-b"} {
		if _, err := db.Exec(`INSERT INTO tenants(id,name) VALUES($1,$2) ON CONFLICT(id) DO NOTHING`, tenant, tenant); err != nil {
			t.Fatal(err)
		}
	}
	digestA := strings.Repeat("a", 64)
	digestB := strings.Repeat("b", 64)
	if _, err := db.Exec(`INSERT INTO credential_index(digest,organization_id,credential_kind,credential_id) VALUES
		($1,'locator-a','browser_session','session-a'),($2,'locator-b','invitation','invite-b')`, digestA, digestB); err != nil {
		t.Fatal(err)
	}
	resolver, err := NewCredentialLocator(pool)
	if err != nil {
		t.Fatal(err)
	}

	got, err := resolver.ResolveExactHash(context.Background(), digestA)
	if err != nil {
		t.Fatal(err)
	}
	if got.OrganizationID != shared.ID("locator-a") || got.Kind != orgidentity.CredentialBrowserSession || got.CredentialID != shared.ID("session-a") {
		t.Fatalf("locator A = %+v", got)
	}
	if _, err := resolver.ResolveExactHash(context.Background(), strings.Repeat("c", 64)); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("random digest error = %v, want not found", err)
	}
	if _, err := resolver.ResolveExactHash(context.Background(), digestB); err != nil {
		t.Fatalf("another organization's exact digest must route without leaking anything beyond locator: %v", err)
	}
}

func TestIdentityConnectionRevisionAndFanoutEvidenceImmutable(t *testing.T) {
	_, db := ownershipTestDatabase(t, 0, nil)
	seedIdentityTenant(t, db, "immut-a", "immut-person", "immut-membership")
	withMigrationTenant(t, db, "immut-a", func(tx *sql.Tx) {
		if _, err := tx.Exec(`INSERT INTO sso_connections(tenant_id,id,protocol,trust_identifier,enabled,connection_epoch,version,created_at,updated_at)
			VALUES('immut-a','conn','oidc','https://issuer.example',true,1,1,now(),now())`); err != nil { t.Fatal(err) }
		if _, err := tx.Exec(`INSERT INTO sso_connection_revisions(tenant_id,connection_id,revision,protocol,configuration,encrypted_secret_ref,test_status,test_result,created_by,created_at,tested_at)
			VALUES('immut-a','conn',1,'oidc','{}','','passed','{}','actor',now(),now())`); err != nil { t.Fatal(err) }
		requireMigrationWriteRejected(t, tx, `UPDATE sso_connection_revisions SET created_by='rewritten' WHERE tenant_id='immut-a' AND connection_id='conn' AND revision=1`)
	})

	if _, err := db.Exec(`INSERT INTO platform_identity_audit(id,actor,action,target_person_id,previous_hash,hash,metadata,created_at)
		VALUES('audit-1','operator','person.suspend','immut-person','',$1,'{}',now())`, strings.Repeat("d", 64)); err != nil {
		t.Fatal(err)
	}
	withMigrationTenant(t, db, "immut-a", func(tx *sql.Tx) {
		if _, err := tx.Exec(`INSERT INTO identity_fanout_obligations(tenant_id,id,person_id,audit_id,idempotency_key,payload,state,created_at)
			VALUES('immut-a','fanout-1','immut-person','audit-1','person.suspend:immut-person:1','{}','pending',now())`); err != nil { t.Fatal(err) }
		requireMigrationWriteRejected(t, tx, `UPDATE identity_fanout_obligations SET payload='{"tampered":true}' WHERE tenant_id='immut-a' AND id='fanout-1'`)
		completed := time.Now().UTC()
		if _, err := tx.Exec(`UPDATE identity_fanout_obligations SET state='completed',completed_at=$1 WHERE tenant_id='immut-a' AND id='fanout-1'`, completed); err != nil {
			t.Fatalf("legal pending->completed transition failed: %v", err)
		}
	})
}
