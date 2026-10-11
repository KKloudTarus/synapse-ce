package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestIdentityRoutingDigestsUnderRuntimeRole(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	f.tenants(t, "org-a", "org-b")
	f.enableProjection(t, "org-a", now)
	f.enableProjection(t, "org-b", now)
	alice := f.createUser(t, "org-a", "alice", user.RoleAdmin, now)
	bob := f.createUser(t, "org-b", "bob", user.RoleConsultant, now)

	route, err := f.store.RouteCredentialDigest(ctx, alice)
	if err != nil || route.TenantID != "org-a" || route.Kind != ports.IdentityCredentialAPIKey {
		t.Fatalf("alice route = %+v, %v", route, err)
	}
	if route, err := f.store.RouteCredentialDigest(ctx, bob); err != nil || route.TenantID != "org-b" {
		t.Fatalf("bob route = %+v, %v", route, err)
	}
	for name, digest := range map[string]string{
		"random":    identityDigest(identityRandomHex(t, 16)),
		"prefix":    alice[:10],
		"wildcard":  "%",
		"uppercase": "A" + alice[1:],
		"empty":     "",
	} {
		if _, err := f.store.RouteCredentialDigest(ctx, digest); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("%s digest routed: %v", name, err)
		}
	}

	// Stale: rotation moves routing to the new digest atomically and the old one routes nowhere.
	fresh := identityDigest("rotated-" + identityRandomHex(t, 8))
	if err := f.updateUser(t, "org-a", "alice", "user.api_key_rotated", func(u *user.User) { u.APIKeyHash = fresh }); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.RouteCredentialDigest(ctx, alice); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("stale digest still routes: %v", err)
	}
	if route, err := f.store.RouteCredentialDigest(ctx, fresh); err != nil || route.TenantID != "org-a" {
		t.Fatalf("rotated digest route = %+v, %v", route, err)
	}

	// Cross-tenant: a digest routed to org-b reads nothing when bound to org-a.
	if n := f.runtimeCount(t, "org-a", `SELECT count(*) FROM identity_credentials WHERE digest=$1`, bob); n != 0 {
		t.Fatalf("org-a sees org-b credential rows: %d", n)
	}
	if n := f.runtimeCount(t, "org-b", `SELECT count(*) FROM identity_credentials WHERE digest=$1`, bob); n != 1 {
		t.Fatalf("org-b credential rows = %d", n)
	}

	// The runtime role cannot read the global routing tables or persons directly, even bound.
	for _, table := range []string{"identity_credential_digests", "identity_persons", "identity_person_audit", "identity_person_membership_index"} {
		err := WithTenant(ctx, f.runtime, "org-a", func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `SELECT 1 FROM `+table+` LIMIT 1`)
			return err
		})
		if err == nil {
			t.Fatalf("runtime role reads %s directly", table)
		}
	}
	// Without a bound tenant, tenant-owned identity rows are invisible.
	var unbound int
	if err := f.runtime.QueryRow(ctx, `SELECT count(*) FROM identity_credentials`).Scan(&unbound); err != nil || unbound != 0 {
		t.Fatalf("unbound credential read = %d, %v", unbound, err)
	}
}

func TestIdentityRuntimeRoleMayOnlyCreatePersons(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	f.tenants(t, "org-a")
	f.enableProjection(t, "org-a", now)
	f.createUser(t, "org-a", "alice", user.RoleAdmin, now)
	alice := f.membershipOf(t, "org-a", "alice")

	// The legacy projection created the person through the create-only function, which fixes the
	// audit actor.
	var actor string
	if err := f.admin.QueryRow(ctx, `SELECT actor FROM identity_person_audit WHERE person_id=$1 AND action='person.created'`, alice.PersonID.String()).Scan(&actor); err != nil || actor != identityProjectionActor {
		t.Fatalf("projected person audit actor = %q, %v", actor, err)
	}
	// Every state-changing command, and a create with an actor of the caller's choosing, is refused
	// to the runtime role.
	for _, action := range []ports.IdentityPersonAction{ports.IdentityPersonSuspended, ports.IdentityPersonReactivated, ports.IdentityPersonSessionsRevoked, ports.IdentityPersonCreated} {
		_, err := f.store.ApplyPersonCommand(ctx, alice.PersonID, action, "forged-actor", "runtime attempt")
		requireSQLState(t, err, "42501")
	}
	err := WithTenant(ctx, f.runtime, "org-a", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT * FROM synapse_identity_person_command($1, 'person.suspended', 'forged-actor', '')`, alice.PersonID.String())
		return err
	})
	requireSQLState(t, err, "42501")
	if n := f.adminCount(t, `SELECT count(*) FROM identity_person_audit WHERE actor='forged-actor'`); n != 0 {
		t.Fatalf("runtime role wrote %d forged person audit rows", n)
	}
	if n := f.adminCount(t, `SELECT count(*) FROM identity_persons WHERE id=$1 AND state='active' AND epoch=1`, alice.PersonID.String()); n != 1 {
		t.Fatal("runtime role changed the person")
	}
	// The create-only function is idempotent for the runtime role and writes no second audit row.
	err = WithTenant(ctx, f.runtime, "org-a", func(tx pgx.Tx) error {
		return createLegacyPerson(ctx, tx, alice.PersonID, "retry")
	})
	if err != nil {
		t.Fatalf("runtime create-only retry: %v", err)
	}
	if n := f.adminCount(t, `SELECT count(*) FROM identity_person_audit WHERE person_id=$1`, alice.PersonID.String()); n != 1 {
		t.Fatalf("person audit rows after retry = %d, want 1", n)
	}
	// A platform operator connected as the owner still runs the general command.
	if _, err := f.platform.ApplyPersonCommand(ctx, alice.PersonID, ports.IdentityPersonSessionsRevoked, "platform-admin", "operator"); err != nil {
		t.Fatalf("owner person command: %v", err)
	}
}
