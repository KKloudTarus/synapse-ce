package postgres

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func (f *identityFixture) membershipOf(t *testing.T, tenant, legacyUserID string) ports.IdentityMembership {
	t.Helper()
	var id string
	if err := f.admin.QueryRow(context.Background(), `SELECT id FROM identity_memberships WHERE tenant_id=$1 AND legacy_user_id=$2`, tenant, legacyUserID).Scan(&id); err != nil {
		t.Fatalf("membership of %s/%s: %v", tenant, legacyUserID, err)
	}
	m, err := f.store.GetMembership(context.Background(), shared.ID(tenant), shared.ID(id))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func (f *identityFixture) newPerson(t *testing.T, id string) shared.ID {
	t.Helper()
	if _, err := f.platform.ApplyPersonCommand(context.Background(), shared.ID(id), ports.IdentityPersonCreated, "platform-admin", "test"); err != nil {
		t.Fatal(err)
	}
	return shared.ID(id)
}

func requireSQLState(t *testing.T, err error, code string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != code {
		t.Fatalf("want SQLSTATE %s, got %v", code, err)
	}
}

func (f *identityFixture) runtimeExec(tenant, sql string, args ...any) error {
	return WithTenant(context.Background(), f.runtime, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), sql, args...)
		return err
	})
}

func TestIdentityWrongPersonAndWrongTenantReferencesRejected(t *testing.T) {
	f := newIdentityFixture(t)
	now := time.Now().UTC()
	f.tenants(t, "org-a", "org-b")
	f.enableProjection(t, "org-a", now)
	f.enableProjection(t, "org-b", now)
	f.createUser(t, "org-a", "alice", user.RoleAdmin, now)
	f.createUser(t, "org-a", "carol", user.RoleMember, now)
	f.createUser(t, "org-b", "bob", user.RoleMember, now)
	alice, carol, bob := f.membershipOf(t, "org-a", "alice"), f.membershipOf(t, "org-a", "carol"), f.membershipOf(t, "org-b", "bob")
	if err := f.runtimeExec("org-a", `INSERT INTO identity_connections(tenant_id,id,protocol,trust_namespace,display_name) VALUES('org-a','conn-a','oidc','https://idp.a.test','A')`); err != nil {
		t.Fatal(err)
	}
	// Same tenant, membership of alice but person of carol.
	err := f.runtimeExec("org-a", `INSERT INTO identity_authenticators(tenant_id,id,connection_id,protocol_subject,membership_id,person_id,approved_by,source)
		VALUES('org-a','auth-1','conn-a','sub-1',$1,$2,'admin','legacy_link')`, alice.ID.String(), carol.PersonID.String())
	requireSQLState(t, err, "23503")
	f.seedUser(t, "org-a", "dave", user.RoleMember, identityDigest("dave"), false)
	err = f.runtimeExec("org-a", `INSERT INTO identity_credentials(tenant_id,id,kind,digest,membership_id,person_id,legacy_user_id,source,legacy_key_issued)
		VALUES('org-a','cred-x','api_key',$1,$2,$3,'dave','legacy_projection',true)`, identityDigest("x"), alice.ID.String(), carol.PersonID.String())
	requireSQLState(t, err, "23503")
	// Cross tenant: an org-a row naming an org-b membership has no matching composite key.
	err = f.runtimeExec("org-a", `INSERT INTO identity_authenticators(tenant_id,id,connection_id,protocol_subject,membership_id,person_id,approved_by,source)
		VALUES('org-a','auth-2','conn-a','sub-2',$1,$2,'admin','legacy_link')`, bob.ID.String(), bob.PersonID.String())
	requireSQLState(t, err, "23503")
	// Writing an org-b row while bound to org-a is refused by the RLS WITH CHECK.
	err = f.runtimeExec("org-a", `INSERT INTO identity_connections(tenant_id,id,protocol,trust_namespace,display_name) VALUES('org-b','conn-b','oidc','https://idp.b.test','B')`)
	requireSQLState(t, err, "42501")
	// Empty tenant IDs are rejected on every new tenant row.
	err = f.runtimeExec("", `INSERT INTO identity_connections(tenant_id,id,protocol,trust_namespace,display_name) VALUES('','conn-e','oidc','https://idp.e.test','E')`)
	if err == nil {
		t.Fatal("empty tenant accepted")
	}
	// Legacy membership FK: a membership cannot name a users row of another tenant.
	err = f.runtimeExec("org-a", `INSERT INTO identity_memberships(tenant_id,id,person_id,legacy_user_id,role,last_transition_source)
		VALUES('org-a','m-x',$1,'bob','member','legacy_projection')`, f.newPerson(t, "person-x").String())
	requireSQLState(t, err, "23503")
	// Canonical authenticator key is unique per (tenant, connection, subject).
	if err := f.runtimeExec("org-a", `INSERT INTO identity_authenticators(tenant_id,id,connection_id,protocol_subject,membership_id,person_id,approved_by,source)
		VALUES('org-a','auth-3','conn-a','sub-3',$1,$2,'admin','legacy_link')`, alice.ID.String(), alice.PersonID.String()); err != nil {
		t.Fatal(err)
	}
	err = f.runtimeExec("org-a", `INSERT INTO identity_authenticators(tenant_id,id,connection_id,protocol_subject,membership_id,person_id,approved_by,source)
		VALUES('org-a','auth-4','conn-a','sub-3',$1,$2,'admin','legacy_link')`, carol.ID.String(), carol.PersonID.String())
	requireSQLState(t, err, "23505")
	// A native authenticator is not representable before cutover.
	err = f.runtimeExec("org-a", `INSERT INTO identity_authenticators(tenant_id,id,connection_id,protocol_subject,membership_id,person_id,approved_by,source)
		VALUES('org-a','auth-5','conn-a','sub-5',$1,$2,'admin','native')`, carol.ID.String(), carol.PersonID.String())
	requireSQLState(t, err, "SYN01")
	// A session's credential and membership must belong to the same person. The matching owner is
	// accepted, while independently valid same-tenant rows for another person fail the composite FK.
	f.declare(t, "org-a")
	aliceCredential := identityDigest("alice-browser-session")
	if err := f.runtimeExec("org-a", `INSERT INTO identity_credentials
		(tenant_id,id,kind,digest,membership_id,person_id,source,legacy_key_issued)
		VALUES('org-a','cred-session','browser_session',$1,$2,$3,'native',false)`, aliceCredential, alice.ID.String(), alice.PersonID.String()); err != nil {
		t.Fatal(err)
	}
	if err := f.runtimeExec("org-a", `INSERT INTO identity_sessions
		(tenant_id,id,credential_id,membership_id,person_id,lineage_id,authenticated_at,origin_at,expires_at,person_epoch,membership_epoch)
		VALUES('org-a','session-owner','cred-session',$1,$2,'lineage-owner',now(),now(),now()+interval '1 hour',1,1)`, alice.ID.String(), alice.PersonID.String()); err != nil {
		t.Fatalf("matching credential owner rejected: %v", err)
	}
	if err := f.runtimeExec("org-a", `DELETE FROM identity_sessions WHERE tenant_id='org-a' AND id='session-owner'`); err != nil {
		t.Fatal(err)
	}
	err = f.runtimeExec("org-a", `INSERT INTO identity_sessions
		(tenant_id,id,credential_id,membership_id,person_id,lineage_id,authenticated_at,origin_at,expires_at,person_epoch,membership_epoch)
		VALUES('org-a','session-non-owner','cred-session',$1,$2,'lineage-non-owner',now(),now(),now()+interval '1 hour',1,1)`, carol.ID.String(), carol.PersonID.String())
	requireSQLState(t, err, "23503")
	// The connection trust namespace is pinned.
	err = f.runtimeExec("org-a", `UPDATE identity_connections SET trust_namespace='https://evil.test' WHERE tenant_id='org-a' AND id='conn-a'`)
	requireSQLState(t, err, "SYN02")
}

func TestIdentityMembershipPickerExactPerson(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	f.tenants(t, "org-a", "org-b", "org-c")
	f.enableProjection(t, "org-a", now)
	aliceKey := f.createUser(t, "org-a", "alice", user.RoleAdmin, now)
	eveKey := f.createUser(t, "org-a", "eve", user.RoleMember, now)
	alice, eve := f.membershipOf(t, "org-a", "alice"), f.membershipOf(t, "org-a", "eve")
	f.declare(t, "org-b")
	f.declare(t, "org-c")
	inB, err := f.store.AddMembership(ctx, "org-b", alice.PersonID, "Alice", user.RoleReviewer, "platform-admin", now)
	if err != nil {
		t.Fatal(err)
	}
	inC, err := f.store.AddMembership(ctx, "org-c", alice.PersonID, "Alice", user.RoleMember, "platform-admin", now)
	if err != nil {
		t.Fatal(err)
	}
	choices, err := f.store.ActiveMembershipsForPerson(ctx, aliceKey, alice.PersonID)
	if err != nil || len(choices) != 3 {
		t.Fatalf("alice picker = %+v, %v", choices, err)
	}
	// Another person: a valid digest of one person never projects another person.
	if got, _ := f.store.ActiveMembershipsForPerson(ctx, eveKey, alice.PersonID); len(got) != 0 {
		t.Fatalf("eve's digest projected alice: %+v", got)
	}
	if got, _ := f.store.ActiveMembershipsForPerson(ctx, aliceKey, eve.PersonID); len(got) != 0 {
		t.Fatalf("alice's digest projected eve: %+v", got)
	}
	if got, _ := f.store.ActiveMembershipsForPerson(ctx, identityDigest("random"), alice.PersonID); len(got) != 0 {
		t.Fatalf("random digest projected alice: %+v", got)
	}
	// Suspended membership disappears from the picker.
	if _, err := f.store.ChangeMembership(ctx, "org-c", inC.ID, ports.IdentityMembershipChange{Kind: ports.IdentityMembershipChangeSuspend, Actor: "admin", At: now}); err != nil {
		t.Fatal(err)
	}
	choices, _ = f.store.ActiveMembershipsForPerson(ctx, aliceKey, alice.PersonID)
	if len(choices) != 2 {
		t.Fatalf("suspended membership still listed: %+v", choices)
	}
	for _, c := range choices {
		if c.MembershipID == inC.ID {
			t.Fatal("suspended membership listed")
		}
		if c.MembershipID == inB.ID && c.Role != user.RoleReviewer {
			t.Fatalf("picker role = %s", c.Role)
		}
	}
	// Suspended person: nothing, and no epoch.
	if _, err := f.platform.ApplyPersonCommand(ctx, alice.PersonID, ports.IdentityPersonSuspended, "platform-admin", "incident"); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.store.ActiveMembershipsForPerson(ctx, aliceKey, alice.PersonID); len(got) != 0 {
		t.Fatalf("suspended person projected: %+v", got)
	}
	if _, err := f.store.PersonEpoch(ctx, aliceKey, alice.PersonID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("suspended person epoch: %v", err)
	}
}

func TestIdentityAuditAndIndexFaultsRollBackLegacyWrite(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	f.tenants(t, "org-a")
	f.enableProjection(t, "org-a", now)
	original := f.createUser(t, "org-a", "alice", user.RoleAdmin, now)

	f.exec(t, `CREATE FUNCTION test_fail_rotation_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action = 'user.api_key_rotated' THEN RAISE EXCEPTION 'injected audit fault'; END IF; RETURN NEW; END $$`)
	f.exec(t, `CREATE TRIGGER test_fail_rotation_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION test_fail_rotation_audit()`)
	rotated := identityDigest("rotated")
	if err := f.updateUser(t, "org-a", "alice", "user.api_key_rotated", func(u *user.User) { u.APIKeyHash = rotated }); err == nil {
		t.Fatal("rotation committed despite audit fault")
	}
	f.exec(t, `DROP TRIGGER test_fail_rotation_audit ON audit_log`)
	stored, err := f.users.GetByID(ctx, "org-a", "alice")
	if err != nil || stored.APIKeyHash != original {
		t.Fatalf("users hash changed after audit fault: %v", err)
	}
	if r, err := f.store.RouteCredentialDigest(ctx, original); err != nil || r.TenantID != "org-a" {
		t.Fatalf("original digest no longer routes: %v", err)
	}
	if _, err := f.store.RouteCredentialDigest(ctx, rotated); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("rolled-back digest routes: %v", err)
	}

	blocked := identityDigest("blocked")
	f.exec(t, `CREATE FUNCTION test_fail_index() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.digest = '`+blocked+`' THEN RAISE EXCEPTION 'injected index fault'; END IF; RETURN NEW; END $$`)
	f.exec(t, `CREATE TRIGGER test_fail_index BEFORE INSERT ON identity_credential_digests FOR EACH ROW EXECUTE FUNCTION test_fail_index()`)
	if err := f.updateUser(t, "org-a", "alice", "user.api_key_rotated", func(u *user.User) { u.APIKeyHash = blocked }); err == nil {
		t.Fatal("rotation committed despite index fault")
	}
	stored, _ = f.users.GetByID(ctx, "org-a", "alice")
	if stored.APIKeyHash != original {
		t.Fatal("users hash changed after index fault")
	}
	if n := f.runtimeCount(t, "org-a", `SELECT count(*) FROM audit_log WHERE action='user.api_key_rotated'`); n != 0 {
		t.Fatalf("audit committed without its mutation: %d", n)
	}

	// Create is tenant-bound and atomic too: an audit fault on create leaves no users row and no projection.
	f.exec(t, `CREATE FUNCTION test_fail_create_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action = 'user.created' THEN RAISE EXCEPTION 'injected audit fault'; END IF; RETURN NEW; END $$`)
	f.exec(t, `CREATE TRIGGER test_fail_create_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION test_fail_create_audit()`)
	u, _ := user.New("mallory", "org-a", "Mallory", user.RoleMember, identityDigest("mallory"), now)
	err = f.tx.Run(ctx, "org-a", func(txCtx context.Context) error {
		if err := f.users.Create(txCtx, u); err != nil {
			return err
		}
		return f.audit.Record(txCtx, ports.AuditEntry{Actor: "admin", Action: "user.created", Target: "mallory", At: now})
	})
	if err == nil {
		t.Fatal("create committed despite audit fault")
	}
	if n := f.adminCount(t, `SELECT count(*) FROM users WHERE id='mallory'`) + f.adminCount(t, `SELECT count(*) FROM identity_memberships WHERE legacy_user_id='mallory'`); n != 0 {
		t.Fatalf("create left %d rows behind", n)
	}
}

func TestIdentityDisableRotateAndEpochRevocation(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	f.tenants(t, "org-a")
	f.enableProjection(t, "org-a", now)
	key := f.createUser(t, "org-a", "alice", user.RoleAdmin, now)
	f.createUser(t, "org-a", "admin2", user.RoleAdmin, now)
	m := f.membershipOf(t, "org-a", "alice")
	if err := f.runtimeExec("org-a", `INSERT INTO identity_connections(tenant_id,id,protocol,trust_namespace,display_name,enabled) VALUES('org-a','conn','oidc','https://idp.test','IdP',true)`); err != nil {
		t.Fatal(err)
	}
	start, err := f.store.CurrentEpochs(ctx, "org-a", m.ID, "conn", key)
	if err != nil || start.Person != 1 || start.Membership != 1 || start.Connection != 1 {
		t.Fatalf("initial epochs = %+v, %v", start, err)
	}
	// Person-scope revocation.
	res, err := f.platform.ApplyPersonCommand(ctx, m.PersonID, ports.IdentityPersonSessionsRevoked, "platform-admin", "lost laptop")
	if err != nil || res.PersonEpoch != 2 || res.Obligations != 1 {
		t.Fatalf("person revoke = %+v, %v", res, err)
	}
	// Connection-scope revocation: disabling moves the epoch; a disabled connection has none.
	if err := f.runtimeExec("org-a", `UPDATE identity_connections SET enabled=false WHERE id='conn'`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.CurrentEpochs(ctx, "org-a", m.ID, "conn", key); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("disabled connection epoch: %v", err)
	}
	if err := f.runtimeExec("org-a", `UPDATE identity_connections SET enabled=true WHERE id='conn'`); err != nil {
		t.Fatal(err)
	}
	after, err := f.store.CurrentEpochs(ctx, "org-a", m.ID, "conn", key)
	if err != nil || after.Person != 2 || after.Connection != 2 || after.Membership != 1 {
		t.Fatalf("epochs after person/connection revoke = %+v, %v", after, err)
	}
	// Disable, as the users service does it: replace the hash with an unusable digest.
	unusable := identityDigest("unusable-" + identityRandomHex(t, 8))
	if err := f.updateUser(t, "org-a", "alice", "user.disabled", func(u *user.User) { u.Disabled, u.APIKeyHash = true, unusable }); err != nil {
		t.Fatal(err)
	}
	for _, digest := range []string{key, unusable} {
		if _, err := f.store.RouteCredentialDigest(ctx, digest); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("disabled user's digest routes: %v", err)
		}
	}
	disabled := f.membershipOf(t, "org-a", "alice")
	if disabled.State != ports.IdentityMembershipSuspended || disabled.Epoch != 2 {
		t.Fatalf("disabled membership = %+v", disabled)
	}
	// Re-enable restores nothing.
	if err := f.updateUser(t, "org-a", "alice", "user.enabled", func(u *user.User) { u.Disabled = false }); err != nil {
		t.Fatal(err)
	}
	for _, digest := range []string{key, unusable} {
		if _, err := f.store.RouteCredentialDigest(ctx, digest); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("re-enable restored digest: %v", err)
		}
	}
	if m := f.membershipOf(t, "org-a", "alice"); m.State != ports.IdentityMembershipActive || m.Epoch != 3 {
		t.Fatalf("re-enabled membership = %+v", m)
	}
	// Rotation issues the only new working credential.
	fresh := identityDigest("fresh-" + identityRandomHex(t, 8))
	if err := f.updateUser(t, "org-a", "alice", "user.api_key_rotated", func(u *user.User) { u.APIKeyHash = fresh }); err != nil {
		t.Fatal(err)
	}
	if r, err := f.store.RouteCredentialDigest(ctx, fresh); err != nil || r.TenantID != "org-a" {
		t.Fatalf("rotated digest route: %v", err)
	}
	// Role change is a membership-scope revocation.
	if err := f.updateUser(t, "org-a", "alice", "user.updated", func(u *user.User) { u.Role = user.RoleReviewer }); err != nil {
		t.Fatal(err)
	}
	if m := f.membershipOf(t, "org-a", "alice"); m.Role != user.RoleReviewer || m.Epoch != 4 {
		t.Fatalf("role-changed membership = %+v", m)
	}
}

func TestIdentityMembershipRejoinAndManualDeny(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	f.tenants(t, "org-a", "org-b")
	f.enableProjection(t, "org-a", now)
	f.createUser(t, "org-a", "alice", user.RoleAdmin, now)
	legacy := f.membershipOf(t, "org-a", "alice")

	// Before declaration every native membership write is unrepresentable.
	_, err := f.store.ChangeMembership(ctx, "org-a", legacy.ID, ports.IdentityMembershipChange{Kind: ports.IdentityMembershipChangeSuspend, Actor: "admin", At: now})
	if !errors.Is(err, ports.ErrIdentityNotRepresentable) || !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("legacy-tenant membership change: %v", err)
	}
	person := f.newPerson(t, "person-dana")
	if _, err := f.store.AddMembership(ctx, "org-a", person, "Dana", user.RoleMember, "admin", now); !errors.Is(err, ports.ErrIdentityNotRepresentable) {
		t.Fatalf("legacy-tenant add membership: %v", err)
	}
	if n := f.adminCount(t, `SELECT count(*) FROM users WHERE tenant_id='org-a' AND name='Dana'`); n != 0 {
		t.Fatal("rejected membership left a projected users row")
	}
	// A second membership for one person is not representable in a legacy tenant.
	f.tenants(t, "org-c")
	f.seedUser(t, "org-c", "alice-c", user.RoleMember, identityDigest("alice-c"), false)
	err = f.runtimeExec("org-c", `INSERT INTO identity_memberships(tenant_id,id,person_id,legacy_user_id,role,last_transition_source)
		VALUES('org-c','m-c',$1,'alice-c','member','legacy_projection')`, legacy.PersonID.String())
	requireSQLState(t, err, "SYN01")

	f.declare(t, "org-b")
	m, err := f.store.AddMembership(ctx, "org-b", person, "Dana", user.RoleMember, "admin", now)
	if err != nil {
		t.Fatal(err)
	}
	change := func(kind ports.IdentityMembershipChangeKind, source ports.IdentityTransitionSource, approver string) (ports.IdentityMembership, error) {
		return f.store.ChangeMembership(ctx, "org-b", m.ID, ports.IdentityMembershipChange{Kind: kind, Source: source, ApprovedBy: approver, Actor: "admin", At: time.Now().UTC()})
	}
	if _, err := change(ports.IdentityMembershipChangeSuspend, ports.IdentityTransitionManual, ""); err != nil {
		t.Fatal(err)
	}
	// A source reactivation or source suspension cannot override a manual suspension.
	if _, err := change(ports.IdentityMembershipChangeReactivate, ports.IdentityTransitionSignal, ""); !errors.Is(err, ports.ErrIdentityLifecycle) {
		t.Fatalf("source reactivation over manual suspension: %v", err)
	}
	if _, err := change(ports.IdentityMembershipChangeSuspend, ports.IdentityTransitionSignal, ""); !errors.Is(err, ports.ErrIdentityLifecycle) {
		t.Fatalf("source re-suspension over manual suspension: %v", err)
	}
	if got, err := change(ports.IdentityMembershipChangeReactivate, ports.IdentityTransitionManual, ""); err != nil || got.State != ports.IdentityMembershipActive {
		t.Fatalf("manual reactivation = %+v, %v", got, err)
	}
	removed, err := change(ports.IdentityMembershipChangeRemove, ports.IdentityTransitionManual, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := change(ports.IdentityMembershipChangeReactivate, ports.IdentityTransitionManual, ""); !errors.Is(err, ports.ErrIdentityLifecycle) {
		t.Fatalf("removed membership reactivated without rejoin: %v", err)
	}
	if _, err := change(ports.IdentityMembershipChangeRejoin, ports.IdentityTransitionManual, ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unapproved rejoin: %v", err)
	}
	rejoined, err := change(ports.IdentityMembershipChangeRejoin, ports.IdentityTransitionManual, "security-admin")
	if err != nil || rejoined.State != ports.IdentityMembershipActive || rejoined.Epoch <= removed.Epoch {
		t.Fatalf("rejoin = %+v, %v", rejoined, err)
	}
	// Historical attribution: the same membership and legacy actor ID, with every transition audited.
	if rejoined.ID != m.ID || rejoined.LegacyUserID != m.LegacyUserID {
		t.Fatal("rejoin changed stable identifiers")
	}
	if n := f.runtimeCount(t, "org-b", `SELECT count(*) FROM audit_log WHERE target=$1 AND action LIKE 'identity.membership_%'`, m.ID.String()); n != 5 {
		t.Fatalf("membership audit rows = %d", n)
	}
	// Stale version is a conflict.
	if _, err := f.store.ChangeMembership(ctx, "org-b", m.ID, ports.IdentityMembershipChange{Kind: ports.IdentityMembershipChangeRole, Role: user.RoleAdmin, ExpectedVersion: 1, Actor: "admin", At: now}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale version: %v", err)
	}
}

func TestIdentityConcurrentLastAdmin(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	f.tenants(t, "org-b")
	f.declare(t, "org-b")
	first, err := f.store.AddMembership(ctx, "org-b", f.newPerson(t, "admin-one"), "One", user.RoleAdmin, "platform", now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.store.AddMembership(ctx, "org-b", f.newPerson(t, "admin-two"), "Two", user.RoleAdmin, "platform", now)
	if err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 5; round++ {
		var wg sync.WaitGroup
		start := make(chan struct{})
		errs := make([]error, 2)
		for i, target := range []shared.ID{first.ID, second.ID} {
			wg.Add(1)
			go func(i int, target shared.ID) {
				defer wg.Done()
				<-start
				_, errs[i] = f.store.ChangeMembership(ctx, "org-b", target, ports.IdentityMembershipChange{Kind: ports.IdentityMembershipChangeRole, Role: user.RoleMember, Actor: "admin", At: time.Now().UTC()})
			}(i, target)
		}
		close(start)
		wg.Wait()
		failures := 0
		for _, err := range errs {
			if err != nil {
				if !errors.Is(err, shared.ErrConflict) {
					t.Fatalf("unexpected demotion error: %v", err)
				}
				failures++
			}
		}
		if failures != 1 {
			t.Fatalf("round %d: %d demotions failed, want exactly 1", round, failures)
		}
		if n := f.runtimeCount(t, "org-b", `SELECT count(*) FROM identity_memberships WHERE role='admin' AND state='active'`); n != 1 {
			t.Fatalf("round %d: %d active administrators", round, n)
		}
		// Restore both administrators for the next round.
		for _, target := range []shared.ID{first.ID, second.ID} {
			if _, err := f.store.ChangeMembership(ctx, "org-b", target, ports.IdentityMembershipChange{Kind: ports.IdentityMembershipChangeRole, Role: user.RoleAdmin, Actor: "admin", At: time.Now().UTC()}); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestIdentityPersonAuditFanOutCrashAndRetry(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	f.tenants(t, "org-a", "org-b")
	f.enableProjection(t, "org-a", now)
	f.createUser(t, "org-a", "alice", user.RoleAdmin, now)
	alice := f.membershipOf(t, "org-a", "alice")
	f.declare(t, "org-b")
	if _, err := f.store.AddMembership(ctx, "org-b", alice.PersonID, "Alice", user.RoleMember, "platform", now); err != nil {
		t.Fatal(err)
	}
	auditsBefore := f.adminCount(t, `SELECT count(*) FROM identity_person_audit`)

	// Atomic with the caller: a rolled-back caller transaction leaves no person audit or obligation.
	injected := errors.New("caller failed")
	err := f.platformTx.Run(ctx, "org-a", func(txCtx context.Context) error {
		if _, err := f.platform.ApplyPersonCommand(txCtx, alice.PersonID, ports.IdentityPersonSessionsRevoked, "platform-admin", "rolled back"); err != nil {
			return err
		}
		return injected
	})
	if !errors.Is(err, injected) {
		t.Fatalf("caller transaction: %v", err)
	}
	if got := f.adminCount(t, `SELECT count(*) FROM identity_person_audit`); got != auditsBefore {
		t.Fatalf("rolled-back person command left audit rows: %d -> %d", auditsBefore, got)
	}
	res, err := f.platform.ApplyPersonCommand(ctx, alice.PersonID, ports.IdentityPersonSessionsRevoked, "platform-admin", "device lost")
	if err != nil || res.Obligations != 2 {
		t.Fatalf("fan-out = %+v, %v", res, err)
	}
	if f.runtimeCount(t, "org-a", `SELECT count(*) FROM identity_person_audit_deliveries WHERE id=$1`, res.AuditID)+
		f.runtimeCount(t, "org-b", `SELECT count(*) FROM identity_person_audit_deliveries WHERE id=$1`, res.AuditID) != 2 {
		t.Fatal("obligations not tenant-scoped")
	}
	// Obligations are immutable.
	err = f.runtimeExec("org-a", `UPDATE identity_person_audit_deliveries SET reason='edited' WHERE id=$1`, res.AuditID)
	requireSQLState(t, err, "SYN02")

	// Delivery crash: the tenant audit append fails; the attempt is counted and retried later.
	f.exec(t, `CREATE FUNCTION test_fail_person_delivery() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action = 'identity.person.sessions_revoked' AND NEW.tenant_id = 'org-b' THEN RAISE EXCEPTION 'injected delivery fault'; END IF; RETURN NEW; END $$`)
	f.exec(t, `CREATE TRIGGER test_fail_person_delivery BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION test_fail_person_delivery()`)
	clock := now.Add(time.Minute)
	for _, tenant := range []shared.ID{"org-a", "org-b"} {
		if _, err := f.store.DeliverPersonAudit(ctx, tenant, clock, 10); err != nil {
			t.Fatal(err)
		}
	}
	status, err := f.store.DeliveryStatus(ctx, "org-b")
	if err != nil || status.Pending != 1 || status.MaxAttempts != 1 {
		t.Fatalf("org-b status after fault = %+v, %v", status, err)
	}
	// Not due yet: the bounded backoff holds the retry.
	if stats, _ := f.store.DeliverPersonAudit(ctx, "org-b", clock, 10); stats.Failed+stats.Delivered != 0 {
		t.Fatalf("retried before backoff: %+v", stats)
	}
	f.exec(t, `DROP TRIGGER test_fail_person_delivery ON audit_log`)
	stats, err := f.store.DeliverPersonAudit(ctx, "org-b", clock.Add(time.Hour), 10)
	if err != nil || stats.Delivered != 1 {
		t.Fatalf("retry = %+v, %v", stats, err)
	}
	// Idempotent: another pass delivers nothing and the tenant chain holds exactly one record.
	if stats, _ := f.store.DeliverPersonAudit(ctx, "org-b", clock.Add(2*time.Hour), 10); stats.Delivered != 0 {
		t.Fatalf("redelivered: %+v", stats)
	}
	for _, tenant := range []string{"org-a", "org-b"} {
		if n := f.runtimeCount(t, tenant, `SELECT count(*) FROM audit_log WHERE action='identity.person.sessions_revoked' AND metadata->>'person_audit_id'=$1`, strconv.FormatInt(res.AuditID, 10)); n != 1 {
			t.Fatalf("%s delivered %d records", tenant, n)
		}
	}

	// Exhaustion is bounded and observable.
	f.exec(t, `CREATE TRIGGER test_fail_person_delivery BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION test_fail_person_delivery()`)
	res, err = f.platform.ApplyPersonCommand(ctx, alice.PersonID, ports.IdentityPersonSessionsRevoked, "platform-admin", "again")
	if err != nil {
		t.Fatal(err)
	}
	at := clock.Add(3 * time.Hour)
	exhausted := 0
	for i := 0; i < 12; i++ {
		at = at.Add(24 * time.Hour)
		stats, err := f.store.DeliverPersonAudit(ctx, "org-b", at, 10)
		if err != nil {
			t.Fatal(err)
		}
		exhausted += stats.Exhausted
	}
	status, _ = f.store.DeliveryStatus(ctx, "org-b")
	if exhausted != 1 || status.Exhausted != 1 || status.Pending != 0 || status.MaxAttempts != 8 {
		t.Fatalf("exhaustion = %d, status %+v", exhausted, status)
	}
}
