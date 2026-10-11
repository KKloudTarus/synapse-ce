package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestIdentityWriterFenceRetiresLegacyUsersAfterDeclaration(t *testing.T) {
	f := newIdentityFixture(t)
	now := time.Now().UTC()
	const tenant = "writer-fence"
	f.tenants(t, tenant)

	legacy, err := user.New("legacy-writer", tenant, "Legacy Writer", user.RoleMember, identityDigest("legacy-writer"), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.users.Create(context.Background(), legacy); err != nil {
		t.Fatalf("legacy create before declaration: %v", err)
	}
	legacy.Name = "Legacy Writer Updated"
	legacy.Audit.UpdatedAt = now.Add(time.Second)
	if err := f.users.Update(context.Background(), tenant, legacy); err != nil {
		t.Fatalf("legacy update before declaration: %v", err)
	}

	f.declare(t, tenant)
	blocked, err := user.New("retired-writer", tenant, "Retired Writer", user.RoleMember, identityDigest("retired-writer"), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.users.Create(context.Background(), blocked); err == nil {
		t.Fatal("legacy create succeeded after declaration")
	}
	legacy.Name = "Forbidden Update"
	legacy.Audit.UpdatedAt = now.Add(2 * time.Second)
	if err := f.users.Update(context.Background(), tenant, legacy); err == nil {
		t.Fatal("legacy update succeeded after declaration")
	}
}

func TestIdentityWriterFenceNativeMembershipMirrorsCompatibilityUser(t *testing.T) {
	f := newIdentityFixture(t)
	now := time.Now().UTC()
	const tenant = "native-writer"
	f.tenants(t, tenant)
	f.declare(t, tenant)
	person := f.newPerson(t, "native-writer-person")
	membership, err := f.store.AddMembership(context.Background(), tenant, person, "Native Member", user.RoleMember, "platform", now)
	if err != nil {
		t.Fatalf("add native membership: %v", err)
	}
	compat, err := f.users.GetByID(context.Background(), tenant, membership.LegacyUserID)
	if err != nil || compat.Role != user.RoleMember || compat.Disabled {
		t.Fatalf("projected compatibility user=%+v err=%v", compat, err)
	}
	updated, err := f.store.ChangeMembership(context.Background(), tenant, membership.ID, ports.IdentityMembershipChange{
		Kind: ports.IdentityMembershipChangeRole, Role: user.RoleReadOnly, ExpectedVersion: membership.Version, Actor: "platform", At: now.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("change native membership role: %v", err)
	}
	compat, err = f.users.GetByID(context.Background(), tenant, membership.LegacyUserID)
	if err != nil || compat.Role != user.RoleReadOnly || compat.Disabled || updated.Role != user.RoleReadOnly {
		t.Fatalf("mirrored compatibility user=%+v membership=%+v err=%v", compat, updated, err)
	}
}

func TestIdentityWriterFenceRejectsUnboundAndSpoofedRuntimeWrites(t *testing.T) {
	f := newIdentityFixture(t)
	const tenant = "spoof-fence"
	f.tenants(t, tenant)
	f.declare(t, tenant)
	ctx := context.Background()
	if _, err := f.runtime.Exec(ctx, `INSERT INTO users(id,name,role,api_key_hash,tenant_id) VALUES('unbound','Unbound','member',$1,$2)`, identityDigest("unbound"), tenant); err == nil {
		t.Fatal("unbound runtime users insert succeeded")
	}
	if _, err := f.runtime.Exec(ctx, `SELECT set_config('app.current_tenant',$1,false)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := f.runtime.Exec(ctx, `INSERT INTO users(id,name,role,api_key_hash,tenant_id) VALUES('spoofed','Spoofed','member',$1,$2)`, identityDigest("spoofed"), tenant); err == nil {
		t.Fatal("caller-set tenant GUC bypassed declared writer fence")
	}
	var owner string
	if err := f.admin.QueryRow(ctx, `SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if _, err := f.runtime.Exec(ctx, `SET ROLE `+quoteIdentifier(owner)); err == nil {
		t.Fatal("runtime role assumed schema owner")
	}
}

func TestIdentityWriterFenceAllowsBootstrapRefreshAndRollsBackNativeProjectionFailure(t *testing.T) {
	f := newIdentityFixture(t)
	now := time.Now().UTC()
	bootstrap, err := user.New("operator", "", "Operator", user.RoleAdmin, identityDigest("bootstrap-one"), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.users.Bootstrap(context.Background(), bootstrap, ports.AuditEntry{Actor: "operator", Action: "bootstrap", Target: "operator", At: now}); err != nil {
		t.Fatalf("bootstrap create: %v", err)
	}
	bootstrap.APIKeyHash = identityDigest("bootstrap-two")
	bootstrap.Audit.UpdatedAt = now.Add(time.Second)
	if err := f.users.Bootstrap(context.Background(), bootstrap, ports.AuditEntry{Actor: "operator", Action: "bootstrap", Target: "operator", At: now}); err != nil {
		t.Fatalf("bootstrap refresh: %v", err)
	}

	const tenant = "projection-rollback"
	f.tenants(t, tenant)
	f.declare(t, tenant)
	person := f.newPerson(t, "projection-rollback-person")
	// An invalid actor makes the terminal audit append fail after the definer projection and
	// membership insert. The encompassing transaction must leave neither row behind.
	_, err = f.store.AddMembership(context.Background(), tenant, person, "Rollback", user.RoleMember, string(make([]byte, 300)), now)
	if err == nil {
		t.Fatal("native membership with invalid audit actor succeeded")
	}
	membershipID := legacyIdentityID("membership_", shared.ID(tenant), person)
	if f.adminCount(t, `SELECT count(*) FROM identity_memberships WHERE tenant_id=$1 AND id=$2`, tenant, membershipID.String()) != 0 ||
		f.adminCount(t, `SELECT count(*) FROM users WHERE ownership_tenant_id=$1 AND id=$2`, tenant, legacyIdentityID("member_", shared.ID(tenant), person).String()) != 0 {
		t.Fatal("failed native membership left compatibility projection rows")
	}
}
