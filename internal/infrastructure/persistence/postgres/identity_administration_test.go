package postgres

import (
	"context"
	"errors"
	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"testing"
	"time"
)

func TestIdentityAdministrationRejectsRecoveryRemovalAndStaleVersion(t *testing.T) {
	f := newIdentityFixture(t)
	now := time.Now().UTC()
	tenant := shared.ID("native-admin")
	f.tenants(t, tenant.String())
	f.declare(t, tenant.String())
	person := f.newPerson(t, "native-person")
	m, err := f.store.AddMembership(context.Background(), tenant, person, "Admin", "admin", "platform", now)
	if err != nil {
		t.Fatal(err)
	}
	seedSessionConnection(t, f, tenant.String(), m, "native-conn", "native-subject", now)
	proof := bootstrapConnectionProof(tenant.String(), now)
	if _, err = f.store.ChangeIdentityMembershipAdministration(context.Background(), ports.IdentityMembershipAdministration{TenantID: tenant, MembershipID: m.ID, Kind: ports.IdentityMembershipChangeRole, Role: "member", ExpectedVersion: m.Version + 1, Proof: proof}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale version=%v", err)
	}
	recovery := proof
	recovery.Bootstrap = nil
	recovery.Recovery = true
	recovery.Principal = authz.Principal{ActorID: "x", TenantID: tenant.String(), Credential: authz.Credential{Kind: authz.KindBreakGlass, ID: "x"}, AuthenticatedAt: now}
	if _, err = f.store.ChangeIdentityMembershipAdministration(context.Background(), ports.IdentityMembershipAdministration{TenantID: tenant, MembershipID: m.ID, Kind: ports.IdentityMembershipChangeRemove, ExpectedVersion: m.Version, Proof: recovery}); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("recovery remove=%v", err)
	}
}

func TestIdentityAdministrationListsOwnAuthenticatorsForActiveMember(t *testing.T) {
	f := newIdentityFixture(t)
	now := time.Now().UTC()
	tenant := shared.ID("member-read")
	f.tenants(t, tenant.String())
	f.declare(t, tenant.String())
	person := f.newPerson(t, "member-person")
	m, err := f.store.AddMembership(context.Background(), tenant, person, "Member", "member", "platform", now)
	if err != nil {
		t.Fatal(err)
	}
	seedSessionConnection(t, f, tenant.String(), m, "member-conn", "member-subject", now)
	session := enterpriseSession("member-session", tenant, m.ID, person, "member-conn", now)
	if err = f.store.CreateEnterpriseSession(context.Background(), ports.IdentitySessionIssue{Session: session, CredentialDigest: identityDigest("member-token")}, "test", now); err != nil {
		t.Fatal(err)
	}
	proof := ports.IdentityAdminProof{Principal: authz.Principal{ActorID: "member", TenantID: tenant.String(), PersonID: person.String(), MembershipID: m.ID.String(), Credential: authz.Credential{Kind: authz.KindBrowserSession, ID: session.ID.String()}, AuthenticatedAt: now}, At: now}
	got, err := f.store.ListOwnIdentityAuthenticators(context.Background(), proof)
	if err != nil || len(got) != 1 {
		t.Fatalf("authenticators=%+v err=%v", got, err)
	}
}
