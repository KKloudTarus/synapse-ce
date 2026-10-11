package users

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/identity"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const testIssuer = "https://issuer.example"

// switchableAudit records entries and fails every Record while fail is set.
type switchableAudit struct {
	fail    bool
	entries []ports.AuditEntry
}

func (a *switchableAudit) Record(_ context.Context, e ports.AuditEntry) error {
	if a.fail {
		return errors.New("audit sink unavailable")
	}
	a.entries = append(a.entries, e)
	return nil
}

type identityRig struct {
	svc        *Service
	repo       *memory.UserRepository
	identities *memory.IdentityStore
	audit      *switchableAudit
	admin      Actor
}

// newIdentityRig wires the users service to the in-memory identity store inside the in-memory tenant
// transaction runner, the same shape the composition root builds.
func newIdentityRig(t *testing.T, tenant string) identityRig {
	t.Helper()
	repo := memory.NewUserRepository()
	audit := &switchableAudit{}
	svc, err := NewService(repo, audit, fixedClock{}, &seqIDs{})
	if err != nil {
		t.Fatal(err)
	}
	identities, err := memory.NewIdentityStore(repo)
	if err != nil {
		t.Fatal(err)
	}
	svc.SetTransactionRunner(memory.NewTenantTransactionRunner())
	svc.SetIdentityStore(identities)
	if err := svc.SetOIDCLinking(testIssuer, shared.ID(tenant)); err != nil {
		t.Fatal(err)
	}
	u, _, err := svc.CreateUser(context.Background(), bootstrapActor, tenant, "Admin", user.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	return identityRig{svc: svc, repo: repo, identities: identities, audit: audit, admin: adminActor(u.ID.String(), tenant)}
}

func (r identityRig) session(t *testing.T, tenant shared.ID, userID shared.ID, tokenHash string) identity.Session {
	t.Helper()
	now := fixedClock{}.Now()
	session, err := identity.NewSession(shared.ID("s-"+tokenHash), tenant, userID, tokenHash, "csrf-"+tokenHash, nil, now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.identities.CreateSession(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	return session
}

func (r identityRig) sessionActive(t *testing.T, tenant shared.ID, tokenHash string) bool {
	t.Helper()
	got, err := r.identities.GetSessionByTokenHash(shared.WithTenant(context.Background(), tenant), tokenHash)
	if err != nil {
		t.Fatal(err)
	}
	return got.Active(fixedClock{}.Now())
}

// Disable revokes every browser session and the bearer key; re-enable restores neither.
func TestDisableRevokesSessionsAndKeyAndEnableRestoresNeither(t *testing.T) {
	rig := newIdentityRig(t, "acme")
	ctx := context.Background()
	target, key, err := rig.svc.CreateUser(ctx, rig.admin, "", "Alice", user.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	rig.session(t, "acme", target.ID, "hash-a")
	rig.session(t, "acme", target.ID, "hash-b")
	admin, _ := rig.repo.GetByID(ctx, "acme", shared.ID(rig.admin.ID))
	rig.session(t, "acme", admin.ID, "hash-admin")

	if _, err := rig.svc.SetDisabled(ctx, rig.admin, target.ID, true); err != nil {
		t.Fatalf("disable: %v", err)
	}
	for _, hash := range []string{"hash-a", "hash-b"} {
		if rig.sessionActive(t, "acme", hash) {
			t.Errorf("session %s survived disable", hash)
		}
	}
	if !rig.sessionActive(t, "acme", "hash-admin") {
		t.Error("disable revoked another user's session")
	}
	if _, err := rig.svc.Authenticate(ctx, key); !errors.Is(err, authz.ErrCredentialInvalid) {
		t.Fatalf("disabled key: %v", err)
	}
	if _, err := rig.svc.SetDisabled(ctx, rig.admin, target.ID, false); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if rig.sessionActive(t, "acme", "hash-a") {
		t.Error("re-enable restored a revoked session")
	}
	if _, err := rig.svc.Authenticate(ctx, key); !errors.Is(err, authz.ErrCredentialInvalid) {
		t.Fatalf("re-enable restored the revoked key: %v", err)
	}
	var disabled ports.AuditEntry
	for _, e := range rig.audit.entries {
		if e.Action == "user.disabled" {
			disabled = e
		}
	}
	if disabled.Metadata["sessions_revoked"] != "2" || disabled.Metadata["api_key_revoked"] != "true" {
		t.Fatalf("disable audit does not record the revocation: %+v", disabled.Metadata)
	}
}

// An account disabled before disable revoked anything still holds its real key digest and live
// sessions. Re-enabling it must revoke both rather than bring them back.
func TestEnablingAPreviouslyDisabledAccountRevokesItsOldCredentials(t *testing.T) {
	rig := newIdentityRig(t, "acme")
	ctx := context.Background()
	target, key, err := rig.svc.CreateUser(ctx, rig.admin, "", "Alice", user.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	rig.session(t, "acme", target.ID, "hash-legacy")
	// Simulate the earlier behavior: only the flag flips, the digest and sessions stay.
	legacy, err := rig.repo.GetByID(ctx, "acme", target.ID)
	if err != nil {
		t.Fatal(err)
	}
	legacy.SetDisabled(true, fixedClock{}.Now())
	if err := rig.repo.Update(ctx, "acme", legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := rig.svc.SetDisabled(ctx, rig.admin, target.ID, false); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if _, err := rig.svc.Authenticate(ctx, key); !errors.Is(err, authz.ErrCredentialInvalid) {
		t.Fatalf("re-enable restored the key held before the account was disabled: %v", err)
	}
	if rig.sessionActive(t, "acme", "hash-legacy") {
		t.Fatal("re-enable restored a session opened before the account was disabled")
	}
}

// Repeating the current state is a no-op: it neither discards a working key nor records a second
// revocation.
func TestSetDisabledToTheCurrentStateChangesNothing(t *testing.T) {
	rig := newIdentityRig(t, "acme")
	ctx := context.Background()
	target, key, err := rig.svc.CreateUser(ctx, rig.admin, "", "Alice", user.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	before := len(rig.audit.entries)
	if _, err := rig.svc.SetDisabled(ctx, rig.admin, target.ID, false); err != nil {
		t.Fatalf("enable an enabled user: %v", err)
	}
	if _, err := rig.svc.Authenticate(ctx, key); err != nil {
		t.Fatalf("enabling an enabled user discarded its key: %v", err)
	}
	if _, err := rig.svc.SetDisabled(ctx, rig.admin, target.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := rig.svc.SetDisabled(ctx, rig.admin, target.ID, true); err != nil {
		t.Fatalf("repeat disable: %v", err)
	}
	var disables int
	for _, e := range rig.audit.entries[before:] {
		if e.Action == "user.disabled" || e.Action == "user.enabled" {
			disables++
		}
	}
	if disables != 1 {
		t.Fatalf("recorded %d state changes, want exactly the one real disable", disables)
	}
}

// Every consequential mutation returns the audit error instead of succeeding silently.
func TestAuditFailureFailsEveryConsequentialMutation(t *testing.T) {
	rig := newIdentityRig(t, "acme")
	ctx := context.Background()
	target, _, err := rig.svc.CreateUser(ctx, rig.admin, "", "Alice", user.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	rig.audit.fail = true
	cases := map[string]func() error{
		"create":  func() error { _, _, err := rig.svc.CreateUser(ctx, rig.admin, "", "Bob", user.RoleMember); return err },
		"update":  func() error { _, err := rig.svc.Update(ctx, rig.admin, target.ID, "Alice B", ""); return err },
		"disable": func() error { _, err := rig.svc.SetDisabled(ctx, rig.admin, target.ID, true); return err },
		"rotate":  func() error { _, _, err := rig.svc.RotateAPIKey(ctx, rig.admin, target.ID); return err },
		"link": func() error {
			_, err := rig.svc.LinkOIDCIdentity(ctx, rig.admin, target.ID, testIssuer, "sub-1")
			return err
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if err := mutate(); err == nil {
				t.Fatal("mutation succeeded although its audit record failed")
			}
		})
	}
}

// The link, the session revocation and the users row itself roll back with a failed audit record:
// the in-memory identity store and users repository both register compensations with the tenant
// transaction, so the no-DSN mode keeps the same atomicity the PostgreSQL test proves.
func TestAuditFailureRollsBackLinkAndSessionRevocation(t *testing.T) {
	rig := newIdentityRig(t, "acme")
	ctx := context.Background()
	target, key, err := rig.svc.CreateUser(ctx, rig.admin, "", "Alice", user.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	rig.session(t, "acme", target.ID, "hash-a")
	rig.audit.fail = true
	if _, err := rig.svc.LinkOIDCIdentity(ctx, rig.admin, target.ID, testIssuer, "sub-1"); err == nil {
		t.Fatal("link succeeded without its audit record")
	}
	if _, err := rig.identities.GetExternalIdentity(shared.WithTenant(ctx, "acme"), testIssuer, "sub-1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("a link survived its failed audit: %v", err)
	}
	if _, err := rig.svc.SetDisabled(ctx, rig.admin, target.ID, true); err == nil {
		t.Fatal("disable succeeded without its audit record")
	}
	if !rig.sessionActive(t, "acme", "hash-a") {
		t.Fatal("session revocation survived the failed disable")
	}
	restored, err := rig.repo.GetByID(ctx, "acme", target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Disabled || restored.APIKeyHash != target.APIKeyHash {
		t.Fatalf("the users row kept the failed disable: disabled=%v, key replaced=%v", restored.Disabled, restored.APIKeyHash != target.APIKeyHash)
	}
	if _, err := rig.svc.Authenticate(ctx, key); err != nil {
		t.Fatalf("the original key stopped working after a rolled-back disable: %v", err)
	}
	rig.audit.fail = false
	other, _, err := rig.svc.CreateUser(ctx, rig.admin, "", "Bob", user.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rig.svc.LinkOIDCIdentity(ctx, rig.admin, other.ID, testIssuer, "sub-1"); err != nil {
		t.Fatalf("the subject must still be linkable after the failed attempt: %v", err)
	}
}

func TestLinkOIDCIdentityIsNarrow(t *testing.T) {
	rig := newIdentityRig(t, "acme")
	ctx := context.Background()
	alice, _, err := rig.svc.CreateUser(ctx, rig.admin, "", "Alice", user.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	disabled, _, err := rig.svc.CreateUser(ctx, rig.admin, "", "Dora", user.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rig.svc.SetDisabled(ctx, rig.admin, disabled.ID, true); err != nil {
		t.Fatal(err)
	}
	otherAdmin, _, err := rig.svc.CreateUser(ctx, bootstrapActor, "globex", "Globex Admin", user.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		actor   Actor
		id      shared.ID
		issuer  string
		subject string
		want    error
	}{
		{"bootstrap user", rig.admin, BootstrapID, testIssuer, "sub-x", shared.ErrForbidden},
		{"disabled user", rig.admin, disabled.ID, testIssuer, "sub-x", shared.ErrConflict},
		{"other tenant actor", adminActor(otherAdmin.ID.String(), "globex"), otherAdmin.ID, testIssuer, "sub-x", shared.ErrForbidden},
		{"user in another tenant", rig.admin, otherAdmin.ID, testIssuer, "sub-x", shared.ErrNotFound},
		{"issuer with trailing slash", rig.admin, alice.ID, testIssuer + "/", "sub-x", shared.ErrValidation},
		{"different issuer", rig.admin, alice.ID, "https://evil.example", "sub-x", shared.ErrValidation},
		{"empty subject", rig.admin, alice.ID, testIssuer, "", shared.ErrValidation},
		{"padded subject", rig.admin, alice.ID, testIssuer, " sub-x", shared.ErrValidation},
		{"control character subject", rig.admin, alice.ID, testIssuer, "sub\nx", shared.ErrValidation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := rig.svc.LinkOIDCIdentity(ctx, tc.actor, tc.id, tc.issuer, tc.subject); !errors.Is(err, tc.want) {
				t.Fatalf("LinkOIDCIdentity() = %v, want %v", err, tc.want)
			}
		})
	}
	link, err := rig.svc.LinkOIDCIdentity(ctx, rig.admin, alice.ID, testIssuer, "sub-alice")
	if err != nil {
		t.Fatalf("approved link: %v", err)
	}
	if link.TenantID != "acme" || link.UserID != alice.ID || link.Issuer != testIssuer || link.Subject != "sub-alice" {
		t.Fatalf("link = %+v", link)
	}
	if _, err := rig.svc.LinkOIDCIdentity(ctx, rig.admin, rig.mustID(t, "Admin"), testIssuer, "sub-alice"); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("a subject may link to one user only: %v", err)
	}
	links, err := rig.svc.ListOIDCLinks(ctx, rig.admin, alice.ID)
	if err != nil || len(links) != 1 || links[0].Subject != "sub-alice" {
		t.Fatalf("ListOIDCLinks = %+v, %v", links, err)
	}
	var audited bool
	for _, e := range rig.audit.entries {
		if e.Action == "user.oidc_identity_linked" && e.Target == alice.ID.String() && e.Metadata["subject"] == "sub-alice" && e.Metadata["issuer"] == testIssuer {
			audited = true
		}
	}
	if !audited {
		t.Fatal("link was not audited")
	}
}

func (r identityRig) mustID(t *testing.T, name string) shared.ID {
	t.Helper()
	users, err := r.repo.List(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		if u.Name == name {
			return u.ID
		}
	}
	t.Fatalf("no user %q", name)
	return ""
}

func TestLinkOIDCIdentityOffWithoutConfiguration(t *testing.T) {
	svc, _ := newSvc(t)
	if _, err := svc.LinkOIDCIdentity(context.Background(), adminActor("a", "acme"), "u", testIssuer, "s"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("linking without OIDC must be unavailable: %v", err)
	}
}

// failingUserRepo fails the authentication lookup like an unreachable database.
type failingUserRepo struct{ *memory.UserRepository }

func (failingUserRepo) GetByAPIKeyHash(context.Context, string) (*user.User, error) {
	return nil, errors.New("connection refused")
}

func TestAuthenticateClassifiesOutcomes(t *testing.T) {
	svc, _ := newSvc(t)
	ctx := context.Background()
	if err := svc.EnsureBootstrapAdmin(ctx, "bootstrap-token"); err != nil {
		t.Fatal(err)
	}
	_, key, err := svc.CreateUser(ctx, bootstrapActor, "acme", "Alice", user.RoleReviewer)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, _, err := svc.AuthenticatePrincipal(ctx, "bootstrap-token")
	if err != nil || bootstrap.Credential.Kind != authz.KindBootstrap || bootstrap.ActorID != BootstrapID || !bootstrap.IsBootstrap() {
		t.Fatalf("bootstrap principal = %+v, %v", bootstrap, err)
	}
	member, _, err := svc.AuthenticatePrincipal(ctx, key)
	if err != nil || member.Credential.Kind != authz.KindAPIKey || member.TenantID != "acme" || member.Role != user.RoleReviewer || member.IsBootstrap() {
		t.Fatalf("api key principal = %+v, %v", member, err)
	}
	if _, _, err := svc.AuthenticatePrincipal(ctx, "unknown"); !errors.Is(err, authz.ErrCredentialInvalid) {
		t.Fatalf("unknown token: %v", err)
	}

	outage, err := NewService(failingUserRepo{memory.NewUserRepository()}, nopAudit{}, fixedClock{}, &seqIDs{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = outage.Authenticate(ctx, key)
	if !errors.Is(err, authz.ErrAuthenticationUnavailable) || errors.Is(err, authz.ErrCredentialInvalid) {
		t.Fatalf("a repository outage must be unavailable, never invalid: %v", err)
	}
}

// A users row carrying the bootstrap id is platform authority only while its digest is the
// configured SYNAPSE_API_TOKEN's.
func TestBootstrapPrincipalRequiresTheConfiguredToken(t *testing.T) {
	repo := memory.NewUserRepository()
	svc, err := NewService(repo, nopAudit{}, fixedClock{}, &seqIDs{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := svc.EnsureBootstrapAdmin(ctx, "configured-token"); err != nil {
		t.Fatal(err)
	}
	stale, err := user.New(BootstrapID, "", "Operator", user.RoleAdmin, HashToken("stale-token"), fixedClock{}.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Upsert(ctx, stale); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.AuthenticatePrincipal(ctx, "stale-token"); !errors.Is(err, authz.ErrCredentialInvalid) {
		t.Fatalf("a bootstrap row with a foreign digest must not authenticate: %v", err)
	}
}

// Unlinking removes exactly the named link, revokes every browser session of the user, and is
// audited with the removed issuer and subject.
func TestUnlinkOIDCIdentityRemovesTheLinkAndRevokesSessions(t *testing.T) {
	rig := newIdentityRig(t, "acme")
	ctx := context.Background()
	alice, _, err := rig.svc.CreateUser(ctx, rig.admin, "", "Alice", user.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	kept, err := rig.svc.LinkOIDCIdentity(ctx, rig.admin, alice.ID, testIssuer, "sub-keep")
	if err != nil {
		t.Fatal(err)
	}
	removed, err := rig.svc.LinkOIDCIdentity(ctx, rig.admin, alice.ID, testIssuer, "sub-remove")
	if err != nil {
		t.Fatal(err)
	}
	rig.session(t, "acme", alice.ID, "hash-a")
	rig.session(t, "acme", alice.ID, "hash-b")

	got, err := rig.svc.UnlinkOIDCIdentity(ctx, rig.admin, alice.ID, removed.ID)
	if err != nil {
		t.Fatalf("unlink: %v", err)
	}
	if got.ID != removed.ID || got.Subject != "sub-remove" {
		t.Fatalf("unlink returned %+v", got)
	}
	if _, err := rig.identities.GetExternalIdentity(shared.WithTenant(ctx, "acme"), testIssuer, "sub-remove"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("the unlinked subject still resolves: %v", err)
	}
	links, err := rig.svc.ListOIDCLinks(ctx, rig.admin, alice.ID)
	if err != nil || len(links) != 1 || links[0].ID != kept.ID {
		t.Fatalf("only the named link may be removed: %+v %v", links, err)
	}
	if rig.sessionActive(t, "acme", "hash-a") || rig.sessionActive(t, "acme", "hash-b") {
		t.Fatal("unlinking must revoke the user's browser sessions")
	}
	var entry *ports.AuditEntry
	for i := range rig.audit.entries {
		if rig.audit.entries[i].Action == "user.oidc_identity_unlinked" {
			entry = &rig.audit.entries[i]
		}
	}
	if entry == nil || entry.Target != alice.ID.String() || entry.Metadata["issuer"] != testIssuer || entry.Metadata["subject"] != "sub-remove" ||
		entry.Metadata["link_id"] != removed.ID.String() || entry.Metadata["sessions_revoked"] != "2" {
		t.Fatalf("unlink audit = %+v", entry)
	}
	if _, err := rig.svc.UnlinkOIDCIdentity(ctx, rig.admin, alice.ID, removed.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("a second unlink of the same link: want ErrNotFound, got %v", err)
	}
}

// An audit failure rolls the whole unlink back: the link still resolves and no session is revoked.
func TestUnlinkOIDCIdentityAuditFailureRollsBack(t *testing.T) {
	rig := newIdentityRig(t, "acme")
	ctx := context.Background()
	alice, _, err := rig.svc.CreateUser(ctx, rig.admin, "", "Alice", user.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	link, err := rig.svc.LinkOIDCIdentity(ctx, rig.admin, alice.ID, testIssuer, "sub-alice")
	if err != nil {
		t.Fatal(err)
	}
	rig.session(t, "acme", alice.ID, "hash-a")
	rig.audit.fail = true
	if _, err := rig.svc.UnlinkOIDCIdentity(ctx, rig.admin, alice.ID, link.ID); err == nil {
		t.Fatal("unlink succeeded without its audit record")
	}
	if _, err := rig.identities.GetExternalIdentity(shared.WithTenant(ctx, "acme"), testIssuer, "sub-alice"); err != nil {
		t.Fatalf("the link was removed despite the failed audit: %v", err)
	}
	if !rig.sessionActive(t, "acme", "hash-a") {
		t.Fatal("session revocation survived the failed unlink")
	}
}

// Unlink is confined like link: the configured OIDC tenant only, never the bootstrap operator, and
// only a link that belongs to the named user in this tenant.
func TestUnlinkOIDCIdentityIsNarrow(t *testing.T) {
	rig := newIdentityRig(t, "acme")
	ctx := context.Background()
	alice, _, err := rig.svc.CreateUser(ctx, rig.admin, "", "Alice", user.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	bob, _, err := rig.svc.CreateUser(ctx, rig.admin, "", "Bob", user.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	link, err := rig.svc.LinkOIDCIdentity(ctx, rig.admin, alice.ID, testIssuer, "sub-alice")
	if err != nil {
		t.Fatal(err)
	}
	otherAdmin, _, err := rig.svc.CreateUser(ctx, bootstrapActor, "globex", "Globex Admin", user.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		actor  Actor
		id     shared.ID
		linkID shared.ID
		want   error
	}{
		{"bootstrap user", rig.admin, BootstrapID, link.ID, shared.ErrForbidden},
		{"other tenant actor", adminActor(otherAdmin.ID.String(), "globex"), otherAdmin.ID, link.ID, shared.ErrForbidden},
		{"user in another tenant", rig.admin, otherAdmin.ID, link.ID, shared.ErrNotFound},
		{"link of another user", rig.admin, bob.ID, link.ID, shared.ErrNotFound},
		{"unknown link", rig.admin, alice.ID, "no-such-link", shared.ErrNotFound},
		{"empty link id", rig.admin, alice.ID, "", shared.ErrNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := rig.svc.UnlinkOIDCIdentity(ctx, tc.actor, tc.id, tc.linkID); !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
	if _, err := rig.identities.GetExternalIdentity(shared.WithTenant(ctx, "acme"), testIssuer, "sub-alice"); err != nil {
		t.Fatalf("a refused unlink removed the link: %v", err)
	}
	unconfigured, _ := newSvc(t)
	if _, err := unconfigured.UnlinkOIDCIdentity(ctx, rig.admin, alice.ID, link.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unlink without OIDC configuration: want ErrNotFound, got %v", err)
	}
}
