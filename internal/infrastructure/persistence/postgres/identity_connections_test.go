package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func bootstrapConnectionProof(tenant string, at time.Time) ports.IdentityAdminProof {
	p := authz.Principal{ActorID: authz.BootstrapActorID, TenantID: tenant, Credential: authz.Credential{Kind: authz.KindBootstrap, ID: "deployment"}}
	return ports.IdentityAdminProof{Principal: p, Bootstrap: &authz.BootstrapEligibility{Principal: p, VerifiedAt: at, ExpiresAt: at.Add(15 * time.Minute)}, At: at}
}

func TestIdentityConnectionDraftTestActivationAndTrustBoundary(t *testing.T) {
	f := newIdentityFixture(t)
	f.tenants(t, "connection-a", "connection-b")
	at := time.Now().UTC()
	proof := bootstrapConnectionProof("connection-a", at)
	draft := ports.IdentityConnectionDraft{TenantID: "connection-a", ID: "connection", DisplayName: "Workforce", Issuer: "https://issuer.example", Settings: ports.IdentityOIDCSettings{ClientID: "application", RedirectURL: "https://app.example/api/auth/enterprise/callback", SealedClientSecret: "test-ciphertext", Auth0OrganizationID: "org_CaseSensitive"}}
	c, err := f.store.SaveIdentityConnectionDraft(context.Background(), draft, proof)
	if err != nil {
		t.Fatal(err)
	}
	if c.Enabled || c.Revision != 1 || c.DraftRevision != 1 {
		t.Fatalf("draft=%+v", c)
	}
	if c.Settings.Auth0OrganizationID != "org_CaseSensitive" {
		t.Fatalf("stored organization id = %q", c.Settings.Auth0OrganizationID)
	}
	colliding := draft
	colliding.ID = "connection-colliding"
	if _, err = f.store.SaveIdentityConnectionDraft(context.Background(), colliding, proof); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("same issuer namespace collision = %v, want ErrConflict", err)
	}
	choices, err := f.store.ListIdentityConnections(context.Background(), "connection-a", true)
	if err != nil || len(choices) != 0 {
		t.Fatalf("draft login choices=%v error=%v", choices, err)
	}
	if _, err = f.store.ActivateIdentityConnection(context.Background(), "connection-a", c.ID, 1, c.Version, proof); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("untested activation=%v", err)
	}
	if err = f.store.RecordIdentityConnectionTest(context.Background(), ports.IdentityConnectionTest{ID: "too-long-test", TenantID: "connection-a", ConnectionID: c.ID, Revision: 1, Passed: true, At: at, ExpiresAt: at.Add(time.Hour + time.Nanosecond)}, proof); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("over-one-hour test lifetime=%v, want ErrValidation", err)
	}
	test := ports.IdentityConnectionTest{ID: "test-1", TenantID: "connection-a", ConnectionID: c.ID, Revision: 1, Passed: true, At: at, ExpiresAt: at.Add(time.Hour)}
	if err = f.store.RecordIdentityConnectionTest(context.Background(), test, proof); err != nil {
		t.Fatal(err)
	}
	c, err = f.store.ActivateIdentityConnection(context.Background(), "connection-a", c.ID, 1, c.Version, proof)
	if err != nil {
		t.Fatal(err)
	}
	choices, err = f.store.ListIdentityConnections(context.Background(), "connection-a", true)
	if err != nil || len(choices) != 1 {
		t.Fatalf("active choices=%v error=%v", choices, err)
	}
	draft.ExpectedVersion = c.Version
	draft.Settings.SealedClientSecret = "rotated-test-ciphertext"
	updated, err := f.store.SaveIdentityConnectionDraft(context.Background(), draft, proof)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Revision != 1 || updated.DraftRevision != 2 || updated.Epoch != c.Epoch {
		t.Fatalf("secret rotation changed active trust: %+v", updated)
	}
	// The operator view describes the current draft, not the previously active revision. An
	// expired newest successful test must not make that draft look ready for activation by
	// falling back to an older still-valid test.
	expiresAt := time.Now().UTC().Add(-time.Hour)
	// An upgraded deployment can encounter a persisted legacy row longer than the new
	// writer lifetime. Seed it through the fixture's admin channel rather than weakening
	// the writer validation that production callbacks use.
	f.exec(t, `INSERT INTO identity_connection_tests(tenant_id,id,connection_id,revision,state,tested_at,expires_at)
		VALUES($1,$2,$3,2,'passed',$4,$5)`, "connection-a", "older-valid-test", c.ID.String(), expiresAt.Add(-3*time.Hour), expiresAt.Add(2*time.Hour))
	if err = f.store.RecordIdentityConnectionTest(context.Background(), ports.IdentityConnectionTest{ID: "expired-test", TenantID: "connection-a", ConnectionID: c.ID, Revision: 2, Passed: true, At: expiresAt.Add(-time.Hour), ExpiresAt: expiresAt}, proof); err != nil {
		t.Fatal(err)
	}
	active, err := f.store.GetIdentityConnection(context.Background(), "connection-a", c.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !active.TestPassed {
		t.Fatalf("active connection lost its historical test after a draft update: %+v", active)
	}
	choices, err = f.store.ListIdentityConnections(context.Background(), "connection-a", true)
	if err != nil || len(choices) != 1 || !choices[0].TestPassed {
		t.Fatalf("eligible active choices=%+v error=%v", choices, err)
	}
	admin, err := f.store.ListIdentityConnections(context.Background(), "connection-a", false)
	if err != nil || len(admin) != 1 || admin[0].TestPassed {
		t.Fatalf("administrator draft projection=%+v error=%v", admin, err)
	}
	if _, err = f.store.ActivateIdentityConnection(context.Background(), "connection-a", c.ID, 2, updated.Version, proof); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale revision test used=%v", err)
	}
	draft.ExpectedVersion = updated.Version
	draft.Settings.ClientID = "different-application"
	if _, err = f.store.SaveIdentityConnectionDraft(context.Background(), draft, proof); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("client trust changed in place=%v", err)
	}
	issuerDraft := draft
	issuerDraft.Settings.ClientID = "application"
	issuerDraft.Issuer += "/"
	if _, err = f.store.SaveIdentityConnectionDraft(context.Background(), issuerDraft, proof); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("issuer trust changed in place=%v", err)
	}
	organizationDraft := draft
	organizationDraft.Settings.ClientID = "application"
	organizationDraft.Settings.Auth0OrganizationID = "org_Other"
	if _, err = f.store.SaveIdentityConnectionDraft(context.Background(), organizationDraft, proof); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("organization trust changed in place=%v", err)
	}
	organizationDraft.Settings.Auth0OrganizationID = ""
	if _, err = f.store.SaveIdentityConnectionDraft(context.Background(), organizationDraft, proof); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("organization trust removal in place=%v", err)
	}
	if _, err = f.store.GetIdentityConnection(context.Background(), "connection-b", c.ID, 0); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant connection=%v", err)
	}
	if n := f.adminCount(t, `SELECT count(*) FROM identity_sessions`); n != 0 {
		t.Fatalf("test issued %d sessions", n)
	}
	if n := f.adminCount(t, `SELECT count(*) FROM identity_memberships`); n != 0 {
		t.Fatalf("test created %d memberships", n)
	}
}

func TestIdentityConnectionLegacyTestLifetimeDoesNotExtendDraftAuthority(t *testing.T) {
	f := newIdentityFixture(t)
	const tenant = "connection-legacy-test-lifetime"
	f.tenants(t, tenant)
	var now time.Time
	if err := f.admin.QueryRow(context.Background(), `SELECT CURRENT_TIMESTAMP`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	proof := bootstrapConnectionProof(tenant, now)
	draft := ports.IdentityConnectionDraft{TenantID: tenant, ID: "connection", DisplayName: "Workforce", Issuer: "https://issuer.example", Settings: ports.IdentityOIDCSettings{ClientID: "application", RedirectURL: "https://app.example/api/auth/enterprise/callback", SealedClientSecret: "first-secret"}}
	connection, err := f.store.SaveIdentityConnectionDraft(context.Background(), draft, proof)
	if err != nil {
		t.Fatal(err)
	}
	// A legacy active revision may carry an expired test proof. Its existing active
	// login authority is historical and must not inherit the draft re-test deadline.
	activeTestedAt := now.Add(-2 * time.Hour)
	f.exec(t, `INSERT INTO identity_connection_tests(tenant_id,id,connection_id,revision,state,tested_at,expires_at)
		VALUES($1,'expired-active-test',$2,1,'passed',$3,$4)`, tenant, connection.ID.String(), activeTestedAt, activeTestedAt.Add(45*time.Minute))
	connection, err = f.store.ActivateIdentityConnection(context.Background(), tenant, connection.ID, 1, connection.Version, bootstrapConnectionProof(tenant, activeTestedAt.Add(30*time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	draft.ExpectedVersion = connection.Version
	draft.Settings.SealedClientSecret = "replacement-secret"
	updated, err := f.store.SaveIdentityConnectionDraft(context.Background(), draft, proof)
	if err != nil {
		t.Fatal(err)
	}
	legacyTestedAt := now.Add(-59 * time.Minute)
	f.exec(t, `INSERT INTO identity_connection_tests(tenant_id,id,connection_id,revision,state,tested_at,expires_at)
		VALUES($1,'legacy-long-test',$2,2,'passed',$3,$4)`, tenant, connection.ID.String(), legacyTestedAt, now.Add(24*time.Hour))

	admin, err := f.store.ListIdentityConnections(context.Background(), tenant, false)
	if err != nil || len(admin) != 1 || !admin[0].TestPassed {
		t.Fatalf("legacy test just before one hour status=%+v error=%v", admin, err)
	}
	boundary := legacyTestedAt.Add(time.Hour)
	if _, err = f.store.ActivateIdentityConnection(context.Background(), tenant, connection.ID, 2, updated.Version, bootstrapConnectionProof(tenant, boundary)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("legacy test at one-hour boundary activated draft: %v", err)
	}
	active, err := f.store.GetIdentityConnection(context.Background(), tenant, connection.ID, 0)
	if err != nil || active.Revision != 1 || !active.Enabled || !active.TestPassed {
		t.Fatalf("expired draft changed active login authority=%+v error=%v", active, err)
	}
	choices, err := f.store.ListIdentityConnections(context.Background(), tenant, true)
	if err != nil || len(choices) != 1 || !choices[0].TestPassed {
		t.Fatalf("expired draft changed eligible active login choices=%+v error=%v", choices, err)
	}

	// A shorter explicit expiry must win even while the one-hour lifetime has not elapsed.
	f.exec(t, `INSERT INTO identity_connection_tests(tenant_id,id,connection_id,revision,state,tested_at,expires_at)
		VALUES($1,'short-explicit-expiry',$2,2,'passed',$3,$4)`, tenant, connection.ID.String(), now.Add(-58*time.Minute), now.Add(-time.Minute))
	admin, err = f.store.ListIdentityConnections(context.Background(), tenant, false)
	if err != nil || len(admin) != 1 || admin[0].TestPassed {
		t.Fatalf("short explicit expiry was ignored: %+v error=%v", admin, err)
	}
	// The most recent failed test must not fall back to an older successful result.
	f.exec(t, `INSERT INTO identity_connection_tests(tenant_id,id,connection_id,revision,state,tested_at,expires_at)
		VALUES($1,'latest-failed-test',$2,2,'failed',$3,$4)`, tenant, connection.ID.String(), now.Add(-57*time.Minute), now.Add(24*time.Hour))
	admin, err = f.store.ListIdentityConnections(context.Background(), tenant, false)
	if err != nil || len(admin) != 1 || admin[0].TestPassed {
		t.Fatalf("latest failed test fell back to prior success: %+v error=%v", admin, err)
	}

	// A distinct unactivated draft preserves the append-only test history while
	// checking a legacy passed row whose explicit expiry remains far in the future.
	agedDraft := draft
	agedDraft.ID = "aged-connection"
	agedDraft.Issuer = "https://issuer-legacy.example"
	agedDraft.ExpectedVersion = 0
	aged, err := f.store.SaveIdentityConnectionDraft(context.Background(), agedDraft, proof)
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, `INSERT INTO identity_connection_tests(tenant_id,id,connection_id,revision,state,tested_at,expires_at)
		VALUES($1,'aged-legacy-long-test',$2,1,'passed',$3,$4)`, tenant, aged.ID.String(), now.Add(-time.Hour-time.Second), now.Add(24*time.Hour))
	admin, err = f.store.ListIdentityConnections(context.Background(), tenant, false)
	if err != nil || len(admin) != 2 {
		t.Fatalf("aged legacy draft list=%+v error=%v", admin, err)
	}
	foundAged := false
	for _, candidate := range admin {
		if candidate.ID == aged.ID {
			foundAged = true
			if candidate.TestPassed {
				t.Fatalf("aged legacy test extended current draft authority: %+v", candidate)
			}
		}
	}
	if !foundAged {
		t.Fatalf("aged legacy draft missing from administrator list: %+v", admin)
	}
}

func TestIdentityConnectionRestrictionCannotBeAddedToExistingUnrestrictedConnection(t *testing.T) {
	f := newIdentityFixture(t)
	const tenant = "connection-unrestricted"
	f.tenants(t, tenant)
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	proof := bootstrapConnectionProof(tenant, at)
	draft := ports.IdentityConnectionDraft{TenantID: tenant, ID: "connection", DisplayName: "Workforce", Issuer: "https://issuer.example", Settings: ports.IdentityOIDCSettings{ClientID: "application", RedirectURL: "https://app.example/api/auth/enterprise/callback", SealedClientSecret: "test-ciphertext"}}
	created, err := f.store.SaveIdentityConnectionDraft(context.Background(), draft, proof)
	if err != nil {
		t.Fatal(err)
	}
	candidate := draft
	candidate.ExpectedVersion = created.Version
	candidate.Settings.Auth0OrganizationID = "org_CaseSensitive"
	if _, err = f.store.SaveIdentityConnectionDraft(context.Background(), candidate, proof); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("adding organization restriction in place = %v, want ErrConflict", err)
	}
	current, err := f.store.GetIdentityConnection(context.Background(), tenant, created.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if current.Settings != draft.Settings || current.SettingsRevision != created.SettingsRevision || current.Revision != created.Revision || current.DraftRevision != created.DraftRevision || current.Version != created.Version {
		t.Fatalf("immutable connection changed after rejected restriction: %+v", current)
	}
	if revisions := f.adminCount(t, `SELECT count(*) FROM identity_connection_revisions WHERE tenant_id=$1 AND connection_id=$2`, tenant, created.ID.String()); revisions != 1 {
		t.Fatalf("revisions after rejected restriction = %d, want 1", revisions)
	}
}

func TestIdentityConnectionRequiresExplicitBootstrapProof(t *testing.T) {
	f := newIdentityFixture(t)
	f.tenants(t, "admin-boundary")
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p := bootstrapConnectionProof("admin-boundary", at)
	d := ports.IdentityConnectionDraft{TenantID: "admin-boundary", ID: "connection", DisplayName: "SSO", Issuer: "https://issuer.example", Settings: ports.IdentityOIDCSettings{ClientID: "app", RedirectURL: "https://app.example/callback", SealedClientSecret: "sealed"}}
	for _, name := range []string{"no eligibility", "expired eligibility", "different tenant", "ordinary member", "recovery"} {
		t.Run(name, func(t *testing.T) {
			proof := p
			e := *p.Bootstrap
			proof.Bootstrap = &e
			switch name {
			case "no eligibility":
				proof.Bootstrap = nil
			case "expired eligibility":
				proof.At = at.Add(15 * time.Minute)
			case "different tenant":
				proof.Principal.TenantID = "other"
			case "ordinary member":
				proof.Principal.ActorID = "member"
				proof.Principal.Credential.Kind = authz.KindBrowserSession
			case "recovery":
				proof.Principal.ActorID = "member"
				proof.Principal.Credential.Kind = authz.KindBreakGlass
			}
			if _, err := f.store.SaveIdentityConnectionDraft(context.Background(), d, proof); !errors.Is(err, shared.ErrForbidden) {
				t.Fatalf("administration allowed: %v", err)
			}
		})
	}
	if n := f.adminCount(t, `SELECT count(*) FROM identity_connections`); n != 0 {
		t.Fatalf("denied administration created %d connections", n)
	}
}
