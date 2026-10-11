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
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	proof := bootstrapConnectionProof("connection-a", at)
	draft := ports.IdentityConnectionDraft{TenantID: "connection-a", ID: "connection", DisplayName: "Workforce", Issuer: "https://issuer.example", Settings: ports.IdentityOIDCSettings{ClientID: "application", RedirectURL: "https://app.example/api/auth/enterprise/callback", SealedClientSecret: "test-ciphertext"}}
	c, err := f.store.SaveIdentityConnectionDraft(context.Background(), draft, proof)
	if err != nil {
		t.Fatal(err)
	}
	if c.Enabled || c.Revision != 1 || c.DraftRevision != 1 {
		t.Fatalf("draft=%+v", c)
	}
	choices, err := f.store.ListIdentityConnections(context.Background(), "connection-a", true)
	if err != nil || len(choices) != 0 {
		t.Fatalf("draft login choices=%v error=%v", choices, err)
	}
	if _, err = f.store.ActivateIdentityConnection(context.Background(), "connection-a", c.ID, 1, c.Version, proof); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("untested activation=%v", err)
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
	if _, err = f.store.ActivateIdentityConnection(context.Background(), "connection-a", c.ID, 2, updated.Version, proof); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale revision test used=%v", err)
	}
	draft.ExpectedVersion = updated.Version
	draft.Settings.ClientID = "different-application"
	if _, err = f.store.SaveIdentityConnectionDraft(context.Background(), draft, proof); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("client trust changed in place=%v", err)
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
