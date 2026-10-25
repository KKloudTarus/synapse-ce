package identityenterprise

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func bindingTestProof(now time.Time, id string) *ports.IdentityAdminProof {
	p := authz.Principal{ActorID: authz.BootstrapActorID, TenantID: "tenant", Role: user.RoleAdmin, Credential: authz.Credential{Kind: authz.KindBootstrap, ID: id}}
	return &ports.IdentityAdminProof{Principal: p, At: now, Bootstrap: &authz.BootstrapEligibility{Principal: p, VerifiedAt: now, ExpiresAt: now.Add(15 * time.Minute)}}
}

func bindingTestService(t *testing.T, id string, connections *testRecordingConnections, transactions *authTransactions, clock ports.Clock, factory ports.IdentityOIDCProviderFactory) *Service {
	t.Helper()
	s, err := NewService(connections, transactions, factory, authProtector{}, clock, &authIDs{})
	if err != nil {
		t.Fatal(err)
	}
	if id != "" {
		if err := s.SetBootstrapCredentialID(id); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func TestBootstrapTestBeginRequiresCurrentCredentialBinding(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC)
	for _, tc := range []struct {
		name       string
		configured string
		change     func(*ports.IdentityAdminProof)
	}{
		{"unconfigured", "", func(*ports.IdentityAdminProof) {}},
		{"missing credential id", "current", func(p *ports.IdentityAdminProof) { p.Principal.Credential.ID = "" }},
		{"replaced credential", "replacement", func(*ports.IdentityAdminProof) {}},
		{"missing eligibility", "current", func(p *ports.IdentityAdminProof) { p.Bootstrap = nil }},
		{"expired eligibility", "current", func(p *ports.IdentityAdminProof) { p.Bootstrap.ExpiresAt = now }},
		{"different eligibility principal", "current", func(p *ports.IdentityAdminProof) { p.Bootstrap.Principal.Credential.ID = "foreign" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := &authTransactions{}
			s := bindingTestService(t, tc.configured, &testRecordingConnections{}, tx, authClock{now}, authFactory{})
			proof := bindingTestProof(now, "current")
			tc.change(proof)
			_, err := s.Begin(t.Context(), BeginInput{TenantID: "tenant", ConnectionID: "connection", Revision: 1, Purpose: ports.IdentityAuthorizationTest, CallerNonce: "browser", AdminProof: proof})
			if !errors.Is(err, shared.ErrForbidden) {
				t.Fatalf("unbound bootstrap Test was not refused: %v", err)
			}
			if !tx.v.ID.IsZero() {
				t.Fatal("invalid bootstrap proof created a protocol transaction")
			}
		})
	}
}

func TestBootstrapTestCallbackRevalidatesCurrentCredentialAfterRestart(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC)
	for _, id := range []string{"current", "replacement", ""} {
		t.Run("callback binding "+id, func(t *testing.T) {
			connections, tx := &testRecordingConnections{}, &authTransactions{}
			before := bindingTestService(t, "current", connections, tx, authClock{now}, authFactory{})
			start, err := before.Begin(t.Context(), BeginInput{TenantID: "tenant", ConnectionID: "connection", Revision: 1, Purpose: ports.IdentityAuthorizationTest, CallerNonce: "browser", AdminProof: bindingTestProof(now, "current")})
			if err != nil {
				t.Fatal(err)
			}
			after := bindingTestService(t, id, connections, tx, authClock{now}, authFactory{})
			state := strings.TrimPrefix(start.AuthorizationURL, "https://issuer.example/auth?state=")
			_, err = after.Callback(t.Context(), CallbackInput{TenantID: "tenant", State: state, Code: "code", CallerNonce: "browser"})
			if id == "current" {
				if err != nil || connections.tests != 1 {
					t.Fatalf("unchanged credential could not finish native Test: %v, tests=%d", err, connections.tests)
				}
			} else if !errors.Is(err, shared.ErrForbidden) || connections.tests != 0 {
				t.Fatalf("replaced or missing callback binding recorded proof: %v, tests=%d", err, connections.tests)
			}
			if !tx.consumed {
				t.Fatal("callback did not burn its one-use state")
			}
		})
	}
}

func TestBootstrapTestCallbackRecordsOneHourTestLifetime(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC)
	connections, tx := &testRecordingConnections{}, &authTransactions{}
	s := bindingTestService(t, "current", connections, tx, authClock{now}, authFactory{})
	started, err := s.Begin(t.Context(), BeginInput{
		TenantID: "tenant", ConnectionID: "connection", Revision: 1,
		Purpose: ports.IdentityAuthorizationTest, CallerNonce: "browser",
		AdminProof: bindingTestProof(now, "current"),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Callback(t.Context(), CallbackInput{
		TenantID: "tenant", State: strings.TrimPrefix(started.AuthorizationURL, "https://issuer.example/auth?state="),
		Code: "code", CallerNonce: "browser",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(connections.recorded) != 1 || !connections.recorded[0].ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("recorded test=%+v, want exactly one-hour lifetime from %s", connections.recorded, now)
	}
}

type bindingClock struct{ at time.Time }

func (c *bindingClock) Now() time.Time { return c.at }

type delayedBindingProvider struct {
	authProvider
	clock *bindingClock
}

func (p delayedBindingProvider) ExchangeAndVerifyWithMaxAge(ctx context.Context, code, verifier, nonce string, age time.Duration) (ports.OIDCIdentity, error) {
	p.clock.at = p.clock.at.Add(2 * time.Second)
	return p.authProvider.ExchangeAndVerifyWithMaxAge(ctx, code, verifier, nonce, age)
}

type delayedBindingFactory struct{ clock *bindingClock }

func (f delayedBindingFactory) ProviderForConnection(context.Context, ports.IdentityConnection) (ports.OIDCProvider, error) {
	return delayedBindingProvider{clock: f.clock}, nil
}

func TestBootstrapTestCallbackRejectsEligibilityExpiringDuringProviderExchange(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC)
	clock := &bindingClock{at: now}
	connections, tx := &testRecordingConnections{}, &authTransactions{}
	s := bindingTestService(t, "current", connections, tx, clock, delayedBindingFactory{clock: clock})
	proof := bindingTestProof(now, "current")
	proof.Bootstrap.ExpiresAt = now.Add(time.Second)
	start, err := s.Begin(t.Context(), BeginInput{TenantID: "tenant", ConnectionID: "connection", Revision: 1, Purpose: ports.IdentityAuthorizationTest, CallerNonce: "browser", AdminProof: proof})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Callback(t.Context(), CallbackInput{TenantID: "tenant", State: strings.TrimPrefix(start.AuthorizationURL, "https://issuer.example/auth?state="), Code: "code", CallerNonce: "browser"})
	if !errors.Is(err, shared.ErrForbidden) || connections.tests != 0 {
		t.Fatalf("expired callback proof recorded success: %v, tests=%d", err, connections.tests)
	}
}

func TestBootstrapCredentialBindingConfigurationCannotBeEmptyOrChanged(t *testing.T) {
	s := bindingTestService(t, "current", &testRecordingConnections{}, &authTransactions{}, authClock{}, authFactory{})
	for _, id := range []string{"", " current", strings.Repeat("x", 257), "replacement"} {
		if err := s.SetBootstrapCredentialID(id); err == nil {
			t.Fatal("invalid or changed process binding accepted")
		}
	}
	if err := s.SetBootstrapCredentialID("current"); err != nil {
		t.Fatal(err)
	}
}
