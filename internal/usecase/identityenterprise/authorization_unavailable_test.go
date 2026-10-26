package identityenterprise

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type unavailableAuthorizationProvider struct {
	authProvider
	err error
}

func (p unavailableAuthorizationProvider) AuthorizationURLWithMaxAge(context.Context, string, string, string, time.Duration) (string, error) {
	return "", p.err
}

type unavailableAuthorizationFactory struct {
	providerError error
	factoryError  error
}

func (f unavailableAuthorizationFactory) ProviderForConnection(context.Context, ports.IdentityConnection) (ports.OIDCProvider, error) {
	return unavailableAuthorizationProvider{err: f.providerError}, f.factoryError
}

type unavailableCallbackProvider struct {
	authProvider
	err error
}

func (p unavailableCallbackProvider) ExchangeAndVerifyWithMaxAge(context.Context, string, string, string, time.Duration) (ports.OIDCIdentity, error) {
	return ports.OIDCIdentity{}, p.err
}

type unavailableCallbackFactory struct{ err error }

func (f unavailableCallbackFactory) ProviderForConnection(context.Context, ports.IdentityConnection) (ports.OIDCProvider, error) {
	return unavailableCallbackProvider{err: f.err}, nil
}

func TestBeginProviderFailureIsUnavailableWithoutSuccessfulAuthorization(t *testing.T) {
	for _, purpose := range []ports.IdentityAuthorizationPurpose{ports.IdentityAuthorizationLogin, ports.IdentityAuthorizationLink, ports.IdentityAuthorizationStepUp, ports.IdentityAuthorizationSwitch} {
		t.Run(string(purpose), func(t *testing.T) {
			cause := errors.New("provider discovery unavailable")
			service, err := NewService(authConnections{}, &authTransactions{}, unavailableAuthorizationFactory{providerError: cause}, authProtector{}, authClock{time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}, &authIDs{})
			if err != nil {
				t.Fatal(err)
			}
			result, err := service.Begin(t.Context(), BeginInput{TenantID: "tenant", ConnectionID: "connection", Revision: 1, Purpose: purpose, CallerNonce: "browser"})
			if !errors.Is(err, authz.ErrAuthenticationUnavailable) || !errors.Is(err, cause) {
				t.Fatalf("provider failure lost availability class or cause: %v", err)
			}
			if result != (BeginResult{}) {
				t.Fatal("failed provider returned a successful authorization")
			}
		})
	}
}

func TestBeginProviderFactoryDenialRemainsForbidden(t *testing.T) {
	service, err := NewService(authConnections{}, &authTransactions{}, unavailableAuthorizationFactory{factoryError: shared.ErrForbidden}, authProtector{}, authClock{time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}, &authIDs{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Begin(t.Context(), BeginInput{TenantID: "tenant", ConnectionID: "connection", Revision: 1, Purpose: ports.IdentityAuthorizationLink, CallerNonce: "browser"})
	if !errors.Is(err, shared.ErrForbidden) || errors.Is(err, authz.ErrAuthenticationUnavailable) || result != (BeginResult{}) {
		t.Fatalf("provider factory denial was reclassified: %v", err)
	}
}

func TestCallbackUnavailableProviderPreservesCauseAndBurnsState(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC)
	cause := errors.New("token endpoint returned 503")
	transactions := &authTransactions{}
	service, err := NewService(authConnections{}, transactions, unavailableCallbackFactory{err: fmt.Errorf("%w: %w", authz.ErrAuthenticationUnavailable, cause)}, authProtector{}, authClock{now}, &authIDs{})
	if err != nil {
		t.Fatal(err)
	}
	started, err := service.Begin(t.Context(), BeginInput{TenantID: "tenant", ConnectionID: "connection", Revision: 1, Purpose: ports.IdentityAuthorizationLogin, CallerNonce: "browser"})
	if err != nil {
		t.Fatal(err)
	}
	state := started.AuthorizationURL[len("https://issuer.example/auth?state="):]
	_, err = service.Callback(t.Context(), CallbackInput{TenantID: "tenant", State: state, Code: "code", CallerNonce: "browser"})
	if !errors.Is(err, authz.ErrAuthenticationUnavailable) || !errors.Is(err, cause) {
		t.Fatalf("callback lost unavailable class or cause: %v", err)
	}
	if !transactions.consumed {
		t.Fatal("token endpoint outage did not consume callback state")
	}
	if _, err = service.Callback(t.Context(), CallbackInput{TenantID: "tenant", State: state, Code: "code", CallerNonce: "browser"}); err == nil || errors.Is(err, authz.ErrAuthenticationUnavailable) {
		t.Fatalf("consumed outage state was reusable or retained availability error: %v", err)
	}
}
