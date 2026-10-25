package oidc

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type factoryProtector struct{}

func (factoryProtector) Seal(context.Context, []byte, []byte) (string, error) { return "", nil }
func (factoryProtector) Open(context.Context, string, []byte) ([]byte, error) {
	return []byte("secret"), nil
}

func TestConnectionFactoryPropagatesAuth0OrganizationRestrictionBySettingsRevision(t *testing.T) {
	factory, err := NewConnectionFactory(factoryProtector{}, "https://synapse.example/callback")
	if err != nil {
		t.Fatal(err)
	}
	connection := ports.IdentityConnection{TenantID: shared.ID("tenant"), ID: shared.ID("connection"), Issuer: "https://issuer.example", Revision: 1, SettingsRevision: 2, Settings: ports.IdentityOIDCSettings{ClientID: "client", RedirectURL: "https://synapse.example/callback", SealedClientSecret: "sealed", Auth0OrganizationID: "org_CaseSensitive"}}
	provider, err := factory.ProviderForConnection(t.Context(), connection)
	if err != nil {
		t.Fatal(err)
	}
	concrete, ok := provider.(*Provider)
	if !ok || concrete.cfg.Auth0OrganizationID != "org_CaseSensitive" {
		t.Fatalf("provider = %#v", provider)
	}
	connection.Settings.Auth0OrganizationID = "org_Other"
	provider, err = factory.ProviderForConnection(t.Context(), connection)
	if err != nil {
		t.Fatal(err)
	}
	if provider != concrete {
		t.Fatal("factory cache key changed from tenant/connection/settings revision")
	}
}
