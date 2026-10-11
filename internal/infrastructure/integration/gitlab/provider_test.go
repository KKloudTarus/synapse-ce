package gitlab

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
)

func TestRegisterInboundOnlyProvider(t *testing.T) {
	registry := integration.NewRegistry()
	if err := Register(registry); err != nil {
		t.Fatal(err)
	}
	got, err := registry.Descriptor(Provider)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Capabilities) != 0 {
		t.Fatalf("GitLab inbound provider capabilities = %v, want none", got.Capabilities)
	}
	if len(got.SecretFields) != 0 {
		t.Fatalf("GitLab inbound provider secret fields = %v, want none", got.SecretFields)
	}
}

func TestNewAcceptsNoCredentialAndNoOutboundCapability(t *testing.T) {
	item := integration.Integration{
		ID: "gitlab-inbound", TenantID: "tenant", Provider: Provider,
		Name: "GitLab inbound", Endpoint: "https://gitlab.example.com",
		Version: 1, ConnectionRevision: 1,
	}
	adapter, err := New(item, integration.CredentialBundle{}, selfhosted.Rules{})
	if err != nil {
		t.Fatal(err)
	}
	if adapter.Descriptor().Provider != Provider {
		t.Fatalf("provider = %q, want %q", adapter.Descriptor().Provider, Provider)
	}
	if _, err := New(item, integration.CredentialBundle{"token":"must-not-be-stored-here"}, selfhosted.Rules{}); err == nil {
		t.Fatal("GitLab inbound provider accepted an integration credential")
	}
}
