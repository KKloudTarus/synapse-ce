package integration

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestResolveAppliesSelfHostedRulesBeforeTheFactory(t *testing.T) {
	registry := NewRegistry()
	descriptor := ProviderDescriptor{Provider: "fake-ci", Name: "Fake CI", Capabilities: []Capability{CapabilityTestConnection}, SelfHosted: true}
	var built int
	var received selfhosted.Rules
	if err := registry.Register(descriptor, func(_ Integration, _ CredentialBundle, rules selfhosted.Rules) (Adapter, error) {
		built++
		received = rules
		return registryTestAdapter{descriptor: descriptor}, nil
	}); err != nil {
		t.Fatal(err)
	}
	hosts, err := selfhosted.ParseHostAllowlist([]string{"ci.corp.example"})
	if err != nil {
		t.Fatal(err)
	}
	registry.SetSelfHostedRules(selfhosted.Rules{Hosts: hosts})
	item := Integration{
		ID: "integration-1", TenantID: "tenant-1", Provider: "fake-ci", Name: "Fake CI", Endpoint: "https://old.example",
		Config: []byte(`{}`), PollInterval: time.Minute, Version: 1, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}

	// Saved before the allowlist was set: refused without building an adapter.
	if _, err := registry.Resolve(item, CredentialBundle{}); !errors.Is(err, shared.ErrValidation) || built != 0 {
		t.Fatalf("off-allowlist resolve: err=%v built=%d", err, built)
	}

	item.Endpoint = "https://ci.corp.example"
	if _, err := registry.Resolve(item, CredentialBundle{}); err != nil {
		t.Fatalf("allowlisted resolve: %v", err)
	}
	if built != 1 || received.Hosts.Empty() || !received.Hosts.Permits("ci.corp.example", "443") {
		t.Fatalf("factory did not receive the operator rules: built=%d rules=%+v", built, received)
	}
}

// A SaaS provider pins its vendor host in its adapter; the operator's self-hosted allowlist must
// not refuse it, or listing one Jenkins host would switch off every SaaS integration.
func TestResolveLeavesSaaSProvidersToTheirOwnHostPin(t *testing.T) {
	registry := NewRegistry()
	descriptor := ProviderDescriptor{Provider: "saas-ci", Name: "SaaS CI", Capabilities: []Capability{CapabilityTestConnection}}
	if err := registry.Register(descriptor, func(Integration, CredentialBundle, selfhosted.Rules) (Adapter, error) {
		return registryTestAdapter{descriptor: descriptor}, nil
	}); err != nil {
		t.Fatal(err)
	}
	hosts, err := selfhosted.ParseHostAllowlist([]string{"jenkins.corp.example"})
	if err != nil {
		t.Fatal(err)
	}
	registry.SetSelfHostedRules(selfhosted.Rules{Hosts: hosts})
	item := Integration{
		ID: "integration-1", TenantID: "tenant-1", Provider: "saas-ci", Name: "SaaS CI", Endpoint: "https://ci.vendor.example/org",
		Config: []byte(`{}`), PollInterval: time.Minute, Version: 1, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	if _, err := registry.Resolve(item, CredentialBundle{}); err != nil {
		t.Fatalf("SaaS provider refused by the self-hosted allowlist: %v", err)
	}
}
