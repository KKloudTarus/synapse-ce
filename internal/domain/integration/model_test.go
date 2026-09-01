package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type registryTestAdapter struct{ descriptor ProviderDescriptor }

func (adapter registryTestAdapter) Descriptor() ProviderDescriptor { return adapter.descriptor }
func (registryTestAdapter) TestConnection(context.Context) error   { return nil }

func TestDecodeConfigRejectsTrailingJSONAndExcessiveDepth(t *testing.T) {
	if _, err := DecodeConfig([]byte(`{"enabled":true} {"extra":true}`)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("trailing JSON error = %v, want validation", err)
	}
	if _, err := DecodeConfig([]byte(`{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":true}}}}}}}}}`)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("deep JSON error = %v, want validation", err)
	}
}

func TestRegistryResolvesSecondProviderWithoutCoreSwitches(t *testing.T) {
	registry := NewRegistry()
	for _, provider := range []Provider{"jenkins", "fake-ci"} {
		descriptor := ProviderDescriptor{Provider: provider, Name: string(provider), Capabilities: []Capability{CapabilityTestConnection}}
		if err := registry.Register(descriptor, func(item Integration, credentials CredentialBundle) (Adapter, error) {
			if credentials["token"] != "secret" {
				t.Fatalf("factory credentials = %#v", credentials)
			}
			return registryTestAdapter{descriptor: descriptor}, nil
		}); err != nil {
			t.Fatalf("register %s: %v", provider, err)
		}
	}
	item := Integration{
		ID: "integration-1", TenantID: "tenant-1", Provider: "fake-ci", Name: "Fake CI", Endpoint: "https://ci.example.com",
		Config: []byte(`{}`), PollInterval: time.Minute, Version: 1, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	adapter, err := registry.Resolve(item, CredentialBundle{"token": "secret"})
	if err != nil {
		t.Fatalf("resolve second provider: %v", err)
	}
	if adapter.Descriptor().Provider != "fake-ci" {
		t.Fatalf("resolved provider = %q", adapter.Descriptor().Provider)
	}
	if got := registry.Descriptors(); len(got) != 2 || got[0].Provider != "fake-ci" || got[1].Provider != "jenkins" {
		t.Fatalf("sorted descriptors = %#v", got)
	}
}

func TestCanonicalEndpointAndExternalKeyFailClosed(t *testing.T) {
	for _, endpoint := range []string{"http://jenkins.example.com", "https://user:pass@jenkins.example.com", "https://jenkins.example.com?token=x"} {
		if _, err := CanonicalEndpoint(endpoint); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("CanonicalEndpoint(%q) error = %v, want validation", endpoint, err)
		}
	}
	for _, key := range []string{"https://jenkins.example.com/job/a", "/job/../admin", "/not-a-job"} {
		if _, err := CanonicalExternalKey(key); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("CanonicalExternalKey(%q) error = %v, want validation", key, err)
		}
	}
}
