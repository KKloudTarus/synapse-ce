package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
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
		if err := registry.Register(descriptor, func(item Integration, credentials CredentialBundle, _ selfhosted.Rules) (Adapter, error) {
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
	for _, key := range []string{"https://jenkins.example.com/job/a", "/job/../admin", "/"} {
		if _, err := CanonicalExternalKey(key); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("CanonicalExternalKey(%q) error = %v, want validation", key, err)
		}
	}
	if key, err := CanonicalExternalKey("/group/project/.github/workflows/release.yml"); err != nil || key != "/group/project/.github/workflows/release.yml" {
		t.Fatalf("provider-neutral key=%q err=%v", key, err)
	}
	if key, err := CanonicalExternalKey("/release/v1..v2"); err != nil || key != "/release/v1..v2" {
		t.Fatalf("benign double-dot key=%q err=%v", key, err)
	}
}

// The console renders ExternalRun.URL straight into an href (web/src/pages/Settings/Integrations.tsx).
// Normalize checked only its length, so the single thing keeping a javascript: URL out of an
// operator's browser was every adapter choosing to build the URL itself instead of passing through
// whatever the provider returned. The invariant belongs here, where every writer has to pass.
func TestExternalRunRejectsAURLThatIsNotAbsoluteHTTP(t *testing.T) {
	valid := func() ExternalRun {
		return ExternalRun{
			ID: "run", TenantID: "tenant", IntegrationID: "integration",
			PipelineKey: "pipeline", ProviderKey: "provider:build:1",
			Lifecycle: RunCompleted, Result: ResultSuccess,
			Correlation: CorrelationLinked, ProviderUpdatedAt: time.Unix(1700000000, 0).UTC(),
		}
	}
	for _, raw := range []string{
		"javascript:alert(document.domain)",
		"data:text/html,<script>alert(1)</script>",
		"vbscript:msgbox(1)",
		"file:///etc/passwd",
		"/builds/17", // relative: no scheme, no host
		"https://",   // absolute with no host
		"not a url at all",
	} {
		run := valid()
		run.URL = raw
		if err := run.Normalize(); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("url %q error = %v, want validation", raw, err)
		}
	}
	// A self-hosted Jenkins on an internal network serves plain http, so http stays admitted.
	for _, raw := range []string{
		"https://ci.example.test/job/build/17/",
		"http://jenkins.internal:8080/job/build/17/",
		"", // a run with no URL is ordinary: the provider did not give one
	} {
		run := valid()
		run.URL = raw
		if err := run.Normalize(); err != nil {
			t.Errorf("url %q must be accepted, got %v", raw, err)
		}
	}
}
