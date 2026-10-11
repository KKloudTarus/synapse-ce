package integrations

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
)

func newSelfHostedTestService(t *testing.T, rules selfhosted.Rules) *Service {
	t.Helper()
	clock := &integrationTestClock{now: time.Date(2026, 9, 27, 8, 0, 0, 0, time.UTC)}
	ids := idgen.RandomID{}
	cipher, err := vault.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	store := memory.NewIntegrationStore(memory.NewJobQueue(ids, clock.Now), cipher, clock, &integrationTestAudit{})
	registry := integration.NewRegistry()
	for _, descriptor := range []integration.ProviderDescriptor{
		{Provider: "fake-ci", Name: "Fake CI", SelfHosted: true},
		{Provider: "saas-ci", Name: "SaaS CI"},
	} {
		if err := registry.Register(descriptor, func(integration.Integration, integration.CredentialBundle, selfhosted.Rules) (integration.Adapter, error) {
			return nil, nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	registry.SetSelfHostedRules(rules)
	service, err := NewService(store, registry, memory.NewProjectRepository(), integrationTestMatcher{}, ids, clock)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func selfHostedCreateInput(endpoint string, requestPrivate bool) CreateInput {
	return CreateInput{
		TenantID: "tenant-1", Provider: "fake-ci", Name: "CI", Endpoint: endpoint, Config: map[string]any{},
		AllowPrivateNetwork: requestPrivate, PollInterval: time.Minute, Actor: "admin",
	}
}

func allowlistRules(t *testing.T, entries ...string) selfhosted.Rules {
	t.Helper()
	hosts, err := selfhosted.ParseHostAllowlist(entries)
	if err != nil {
		t.Fatal(err)
	}
	return selfhosted.Rules{Hosts: hosts}
}

func TestCreateRefusesHostsOutsideTheOperatorAllowlist(t *testing.T) {
	service := newSelfHostedTestService(t, allowlistRules(t, "jenkins.corp.example"))
	ctx := context.Background()

	_, err := service.Create(ctx, selfHostedCreateInput("https://attacker.example/secret-path", false))
	if !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), `"attacker.example"`) || strings.Contains(err.Error(), "secret-path") {
		t.Fatalf("off-allowlist create: err = %v", err)
	}
	if _, err := service.Create(ctx, selfHostedCreateInput("https://JENKINS.corp.example/ci", false)); err != nil {
		t.Fatalf("allowlisted create: %v", err)
	}
}

func TestUpdateRefusesMovingToAHostOutsideTheAllowlist(t *testing.T) {
	service := newSelfHostedTestService(t, allowlistRules(t, "jenkins.corp.example"))
	ctx := context.Background()
	created, err := service.Create(ctx, selfHostedCreateInput("https://jenkins.corp.example", false))
	if err != nil {
		t.Fatal(err)
	}
	update := UpdateInput{Name: "CI", Endpoint: "https://attacker.example", Config: map[string]any{}, PollInterval: time.Minute, Version: created.Version, Actor: "admin"}
	if _, err := service.Update(ctx, created.TenantID, created.ID, update); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("off-allowlist update: err = %v", err)
	}
	stored, err := service.Get(ctx, created.TenantID, created.ID)
	if err != nil || stored.Endpoint != "https://jenkins.corp.example" {
		t.Fatalf("refused update changed the endpoint: %+v err=%v", stored, err)
	}
}

func TestCreateRefusesPrivateLiteralsOutsidePrivateCIDRs(t *testing.T) {
	rules := selfhosted.Rules{AllowPrivateNetwork: true, PrivateCIDRs: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}}
	service := newSelfHostedTestService(t, rules)
	ctx := context.Background()
	if _, err := service.Create(ctx, selfHostedCreateInput("https://10.30.0.5", true)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("private literal outside CIDRs: err = %v", err)
	}
	if _, err := service.Create(ctx, selfHostedCreateInput("https://10.20.0.5", true)); err != nil {
		t.Fatalf("private literal inside CIDRs: %v", err)
	}
}

func TestSaaSProvidersIgnoreTheHostAllowlistButNotThePrivateSwitch(t *testing.T) {
	service := newSelfHostedTestService(t, allowlistRules(t, "jenkins.corp.example"))
	ctx := context.Background()
	input := selfHostedCreateInput("https://ci.vendor.example/org", false)
	input.Provider = "saas-ci"
	if _, err := service.Create(ctx, input); err != nil {
		t.Fatalf("SaaS provider refused by the self-hosted allowlist: %v", err)
	}
	input.Name, input.AllowPrivateNetwork = "private SaaS", true
	if _, err := service.Create(ctx, input); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("private-network request with the operator switch off: err = %v", err)
	}
}
