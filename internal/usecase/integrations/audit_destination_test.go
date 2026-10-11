package integrations

import (
	"context"
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

// Every integration audit entry records the actor and the destination masked to scheme://host
// (#1358); the endpoint path never reaches the audit log.
func TestIntegrationAuditRecordsMaskedDestination(t *testing.T) {
	ctx := context.Background()
	tenantID := shared.ID("tenant-1")
	clock := &integrationTestClock{now: time.Date(2026, 8, 31, 8, 0, 0, 0, time.UTC)}
	ids := idgen.RandomID{}
	cipher, err := vault.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	audit := &integrationTestAudit{}
	store := memory.NewIntegrationStore(memory.NewJobQueue(ids, clock.Now), cipher, clock, audit)
	registry := integration.NewRegistry()
	descriptor := integration.ProviderDescriptor{Provider: "fake-ci", Name: "Fake CI",
		SecretFields: []integration.FieldDescriptor{{Name: "token", Label: "Token", Kind: integration.FieldPassword, Required: true}}}
	if err := registry.Register(descriptor, func(integration.Integration, integration.CredentialBundle, selfhosted.Rules) (integration.Adapter, error) {
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, registry, memory.NewProjectRepository(), integrationTestMatcher{}, ids, clock)
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.Create(ctx, CreateInput{TenantID: tenantID, Provider: "fake-ci", Name: "CI", Endpoint: "https://CI.Example.com:8443/jenkins/p4th",
		Config: map[string]any{}, PollInterval: time.Minute, Actor: "ada"})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.SetCredential(ctx, tenantID, created.ID, map[string]string{"token": "s3cret-value"}, created.Version, created.ConnectionRevision, "ada"); err != nil {
		t.Fatal(err)
	}
	current, err := service.Get(ctx, tenantID, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Update(ctx, tenantID, created.ID, UpdateInput{Name: "CI", Endpoint: "https://ci2.example.org/p4th", Config: map[string]any{},
		PollInterval: time.Minute, Version: current.Version, Actor: "root"}); err != nil {
		t.Fatal(err)
	}
	current, err = service.Get(ctx, tenantID, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Archive(ctx, tenantID, created.ID, current.Version, "ada"); err != nil {
		t.Fatal(err)
	}

	want := map[string]struct{ actor, destination string }{
		"integration.created":             {"ada", "https://ci.example.com:8443"},
		"integration.credential_replaced": {"ada", "https://ci.example.com:8443"},
		"integration.updated":             {"root", "https://ci2.example.org"},
		"integration.archived":            {"ada", "https://ci2.example.org"},
	}
	seen := map[string]bool{}
	for _, entry := range audit.entries {
		for key, value := range entry.Metadata {
			if strings.Contains(value, "p4th") || strings.Contains(value, "s3cret") {
				t.Fatalf("%s metadata %s=%q leaks the endpoint path or secret", entry.Action, key, value)
			}
		}
		expected, ok := want[entry.Action]
		if !ok {
			continue
		}
		seen[entry.Action] = true
		if entry.Actor != expected.actor || entry.Metadata["destination"] != expected.destination {
			t.Fatalf("%s entry = actor %q metadata %v, want actor %q destination %q", entry.Action, entry.Actor, entry.Metadata, expected.actor, expected.destination)
		}
		if entry.Action == "integration.updated" && (entry.Metadata["destination_changed"] != "true" || entry.Metadata["previous_destination"] != "https://ci.example.com:8443") {
			t.Fatalf("host change entry = %v", entry.Metadata)
		}
	}
	for action := range want {
		if !seen[action] {
			t.Fatalf("no %s audit entry in %+v", action, audit.entries)
		}
	}
}
