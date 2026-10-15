package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type ticketProviderTestAdapter struct {
	descriptor integration.ProviderDescriptor
}

func (a ticketProviderTestAdapter) Descriptor() integration.ProviderDescriptor { return a.descriptor }
func (ticketProviderTestAdapter) DiscoverTickets(context.Context, string, string, string) (ports.TicketMetadata, error) {
	return ports.TicketMetadata{}, nil
}
func (ticketProviderTestAdapter) FormatTicketDescription(value string, _ []ports.RenderedLink) (json.RawMessage, error) {
	return json.Marshal(value)
}
func (ticketProviderTestAdapter) ValidateTicketPayload(json.RawMessage) error { return nil }
func (ticketProviderTestAdapter) CreateTicket(context.Context, json.RawMessage) (ticketing.RemoteTicket, error) {
	return ticketing.RemoteTicket{}, nil
}
func (ticketProviderTestAdapter) SearchTicketMarker(context.Context, string, string, string) ([]ticketing.RemoteTicket, error) {
	return nil, nil
}

func TestTicketProviderRefusesDispatchWhenCurrentIntegrationWasDisabled(t *testing.T) {
	clock := &integrationTestClock{now: time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)}
	ids := idgen.RandomID{}
	cipher, err := vault.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	audit := &integrationTestAudit{}
	store := memory.NewIntegrationStore(memory.NewJobQueue(ids, clock.Now), cipher, clock, audit)
	descriptor := integration.ProviderDescriptor{
		Provider: "jira-cloud", Name: "Jira Cloud",
		SecretFields: []integration.FieldDescriptor{{Name: "api_token", Label: "API token", Kind: integration.FieldPassword, Required: true}},
	}
	registry := integration.NewRegistry()
	if err := registry.Register(descriptor, func(integration.Integration, integration.CredentialBundle, selfhosted.Rules) (integration.Adapter, error) {
		return ticketProviderTestAdapter{descriptor: descriptor}, nil
	}); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, registry, memory.NewProjectRepository(), memory.MissingIntegrationAnalysisMatcher{}, ids, clock)
	if err != nil {
		t.Fatal(err)
	}
	tenant := shared.ID("tenant-a")
	ctx := shared.WithTenant(context.Background(), tenant)
	item := integration.Integration{ID: "jira", TenantID: tenant, Provider: "jira-cloud", Name: "Jira", Endpoint: "https://tenant.atlassian.net", Config: json.RawMessage(`{}`), Version: 1, ConnectionRevision: 1}
	if err := store.CreateIntegration(ctx, item, ports.AuditEntry{Actor: "admin", Action: "integration.created", Target: item.ID.String(), At: clock.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutIntegrationCredential(ctx, item.ID, "default", []byte(`{"api_token":"test-token"}`), 1, 1, ports.AuditEntry{Actor: "admin", Action: "integration.credential_replaced", Target: item.ID.String(), At: clock.Now()}); err != nil {
		t.Fatal(err)
	}
	current, err := service.Get(ctx, tenant, item.ID)
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := service.SetEnabled(ctx, tenant, item.ID, true, current.Version, "admin")
	if err != nil || !enabled.Enabled {
		t.Fatalf("enable test integration=%+v err=%v", enabled, err)
	}
	capturedEnabled := enabled
	disabled, err := service.SetEnabled(ctx, tenant, item.ID, false, enabled.Version, "admin")
	if err != nil || disabled.Enabled || disabled.ConnectionRevision != capturedEnabled.ConnectionRevision || disabled.CredentialRevision != capturedEnabled.CredentialRevision {
		t.Fatalf("disable must change only enabled/version: %+v err=%v", disabled, err)
	}
	if _, err := service.TicketProvider(ctx, capturedEnabled); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("dispatch captured before disable error=%v, want conflict", err)
	}
	if _, err := service.TicketProvider(ctx, disabled); err != nil {
		t.Fatalf("disabled integration metadata discovery error=%v", err)
	}
}
