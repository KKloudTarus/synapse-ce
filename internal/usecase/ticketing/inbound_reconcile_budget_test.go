package ticketing

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type reconcileBudgetClock struct{ at time.Time }

func (c reconcileBudgetClock) Now() time.Time { return c.at }

type reconcileBudgetIntegrations struct{ ports.IntegrationStore }

func (reconcileBudgetIntegrations) GetIntegration(ctx context.Context, id shared.ID) (integration.Integration, error) {
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant != "tenant" {
		return integration.Integration{}, shared.ErrNotFound
	}
	return integration.Integration{ID: id, TenantID: tenant, Provider: "jira-cloud", Enabled: true, Endpoint: "https://unit.atlassian.net", ConnectionRevision: 1, CredentialRevision: 1}, nil
}

type reconcileBudgetProvider struct {
	ports.TicketProvider
	reads, identities int
	at                time.Time
}

func (p *reconcileBudgetProvider) GetTicket(_ context.Context, key string) (ports.TicketObservation, error) {
	p.reads++
	author := "external-human"
	if key == "SEC-1" {
		author = ""
	}
	return ports.TicketObservation{ExternalID: key, StatusCategory: "done", UpdatedAt: p.at, StatusChangedAt: p.at, AuthorID: author}, nil
}
func (p *reconcileBudgetProvider) TicketIdentity(context.Context) (string, error) {
	p.identities++
	return "integration-user", nil
}

type reconcileBudgetProviders struct{ p *reconcileBudgetProvider }

func (f reconcileBudgetProviders) TicketProvider(context.Context, integration.Integration) (ports.TicketProvider, error) {
	return f.p, nil
}
func (f reconcileBudgetProviders) TicketProviderDescriptor(provider integration.Provider) (integration.ProviderDescriptor, error) {
	return integration.ProviderDescriptor{Provider: provider, Capabilities: []integration.Capability{integration.CapabilityTickets}}, nil
}

type reconcileBudgetStore struct {
	ports.TicketInboundStore
	targets      []ports.TicketStatusTarget
	polls        int
	observations []domain.ExternalTicketObservation
}

func (s *reconcileBudgetStore) ListInboundTicketTargets(_ context.Context, _ shared.ID, limit int) ([]ports.TicketStatusTarget, error) {
	return s.targets[:min(limit, len(s.targets))], nil
}
func (s *reconcileBudgetStore) ResolveInboundTicket(_ context.Context, _ shared.ID, integrationID shared.ID, remote string) ([]ports.TicketStatusTarget, error) {
	for _, target := range s.targets {
		if target.Mapping.IntegrationID == integrationID && target.Intent.RemoteID == remote {
			return []ports.TicketStatusTarget{target}, nil
		}
	}
	return nil, nil
}
func (s *reconcileBudgetStore) RecordInboundTicketPoll(context.Context, shared.ID, ports.TicketStatusTarget, time.Time) error {
	s.polls++
	return nil
}
func (s *reconcileBudgetStore) ReduceInboundTicket(_ context.Context, _ shared.ID, observations []domain.ExternalTicketObservation, _ []domain.ExternalTicketComment, _ time.Time) error {
	s.observations = append(s.observations, observations...)
	return nil
}

func TestInboundReconcileChargesIdentityWithinReadBudget(t *testing.T) {
	at := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	store := &reconcileBudgetStore{}
	for n := 1; n <= 250; n++ {
		id := shared.ID(fmt.Sprintf("intent-%d", n))
		remote := fmt.Sprintf("SEC-%d", n)
		integrationID := shared.ID(fmt.Sprintf("integration-%d", n))
		mappingID := shared.ID(fmt.Sprintf("mapping-%d", n))
		fields := map[string]any{"project": map[string]string{"key": "SEC"}, "issuetype": map[string]string{"id": "10001"}, "labels": []string{}, "summary": "Title", "description": "Description"}
		payload := map[string]any{"fields": fields, "_synapse": snapshotFacts{Provider: "jira-cloud", Endpoint: "https://unit.atlassian.net", DataClass: notification.DataClassDetail, MappingVersion: 1, ConnectionRevision: 1, CredentialRevision: 1}}
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		digest := ticketDigest(raw)
		fields["labels"] = []string{"synapse-intent-" + id.String()}
		raw, err = json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		store.targets = append(store.targets, ports.TicketStatusTarget{Mapping: domain.Mapping{ID: mappingID, TenantID: "tenant", IntegrationID: integrationID, ProjectKey: "SEC", IssueType: "10001", Version: 1}, Intent: domain.Intent{ID: id, TenantID: "tenant", MappingID: mappingID, IntegrationID: integrationID, EngagementID: "eng", FindingID: "finding", Snapshot: raw, PayloadDigest: digest, Marker: "synapse-intent-" + id.String(), MappingVersion: 1, ConnectionRevision: 1, CredentialRevision: 1, RemoteID: remote, RemoteURL: "https://unit.atlassian.net/browse/" + remote}})
	}
	provider := &reconcileBudgetProvider{at: at}
	w := &Workflow{Service: &Service{clock: reconcileBudgetClock{at}}, integrations: reconcileBudgetIntegrations{}, providers: reconcileBudgetProviders{provider}}
	if err := w.tickInboundTicketObservations(shared.WithTenant(context.Background(), "tenant"), "tenant", store, 250); err != nil {
		t.Fatal(err)
	}
	if provider.reads+provider.identities != 250 || provider.reads != 126 || provider.identities != 124 || store.polls != 126 || len(store.observations) != 126 {
		t.Fatalf("reads=%d identities=%d polls=%d observations=%d", provider.reads, provider.identities, store.polls, len(store.observations))
	}
	last := store.observations[len(store.observations)-1]
	if last.StatusAuthorKnown || last.AuthorID != "" || last.StatusCategory != "done" {
		t.Fatalf("budget exhaustion lost status or guessed author: %+v", last)
	}
}
