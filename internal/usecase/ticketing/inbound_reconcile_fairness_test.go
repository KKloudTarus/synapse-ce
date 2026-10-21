package ticketing

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type inboundFairnessProvider struct {
	ports.TicketProvider
	reads []string
	at    time.Time
}

func (p *inboundFairnessProvider) GetTicket(ctx context.Context, remoteID string) (ports.TicketObservation, error) {
	p.reads = append(p.reads, remoteID)
	if remoteID == "SLOW-1" {
		<-ctx.Done()
		return ports.TicketObservation{}, ctx.Err()
	}
	return ports.TicketObservation{ExternalID: remoteID, StatusCategory: "done", UpdatedAt: p.at, StatusChangedAt: p.at}, nil
}

type inboundFairnessProviders struct{ provider *inboundFairnessProvider }

func (p inboundFairnessProviders) TicketProvider(context.Context, integration.Integration) (ports.TicketProvider, error) {
	return p.provider, nil
}
func (p inboundFairnessProviders) TicketProviderDescriptor(provider integration.Provider) (integration.ProviderDescriptor, error) {
	return integration.ProviderDescriptor{Provider: provider, Capabilities: []integration.Capability{integration.CapabilityTickets}}, nil
}

type inboundFairnessStore struct {
	ports.TicketInboundStore
	targets      []ports.TicketStatusTarget
	polls        []string
	observations []domain.ExternalTicketObservation
}

func (s *inboundFairnessStore) ListInboundTicketTargets(_ context.Context, _ shared.ID, limit int) ([]ports.TicketStatusTarget, error) {
	out := append([]ports.TicketStatusTarget(nil), s.targets...)
	if len(s.polls) > 0 {
		out[0], out[1] = out[1], out[0]
	}
	return out[:min(limit, len(out))], nil
}

func (s *inboundFairnessStore) ResolveInboundTicket(_ context.Context, _ shared.ID, integrationID shared.ID, remoteID string) ([]ports.TicketStatusTarget, error) {
	for _, target := range s.targets {
		if target.Mapping.IntegrationID == integrationID && target.Intent.RemoteID == remoteID {
			return []ports.TicketStatusTarget{target}, nil
		}
	}
	return nil, nil
}

func (s *inboundFairnessStore) RecordInboundTicketPoll(_ context.Context, _ shared.ID, target ports.TicketStatusTarget, _ time.Time) error {
	s.polls = append(s.polls, target.Intent.RemoteID)
	return nil
}

func (s *inboundFairnessStore) ReduceInboundTicket(_ context.Context, _ shared.ID, observations []domain.ExternalTicketObservation, _ []domain.ExternalTicketComment, _ time.Time) error {
	s.observations = append(s.observations, observations...)
	return nil
}

func (s *inboundFairnessStore) ListInboundTicketView(context.Context, shared.ID, shared.ID, shared.ID) (ports.TicketInboundView, error) {
	return ports.TicketInboundView{}, nil
}

func inboundFairnessTarget(id, remoteID shared.ID) ports.TicketStatusTarget {
	fields := map[string]any{
		"project":     map[string]string{"key": "SEC"},
		"issuetype":   map[string]string{"id": "10001"},
		"labels":      []string{},
		"summary":     "Title",
		"description": "Description",
	}
	payload := map[string]any{"fields": fields, "_synapse": snapshotFacts{Provider: "jira-cloud", Endpoint: "https://unit.atlassian.net", DataClass: notification.DataClassDetail, MappingVersion: 1, ConnectionRevision: 1, CredentialRevision: 1}}
	raw, _ := json.Marshal(payload)
	digest := ticketDigest(raw)
	fields["labels"] = []string{"synapse-intent-" + id.String()}
	raw, _ = json.Marshal(payload)
	return ports.TicketStatusTarget{
		Mapping: domain.Mapping{ID: "mapping-" + id, TenantID: "tenant", IntegrationID: "integration", ProjectKey: "SEC", IssueType: "10001", Version: 1},
		Intent:  domain.Intent{ID: id, TenantID: "tenant", MappingID: "mapping-" + id, IntegrationID: "integration", EngagementID: "engagement", FindingID: "finding", Action: domain.Create, State: writeintent.Done, Version: 1, Snapshot: raw, PayloadDigest: digest, Marker: "synapse-intent-" + id.String(), MappingVersion: 1, ConnectionRevision: 1, CredentialRevision: 1, RemoteID: remoteID.String(), RemoteURL: "https://unit.atlassian.net/browse/" + remoteID.String()},
	}
}

func TestInboundReconcileTimeoutCheckpointsAttemptedTargetForNextFairTick(t *testing.T) {
	at := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	store := &inboundFairnessStore{targets: []ports.TicketStatusTarget{
		inboundFairnessTarget("slow", "SLOW-1"),
		inboundFairnessTarget("healthy", "HEALTHY-2"),
	}}
	provider := &inboundFairnessProvider{at: at}
	w := &Workflow{Service: &Service{clock: reconcileBudgetClock{at}}, integrations: reconcileBudgetIntegrations{}, providers: inboundFairnessProviders{provider}}
	progressCtx := shared.WithTenant(context.Background(), "tenant")

	firstCtx, firstCancel := context.WithTimeout(progressCtx, 30*time.Millisecond)
	err := w.tickInboundTicketObservationsWithProgress(firstCtx, progressCtx, "tenant", store, 2)
	firstCancel()
	if !errors.Is(err, context.DeadlineExceeded) || len(store.polls) != 1 || store.polls[0] != "SLOW-1" {
		t.Fatalf("first slow poll checkpoint: err=%v polls=%v", err, store.polls)
	}

	secondCtx, secondCancel := context.WithTimeout(progressCtx, 30*time.Millisecond)
	err = w.tickInboundTicketObservationsWithProgress(secondCtx, progressCtx, "tenant", store, 2)
	secondCancel()
	if !errors.Is(err, context.DeadlineExceeded) || len(store.polls) < 2 || store.polls[1] != "HEALTHY-2" {
		t.Fatalf("healthy target was not advanced after slow checkpoint: err=%v polls=%v", err, store.polls)
	}
	if len(store.observations) != 1 || store.observations[0].RemoteID != "HEALTHY-2" {
		t.Fatalf("healthy inbound observation=%+v", store.observations)
	}
	if len(provider.reads) != 3 || provider.reads[0] != "SLOW-1" || provider.reads[1] != "HEALTHY-2" || provider.reads[2] != "SLOW-1" {
		t.Fatalf("unexpected provider read sequence: %v", provider.reads)
	}
}
