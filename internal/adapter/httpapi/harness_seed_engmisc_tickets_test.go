package httpapi

import (
	"context"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	ticketuc "github.com/KKloudTarus/synapse-ce/internal/usecase/ticketing"
)

// seedEngmiscTickets wires the real ticket workflow over the in-memory ticket store and links one
// manual ticket to finding f1 of tenantA, plus one inbound comment under engagement engA and one under
// the hidden context of project-a. The two engagement-scoped ticket routes and the two project-scoped
// ones then answer tenantA's rows; the project routes resolve the context engagement through the
// project service, so the finding has to exist under that id as well.
//
// The workflow gets its own finding repository: it only needs to prove the finding exists, and a
// private one keeps this seed independent of whatever the findings seed plants.
func seedEngmiscTickets(w *harnessWorld) {
	ctx := engmiscTenantCtx()
	source, err := w.projects.SourceContext(ctx, "tenantA", "project-a")
	if err != nil {
		w.t.Fatalf("resolve project-a source context: %v", err)
	}
	engagements := []shared.ID{engmiscEngagement, source.Context.ID}

	findings := memory.NewFindingRepository()
	for _, engagementID := range engagements {
		item, err := finding.NewManual(engmiscFinding, engagementID, finding.ManualInput{Title: "ticketed " + engmiscMarker, Severity: shared.SeverityHigh}, engmiscNow)
		if err != nil {
			w.t.Fatalf("build ticketed finding: %v", err)
		}
		if err := findings.Upsert(ctx, []finding.Finding{item}); err != nil {
			w.t.Fatalf("seed ticketed finding: %v", err)
		}
	}
	store, err := memory.NewTicketStore(w.engagements, findings)
	if err != nil {
		w.t.Fatalf("ticket store: %v", err)
	}
	workflow, err := ticketuc.NewWorkflow(store, engmiscTicketIntegrations{}, manualTicketProviders{}, findings, w.engagements,
		manualTicketPolicy{}, &harnessAudit{}, &engmiscIDs{}, engmiscClock{})
	if err != nil {
		w.t.Fatalf("ticket workflow: %v", err)
	}
	// The store keys a link by finding id alone, so one link serves every engagement that carries f1.
	link, _, err := workflow.LinkManual(ctx, "tenantA", engmiscEngagement, engmiscFinding, "https://jira.example/browse/"+engmiscMarker)
	if err != nil {
		w.t.Fatalf("link ticket: %v", err)
	}
	if link.ID != engmiscTicketLink {
		w.t.Fatalf("ticket link id = %s, want %s", link.ID, engmiscTicketLink)
	}
	for index, engagementID := range engagements {
		comment := ticketing.ExternalTicketComment{
			ID: shared.ID(fmt.Sprintf("engmisc-comment-%d", index)), TenantID: "tenantA", IntegrationID: "engmisc-integration",
			EngagementID: engagementID, FindingID: engmiscFinding, RemoteID: "SEC-1", AuthorID: "reporter",
			Body: "comment " + engmiscMarker, ProviderAt: engmiscNow, CreatedAt: engmiscNow,
		}
		if err := store.ReduceInboundTicket(ctx, "tenantA", nil, []ticketing.ExternalTicketComment{comment}, engmiscNow); err != nil {
			w.t.Fatalf("seed inbound ticket comment under %s: %v", engagementID, err)
		}
	}
	seedEngmiscTicketRecords(w, store)
	w.rt.SetTicketing(workflow)
}

// seedEngmiscTicketRecords plants one tenantA Jira mapping and one pending write intent under fixed
// ids, so the mapping, intent and breaker routes are addressed at real tenantA records.
func seedEngmiscTicketRecords(w *harnessWorld, store *memory.TicketStore) {
	ctx := engmiscTenantCtx()
	mapping := ticketing.Mapping{
		ID: engmiscTicketMapping, TenantID: "tenantA", IntegrationID: engmiscTicketIntegration,
		Scope: ticketing.Engagement, ScopeID: engmiscEngagement, ProjectKey: "SEC", IssueType: "Bug",
		Version: 1, CreatedAt: engmiscNow, UpdatedAt: engmiscNow,
	}
	if err := store.CreateMapping(ctx, "tenantA", mapping); err != nil {
		w.t.Fatalf("seed ticket mapping: %v", err)
	}
	intent := ticketing.Intent{
		ID: engmiscTicketIntent, TenantID: "tenantA", IntegrationID: engmiscTicketIntegration, MappingID: engmiscTicketMapping,
		FindingID: engmiscFinding, EngagementID: engmiscEngagement, Action: ticketing.Create, RequestKey: "engmisc-request",
		PayloadDigest: strings.Repeat("a", 64), Marker: "synapse-intent-" + engmiscTicketIntent.String(),
		State: writeintent.Pending, Version: 1, CreatedAt: engmiscNow, UpdatedAt: engmiscNow,
	}
	if _, _, err := store.CreateOrGetIntent(ctx, "tenantA", intent); err != nil {
		w.t.Fatalf("seed ticket intent: %v", err)
	}
}

// engmiscTicketIntegrations answers the one tenantA Jira integration for every caller, whatever tenant
// asks, so the metadata and breaker routes are addressed at a real integration id. The harness provider
// registry has no Jira descriptor, so tenantA's own requests are refused too and these routes stay
// vacuous: they prove tenantB is refused, not which check refuses it. A route proven through this stub
// later must be read with that in mind, since the stub does not scope.
type engmiscTicketIntegrations struct{ ports.IntegrationStore }

func (engmiscTicketIntegrations) GetIntegration(_ context.Context, id shared.ID) (integration.Integration, error) {
	if id != engmiscTicketIntegration {
		return integration.Integration{}, shared.ErrNotFound
	}
	return integration.Integration{
		ID: engmiscTicketIntegration, TenantID: "tenantA", Provider: "jira", Name: "jira " + engmiscMarker,
		Endpoint: "https://jira-a.example", Enabled: true, Version: 1, ConnectionRevision: 1,
	}, nil
}
