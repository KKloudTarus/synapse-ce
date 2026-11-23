package httpapi

import (
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
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
	workflow, err := ticketuc.NewWorkflow(store, manualTicketIntegrations{}, manualTicketProviders{}, findings, w.engagements,
		manualTicketPolicy{}, &harnessAudit{}, &engmiscIDs{}, engmiscClock{})
	if err != nil {
		w.t.Fatalf("ticket workflow: %v", err)
	}
	// The store keys a link by finding id alone, so one link serves every engagement that carries f1.
	if _, _, err := workflow.LinkManual(ctx, "tenantA", engmiscEngagement, engmiscFinding, "https://jira.example/browse/"+engmiscMarker); err != nil {
		w.t.Fatalf("link ticket: %v", err)
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
	w.rt.SetTicketing(workflow)
}
