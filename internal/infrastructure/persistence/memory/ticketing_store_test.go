package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ticketing/storetest"
)

func TestTicketStoreConformance(t *testing.T) {
	f := storetest.Fixture{Tenant: "ticket-a", Other: "ticket-b", Integration: "ticket-integration-a",
		Project: "ticket-project-a", Engagement: "ticket-engagement-a", Finding: "ticket-finding-a"}
	engagements := NewEngagementRepository()
	findings := NewFindingRepository()
	seedTicketParents(t, engagements, findings, f)
	store, err := NewTicketStore(engagements, findings)
	if err != nil {
		t.Fatal(err)
	}
	storetest.Run(t, store, f)
	storetest.ConcurrentReplay(t, store, f)
	storetest.ConcurrentClaim(t, store, f)
	storetest.ConcurrentCompletionConflict(t, store, f)
	storetest.CanceledContext(t, store, f)
}

func TestNewTicketStoreRequiresParents(t *testing.T) {
	engagements := NewEngagementRepository()
	findings := NewFindingRepository()
	for _, parents := range []struct {
		name        string
		engagements *EngagementRepository
		findings    *FindingRepository
	}{
		{name: "engagements", findings: findings},
		{name: "findings", engagements: engagements},
	} {
		t.Run(parents.name, func(t *testing.T) {
			if store, err := NewTicketStore(parents.engagements, parents.findings); store != nil || !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("store=%v err=%v", store, err)
			}
		})
	}
}

func TestTicketStoreChecksProjectContextAndFindingReference(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	engagements := NewEngagementRepository()
	findings := NewFindingRepository()
	standard := storetest.Fixture{Tenant: "ticket-a", Integration: "ticket-integration-a", Project: "ticket-project-a", Engagement: "ticket-engagement-a", Finding: "ticket-finding-a"}
	seedTicketParents(t, engagements, findings, standard)
	projectContext, err := engagement.New("ticket-project-context-a", standard.Tenant, "Project ticketing", "Synapse", now)
	if err != nil {
		t.Fatal(err)
	}
	projectContext.ProjectID = standard.Project
	if err = engagements.Create(shared.WithTenant(ctx, standard.Tenant), projectContext); err != nil {
		t.Fatal(err)
	}
	projectFinding, err := finding.NewManual("ticket-project-finding-a", projectContext.ID, finding.ManualInput{Title: "Project ticket finding", Severity: shared.SeverityHigh}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = findings.Upsert(shared.WithTenant(ctx, standard.Tenant), []finding.Finding{projectFinding}); err != nil {
		t.Fatal(err)
	}
	store, err := NewTicketStore(engagements, findings)
	if err != nil {
		t.Fatal(err)
	}
	mapping := ticketing.Mapping{ID: "ticket-project-map-a", TenantID: standard.Tenant, IntegrationID: standard.Integration,
		Scope: ticketing.Project, ScopeID: standard.Project, ProjectKey: "SEC", IssueType: "Bug", Version: 1, CreatedAt: now, UpdatedAt: now}
	if err = store.CreateMapping(ctx, standard.Tenant, mapping); err != nil {
		t.Fatal(err)
	}
	intent := ticketing.Intent{ID: "ticket-project-intent-a", TenantID: standard.Tenant, IntegrationID: standard.Integration,
		MappingID: mapping.ID, FindingID: projectFinding.ID, EngagementID: projectContext.ID, Action: ticketing.Create,
		RequestKey: "project-context", PayloadDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Marker: "synapse-intent-ticket-project-intent-a", State: writeintent.Pending, Version: 1, CreatedAt: now, UpdatedAt: now}
	if _, created, createErr := store.CreateOrGetIntent(ctx, standard.Tenant, intent); createErr != nil || !created {
		t.Fatalf("project intent: created=%t err=%v", created, createErr)
	}
	if _, created, createErr := store.CreateLink(ctx, standard.Tenant, ticketing.Link{ID: "ticket-project-link-a", TenantID: standard.Tenant, FindingID: projectFinding.ID, EngagementID: projectContext.ID, ExternalURL: "https://jira.example/browse/PROJECT-1", CreatedAt: now}); createErr != nil || !created {
		t.Fatalf("project context link: created=%t err=%v", created, createErr)
	}
	engagementMapping := mapping
	engagementMapping.ID = "ticket-project-engagement-map-a"
	engagementMapping.Scope = ticketing.Engagement
	engagementMapping.ScopeID = projectContext.ID
	if err = store.CreateMapping(ctx, standard.Tenant, engagementMapping); err != nil {
		t.Fatal(err)
	}
	engagementIntent := intent
	engagementIntent.ID = "ticket-project-engagement-intent-a"
	engagementIntent.MappingID = engagementMapping.ID
	engagementIntent.RequestKey = "project-engagement-context"
	engagementIntent.Marker = "synapse-intent-" + engagementIntent.ID.String()
	if _, created, createErr := store.CreateOrGetIntent(ctx, standard.Tenant, engagementIntent); createErr != nil || !created {
		t.Fatalf("engagement-scoped project context intent: created=%t err=%v", created, createErr)
	}
	wrongContext := intent
	wrongContext.ID = "ticket-project-intent-wrong-a"
	wrongContext.Marker = "synapse-intent-" + wrongContext.ID.String()
	wrongContext.RequestKey = "wrong-project-context"
	wrongContext.EngagementID = standard.Engagement
	wrongContext.FindingID = standard.Finding
	if _, _, createErr := store.CreateOrGetIntent(ctx, standard.Tenant, wrongContext); !errors.Is(createErr, shared.ErrValidation) {
		t.Fatalf("accepted project intent for unrelated engagement: %v", createErr)
	}
	missingFinding := intent
	missingFinding.ID = "ticket-project-intent-missing-a"
	missingFinding.Marker = "synapse-intent-" + missingFinding.ID.String()
	missingFinding.RequestKey = "missing-project-finding"
	missingFinding.FindingID = "ticket-finding-missing-a"
	if _, _, createErr := store.CreateOrGetIntent(ctx, standard.Tenant, missingFinding); !errors.Is(createErr, shared.ErrNotFound) {
		t.Fatalf("accepted missing project finding: %v", createErr)
	}
}

func seedTicketParents(t *testing.T, engagements *EngagementRepository, findings *FindingRepository, f storetest.Fixture) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	item, err := engagement.New(f.Engagement, f.Tenant, "Ticketing", "Synapse", now)
	if err != nil {
		t.Fatal(err)
	}
	if err = engagements.Create(shared.WithTenant(ctx, f.Tenant), item); err != nil {
		t.Fatal(err)
	}
	issue, err := finding.NewManual(f.Finding, f.Engagement, finding.ManualInput{Title: "Ticketing finding", Severity: shared.SeverityHigh}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = findings.Upsert(shared.WithTenant(ctx, f.Tenant), []finding.Finding{issue}); err != nil {
		t.Fatal(err)
	}
}
