package ticketing_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	usecase "github.com/KKloudTarus/synapse-ce/internal/usecase/ticketing"
)

type ticketClock struct{ t time.Time }

func (c ticketClock) Now() time.Time { return c.t }

type ticketIDs struct {
	mu sync.Mutex
	n  int
}

func (g *ticketIDs) NewID() shared.ID {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.n++
	return shared.ID(fmt.Sprintf("ticket-service-%d", g.n))
}

type ticketFixture struct {
	store       *memory.TicketStore
	findings    *memory.FindingRepository
	engagements *memory.EngagementRepository
	clock       ticketClock
}

func newTicketFixture(t *testing.T) ticketFixture {
	t.Helper()
	clock := ticketClock{time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	engagements := memory.NewEngagementRepository()
	findings := memory.NewFindingRepository()
	seedTicketParent(t, engagements, findings, "tenant-a", "eng-a", "finding-a", "", clock.Now())
	store, err := memory.NewTicketStore(engagements, findings)
	if err != nil {
		t.Fatal(err)
	}
	return ticketFixture{store: store, findings: findings, engagements: engagements, clock: clock}
}

func seedTicketParent(t *testing.T, engagements *memory.EngagementRepository, findings *memory.FindingRepository, tenant, engagementID, findingID, projectID shared.ID, now time.Time) {
	t.Helper()
	ctx := shared.WithTenant(context.Background(), tenant)
	item, err := engagement.New(engagementID, tenant, "Ticketing", "Synapse", now)
	if err != nil {
		t.Fatal(err)
	}
	item.ProjectID = projectID
	if err = engagements.Create(ctx, item); err != nil {
		t.Fatal(err)
	}
	issue, err := finding.NewManual(findingID, engagementID, finding.ManualInput{Title: "Ticket finding", Severity: shared.SeverityHigh}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = findings.Upsert(ctx, []finding.Finding{issue}); err != nil {
		t.Fatal(err)
	}
}

func TestServiceCreatesReplayableIntentAndManualLink(t *testing.T) {
	ctx := context.Background()
	f := newTicketFixture(t)
	service, err := usecase.NewService(f.store, f.findings, f.engagements, &ticketIDs{}, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	mapping, err := service.CreateMapping(ctx, "tenant-a", "integration-a", "eng-a", domain.Engagement, "SEC", "Bug")
	if err != nil {
		t.Fatal(err)
	}
	link, created, err := service.LinkManual(ctx, "tenant-a", "eng-a", "finding-a", "https://jira.example/browse/SEC-1")
	if err != nil || !created || link.IntegrationID != "" {
		t.Fatalf("manual link: %+v %t %v", link, created, err)
	}
	if _, _, err = service.LinkManual(ctx, "tenant-a", "eng-a", "finding-a", "http://jira.example/browse/SEC-1"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("accepted insecure URL: %v", err)
	}
	digest := strings.Repeat("f", 64)
	intent, created, err := service.OpenIntent(ctx, "tenant-a", mapping.ID, "finding-a", "eng-a", domain.Create, "submit:once", digest)
	if err != nil || !created || intent.Marker != "synapse-intent-"+intent.ID.String() {
		t.Fatalf("new intent: %+v %t %v", intent, created, err)
	}
	replay, created, err := service.OpenIntent(ctx, "tenant-a", mapping.ID, "finding-a", "eng-a", domain.Create, "submit:once", digest)
	if err != nil || created || replay.ID != intent.ID {
		t.Fatalf("replay: %+v %t %v", replay, created, err)
	}
	if _, _, err = service.OpenIntent(ctx, "tenant-a", mapping.ID, "finding-a", "foreign-eng", domain.Create, "submit:other", digest); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("accepted finding from wrong engagement: %v", err)
	}
}

func TestServiceProjectMappingRequiresOwningProjectContext(t *testing.T) {
	ctx := context.Background()
	f := newTicketFixture(t)
	seedTicketParent(t, f.engagements, f.findings, "tenant-a", "project-context-a", "project-finding-a", "project-a", f.clock.Now())
	service, err := usecase.NewService(f.store, f.findings, f.engagements, &ticketIDs{}, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	mapping, err := service.CreateMapping(ctx, "tenant-a", "integration-a", "project-a", domain.Project, "SEC", "Bug")
	if err != nil {
		t.Fatal(err)
	}
	if _, created, err := service.OpenIntent(ctx, "tenant-a", mapping.ID, "project-finding-a", "project-context-a", domain.Create, "project-request", strings.Repeat("a", 64)); err != nil || !created {
		t.Fatalf("project intent: created=%t err=%v", created, err)
	}
	if _, _, err := service.OpenIntent(ctx, "tenant-a", mapping.ID, "finding-a", "eng-a", domain.Create, "wrong-project", strings.Repeat("b", 64)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("accepted unrelated assessment engagement: %v", err)
	}
}

func TestServiceRequiresDependenciesAndTenant(t *testing.T) {
	f := newTicketFixture(t)
	ids := &ticketIDs{}
	for _, missing := range []string{"store", "findings", "engagements", "ids", "clock"} {
		t.Run(missing, func(t *testing.T) {
			var err error
			switch missing {
			case "store":
				_, err = usecase.NewService(nil, f.findings, f.engagements, ids, f.clock)
			case "findings":
				_, err = usecase.NewService(f.store, nil, f.engagements, ids, f.clock)
			case "engagements":
				_, err = usecase.NewService(f.store, f.findings, nil, ids, f.clock)
			case "ids":
				_, err = usecase.NewService(f.store, f.findings, f.engagements, nil, f.clock)
			case "clock":
				_, err = usecase.NewService(f.store, f.findings, f.engagements, ids, nil)
			}
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("missing dependency: %v", err)
			}
		})
	}
	service, err := usecase.NewService(f.store, f.findings, f.engagements, ids, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateMapping(context.Background(), "", "integration-a", "eng-a", domain.Engagement, "SEC", "Bug"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing tenant mapping: %v", err)
	}
	if _, _, err := service.LinkManual(context.Background(), "", "eng-a", "finding-a", "https://jira.example/browse/SEC-1"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing tenant link: %v", err)
	}
	if _, _, err := service.OpenIntent(context.Background(), "", "mapping-a", "finding-a", "eng-a", domain.Create, "request", strings.Repeat("f", 64)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing tenant intent: %v", err)
	}
}
