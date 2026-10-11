package ticketing_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	usecase "github.com/KKloudTarus/synapse-ce/internal/usecase/ticketing"
)

type ticketClock struct{ t time.Time }

func (c ticketClock) Now() time.Time { return c.t }

type ticketIDs struct{ n int }

func (g *ticketIDs) NewID() shared.ID { g.n++; return shared.ID(fmt.Sprintf("ticket-service-%d", g.n)) }
func TestServiceCreatesReplayableIntentAndManualLink(t *testing.T) {
	ctx := context.Background()
	store := memory.NewTicketStore()
	service, err := usecase.NewService(store, &ticketIDs{}, ticketClock{time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})
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
	if _, _, err = service.LinkManual(ctx, "tenant-a", "eng-a", "finding-a",
		"http://jira.example/browse/SEC-1"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("accepted insecure URL: %v", err)
	}
	digest := strings.Repeat("f", 64)
	intent, created, err := service.OpenIntent(ctx, "tenant-a", mapping.ID, "finding-a", "eng-a",
		domain.Create, "submit:once", digest)
	if err != nil || !created || intent.Marker != "synapse-intent-"+intent.ID.String() {
		t.Fatalf("new intent: %+v %t %v", intent, created, err)
	}
	replay, created, err := service.OpenIntent(ctx, "tenant-a", mapping.ID, "finding-a", "eng-a",
		domain.Create, "submit:once", digest)
	if err != nil || created || replay.ID != intent.ID {
		t.Fatalf("replay: %+v %t %v", replay, created, err)
	}
	if _, _, err = service.OpenIntent(ctx, "tenant-a", mapping.ID, "finding-a", "foreign-eng",
		domain.Create, "submit:other", digest); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("accepted wrong engagement: %v", err)
	}
}

func TestServiceRequiresDependenciesAndTenant(t *testing.T) {
	store := memory.NewTicketStore()
	ids := &ticketIDs{}
	clock := ticketClock{time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	for _, missing := range []string{"store", "ids", "clock"} {
		t.Run(missing, func(t *testing.T) {
			var err error
			switch missing {
			case "store":
				_, err = usecase.NewService(nil, ids, clock)
			case "ids":
				_, err = usecase.NewService(store, nil, clock)
			case "clock":
				_, err = usecase.NewService(store, ids, nil)
			}
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("missing dependency: %v", err)
			}
		})
	}
	service, err := usecase.NewService(store, ids, clock)
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
