package assessmentuc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
)

type testClock struct{ now time.Time }

func (c testClock) Now() time.Time { return c.now }

type testIDs struct{ n int }

func (g *testIDs) NewID() shared.ID { g.n++; return shared.ID(string(rune('a' + g.n))) }

func TestAssessmentHierarchyAndEngagementDefaults(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	clock := testClock{now: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
	services := memory.NewAssetInventoryRepository()
	engagements := memory.NewEngagementRepository()
	if err := services.CreateBusinessService(ctx, asset.BusinessService{ID: "service-a", TenantID: "tenant-a", Name: "Service", Criticality: asset.CriticalityMedium, Lifecycle: asset.LifecyclePlanned}); err != nil {
		t.Fatal(err)
	}
	svc, err := New(memory.NewAssessmentRepository(services, engagements), services, clock, &testIDs{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Create(ctx, CreateInput{TenantID: "tenant-a", BusinessServiceID: "missing", Name: "A", Engagements: []EngagementInput{{Name: "E"}}}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing parent=%v", err)
	}
	if _, err := svc.Create(ctx, CreateInput{TenantID: "tenant-a", BusinessServiceID: "service-a", Name: "A"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("zero children=%v", err)
	}
	created, err := svc.Create(ctx, CreateInput{TenantID: "tenant-a", BusinessServiceID: "service-a", Actor: "operator", Name: "A", Engagements: []EngagementInput{{Name: "E", Client: "Client"}}})
	if err != nil {
		t.Fatal(err)
	}
	children, err := engagements.List(ctx, "tenant-a")
	if err != nil || len(children) != 1 {
		t.Fatalf("children=%v err=%v", children, err)
	}
	child := children[0]
	if child.AssessmentID != created.ID || !child.ProjectID.IsZero() || child.Status != "draft" || child.LiveReconEnabled {
		t.Fatalf("child=%+v", child)
	}
	if _, err := svc.Get(ctx, "other", created.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("wrong parent=%v", err)
	}
	if _, err := svc.List(ctx, "other"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("nonexistent parent list=%v", err)
	}
	if _, err := svc.Create(shared.WithTenant(context.Background(), "tenant-b"), CreateInput{TenantID: "tenant-b", BusinessServiceID: "service-a", Name: "Cross", Engagements: []EngagementInput{{Name: "E"}}}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross parent=%v", err)
	}
}
