package assetuc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

type fixedIDs struct{ next int }

func (g *fixedIDs) NewID() shared.ID { g.next++; return shared.ID(string(rune('a' + g.next))) }

func TestUpdateBusinessServiceAndProtectedDelete(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant")
	clock := fixedClock{now: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
	ids := &fixedIDs{}
	services := memory.NewAssetInventoryRepository()
	engagements := memory.NewEngagementRepository()
	repo := memory.NewAssessmentRepository(services, engagements)
	svc, err := New(services, clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	created, err := svc.CreateBusinessService(ctx, CreateBusinessServiceInput{TenantID: "tenant", Actor: "creator", Name: " First ", Description: " Initial ", Criticality: asset.CriticalityMedium, Lifecycle: asset.LifecyclePlanned})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := svc.UpdateBusinessService(ctx, created.ID, UpdateBusinessServiceInput{Actor: "editor", Name: " Updated ", Description: " Changed ", Criticality: asset.CriticalityHigh, Lifecycle: asset.LifecycleActive})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "Updated" || updated.Description != "Changed" || updated.Criticality != asset.CriticalityHigh || updated.Lifecycle != asset.LifecycleActive || updated.ID != created.ID || updated.TenantID != created.TenantID || updated.Audit.CreatedAt != created.Audit.CreatedAt || updated.Audit.CreatedBy != "creator" || updated.Audit.UpdatedAt != clock.now || updated.Audit.UpdatedBy != "editor" {
		t.Fatalf("updated=%+v created=%+v", updated, created)
	}
	if _, err := svc.CreateBusinessService(ctx, CreateBusinessServiceInput{TenantID: "tenant", Actor: "creator", Name: "Duplicate", Criticality: asset.CriticalityMedium, Lifecycle: asset.LifecyclePlanned}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdateBusinessService(ctx, created.ID, UpdateBusinessServiceInput{Name: "Duplicate", Criticality: asset.CriticalityHigh, Lifecycle: asset.LifecycleActive}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate error=%v", err)
	}
	if _, err := svc.UpdateBusinessService(ctx, created.ID, UpdateBusinessServiceInput{Name: "", Criticality: asset.CriticalityHigh, Lifecycle: asset.LifecycleActive}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("invalid error=%v", err)
	}
	a, err := assessment.New("assessment", "tenant", created.ID, "Assessment", "", assessment.Policy{}, clock.now)
	if err != nil {
		t.Fatal(err)
	}
	e, err := engagement.New("engagement", "tenant", "Engagement", "", clock.now)
	if err != nil {
		t.Fatal(err)
	}
	e.AssessmentID = a.ID
	if err := repo.Create(ctx, a, []*engagement.Engagement{e}); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteBusinessService(ctx, created.ID); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("delete error=%v", err)
	}
}
