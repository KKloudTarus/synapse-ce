package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestAssessmentCreateIsAtomicAndUnique(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant")
	now := time.Now().UTC()
	services := NewAssetInventoryRepository()
	engagements := NewEngagementRepository()
	repo := NewAssessmentRepository(services, engagements)
	if err := services.CreateBusinessService(ctx, asset.BusinessService{ID: "service", TenantID: "tenant", Name: "Service", Criticality: asset.CriticalityMedium, Lifecycle: asset.LifecyclePlanned}); err != nil {
		t.Fatal(err)
	}
	a, err := assessment.New("assessment", "tenant", "service", "Name", "", assessment.Policy{}, now)
	if err != nil {
		t.Fatal(err)
	}
	good, err := engagement.New("good", "tenant", "Good", "", now)
	if err != nil {
		t.Fatal(err)
	}
	good.AssessmentID = a.ID
	bad, err := engagement.New("bad", "other", "Bad", "", now)
	if err != nil {
		t.Fatal(err)
	}
	bad.AssessmentID = a.ID
	if err := repo.Create(ctx, a, []*engagement.Engagement{good, bad}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("invalid create=%v", err)
	}
	if _, err := repo.Get(ctx, a.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("assessment persisted=%v", err)
	}
	if _, err := engagements.GetByID(ctx, good.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("child persisted=%v", err)
	}
	if err := repo.Create(ctx, a, []*engagement.Engagement{good}); err != nil {
		t.Fatal(err)
	}
	duplicate, err := assessment.New("assessment-2", "tenant", "service", "Name", "", assessment.Policy{}, now)
	if err != nil {
		t.Fatal(err)
	}
	child, err := engagement.New("child-2", "tenant", "Child", "", now)
	if err != nil {
		t.Fatal(err)
	}
	child.AssessmentID = duplicate.ID
	if err := repo.Create(ctx, duplicate, []*engagement.Engagement{child}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate name=%v", err)
	}
}
