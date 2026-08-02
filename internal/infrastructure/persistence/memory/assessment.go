package memory

import (
	"context"
	"fmt"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type AssessmentRepository struct {
	mu          sync.RWMutex
	items       map[shared.ID]assessment.Assessment
	services    *AssetInventoryRepository
	engagements *EngagementRepository
}

func NewAssessmentRepository(services *AssetInventoryRepository, engagements *EngagementRepository) *AssessmentRepository {
	r := &AssessmentRepository{items: map[shared.ID]assessment.Assessment{}, services: services, engagements: engagements}
	if services != nil {
		services.assessments = r
	}
	return r
}

var _ ports.AssessmentRepository = (*AssessmentRepository)(nil)

func (r *AssessmentRepository) Create(ctx context.Context, a assessment.Assessment, children []*engagement.Engagement) error {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID != a.TenantID || r.services == nil || r.engagements == nil {
		return fmt.Errorf("%w: assessment tenant context", shared.ErrValidation)
	}
	if err := a.Validate(); err != nil || len(children) == 0 {
		if err != nil {
			return err
		}
		return fmt.Errorf("%w: assessment requires an engagement", shared.ErrValidation)
	}

	r.services.mu.Lock()
	defer r.services.mu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.engagements.mu.Lock()
	defer r.engagements.mu.Unlock()

	service, ok := r.services.services[a.BusinessServiceID]
	if !ok || service.TenantID != tenantID {
		return fmt.Errorf("business service %s: %w", a.BusinessServiceID, shared.ErrNotFound)
	}
	if _, ok := r.items[a.ID]; ok {
		return fmt.Errorf("assessment: %w", shared.ErrConflict)
	}
	for _, existing := range r.items {
		if existing.TenantID == tenantID && existing.BusinessServiceID == a.BusinessServiceID && existing.Name == a.Name {
			return fmt.Errorf("assessment name: %w", shared.ErrConflict)
		}
	}
	seen := make(map[shared.ID]struct{}, len(children))
	for _, child := range children {
		if child == nil || child.ID.IsZero() || child.TenantID != tenantID || child.AssessmentID != a.ID {
			return fmt.Errorf("%w: invalid assessment engagement", shared.ErrValidation)
		}
		if _, duplicate := seen[child.ID]; duplicate {
			return fmt.Errorf("assessment engagement: %w", shared.ErrConflict)
		}
		if _, exists := r.engagements.data[child.ID]; exists {
			return fmt.Errorf("assessment engagement: %w", shared.ErrConflict)
		}
		seen[child.ID] = struct{}{}
	}
	r.items[a.ID] = a
	for _, child := range children {
		r.engagements.data[child.ID] = child
	}
	return nil
}

func (r *AssessmentRepository) Get(ctx context.Context, id shared.ID) (assessment.Assessment, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return assessment.Assessment{}, fmt.Errorf("%w: assessment tenant context", shared.ErrValidation)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.items[id]
	if !ok || a.TenantID != tenantID {
		return assessment.Assessment{}, fmt.Errorf("assessment: %w", shared.ErrNotFound)
	}
	return a, nil
}

func (r *AssessmentRepository) ListByBusinessService(ctx context.Context, id shared.ID) ([]assessment.Assessment, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return nil, fmt.Errorf("%w: assessment tenant context", shared.ErrValidation)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := []assessment.Assessment{}
	for _, a := range r.items {
		if a.TenantID == tenantID && a.BusinessServiceID == id {
			out = append(out, a)
		}
	}
	return out, nil
}
