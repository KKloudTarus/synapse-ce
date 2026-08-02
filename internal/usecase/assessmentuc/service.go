package assessmentuc

import (
	"context"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type BusinessServiceReader interface {
	GetBusinessService(context.Context, shared.ID) (asset.BusinessService, error)
}

type Service struct {
	repo             ports.AssessmentRepository
	businessServices BusinessServiceReader
	clock            ports.Clock
	ids              ports.IDGenerator
}

func New(repo ports.AssessmentRepository, businessServices BusinessServiceReader, clock ports.Clock, ids ports.IDGenerator) (*Service, error) {
	if repo == nil || businessServices == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("assessment dependencies are required")
	}
	return &Service{repo: repo, businessServices: businessServices, clock: clock, ids: ids}, nil
}

type AssetInput struct {
	Name   string
	Client string
}

type CreateInput struct {
	TenantID, BusinessServiceID shared.ID
	Actor, Name, Objective      string
	Policy                      assessment.Policy
	Assets                      []AssetInput
}

func (s *Service) Create(ctx context.Context, in CreateInput) (assessment.Assessment, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID != in.TenantID {
		return assessment.Assessment{}, fmt.Errorf("%w: assessment tenant context", shared.ErrValidation)
	}
	if len(in.Assets) == 0 || len(in.Assets) > 128 {
		return assessment.Assessment{}, fmt.Errorf("%w: assessment requires 1-128 assets", shared.ErrValidation)
	}
	if _, err := s.businessServices.GetBusinessService(ctx, in.BusinessServiceID); err != nil {
		return assessment.Assessment{}, err
	}
	now := s.clock.Now()
	a, err := assessment.New(s.ids.NewID(), in.TenantID, in.BusinessServiceID, in.Name, in.Objective, in.Policy, now)
	if err != nil {
		return assessment.Assessment{}, err
	}
	a.Audit.CreatedBy, a.Audit.UpdatedBy = in.Actor, in.Actor
	children := make([]*engagement.Engagement, 0, len(in.Assets))
	for _, input := range in.Assets {
		e, err := engagement.New(s.ids.NewID(), in.TenantID, strings.TrimSpace(input.Name), strings.TrimSpace(input.Client), now)
		if err != nil {
			return assessment.Assessment{}, err
		}
		e.AssessmentID = a.ID
		e.Audit.CreatedBy, e.Audit.UpdatedBy = in.Actor, in.Actor
		children = append(children, e)
	}
	if err := s.repo.Create(ctx, a, children); err != nil {
		return assessment.Assessment{}, err
	}
	return a, nil
}

func (s *Service) Get(ctx context.Context, businessServiceID, assessmentID shared.ID) (assessment.Assessment, error) {
	if _, err := s.businessServices.GetBusinessService(ctx, businessServiceID); err != nil {
		return assessment.Assessment{}, err
	}
	a, err := s.repo.Get(ctx, assessmentID)
	if err != nil {
		return assessment.Assessment{}, err
	}
	if a.BusinessServiceID != businessServiceID {
		return assessment.Assessment{}, fmt.Errorf("assessment parent: %w", shared.ErrNotFound)
	}
	return a, nil
}

func (s *Service) List(ctx context.Context, businessServiceID shared.ID) ([]assessment.Assessment, error) {
	if _, err := s.businessServices.GetBusinessService(ctx, businessServiceID); err != nil {
		return nil, err
	}
	return s.repo.ListByBusinessService(ctx, businessServiceID)
}
