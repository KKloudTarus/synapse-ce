package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// AssessmentRepository persists a Business Service assessment atomically with its
// required Engagement children.
type AssessmentRepository interface {
	Create(context.Context, assessment.Assessment, []*engagement.Engagement) error
	Get(context.Context, shared.ID) (assessment.Assessment, error)
	ListByBusinessService(context.Context, shared.ID) ([]assessment.Assessment, error)
}
