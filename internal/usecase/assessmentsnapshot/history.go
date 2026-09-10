package assessmentsnapshot

import (
	"context"
	"fmt"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ReadComparisonHistory bounds internal ancestry/review reads as well as the
// public history endpoint. Refuse oversized histories rather than silently omit
// evidence from a comparison. The canonical MVP targets ten snapshots per member.
func ReadComparisonHistory(ctx context.Context, store ports.AssessmentSnapshotRepository, tenantID, assessmentID shared.ID) ([]domain.Snapshot, error) {
	page, err := store.ListAssessmentSnapshots(ctx, ports.AssessmentSnapshotListQuery{
		TenantID: tenantID, AssessmentID: assessmentID, Limit: 100,
	})
	if err != nil {
		return nil, err
	}
	if page.HasMore {
		return nil, fmt.Errorf("%w: snapshot history exceeds supported comparison limit", shared.ErrValidation)
	}
	return page.Items, nil
}
