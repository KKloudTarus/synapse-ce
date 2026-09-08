package assessmentsnapshot_test

import (
	"context"
	"errors"
	"testing"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	uc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type boundedHistoryStore struct {
	ports.AssessmentSnapshotRepository
	query ports.AssessmentSnapshotListQuery
	more  bool
}

func (store *boundedHistoryStore) ListAssessmentSnapshots(_ context.Context, query ports.AssessmentSnapshotListQuery) (ports.AssessmentSnapshotPage, error) {
	store.query = query
	return ports.AssessmentSnapshotPage{Items: make([]domain.Snapshot, 100), HasMore: store.more}, nil
}

func TestComparisonHistoryNeverSilentlyTruncates(t *testing.T) {
	store := &boundedHistoryStore{}
	items, err := uc.ReadComparisonHistory(context.Background(), store, "tenant", "assessment")
	if err != nil || len(items) != 100 || store.query.Limit != 100 || store.query.TenantID != "tenant" || store.query.AssessmentID != "assessment" {
		t.Fatalf("bounded history: %d %+v %v", len(items), store.query, err)
	}
	store.more = true
	if items, err := uc.ReadComparisonHistory(context.Background(), store, "tenant", "assessment"); !errors.Is(err, shared.ErrValidation) || len(items) != 0 {
		t.Fatalf("truncated history accepted: %d %v", len(items), err)
	}
}
