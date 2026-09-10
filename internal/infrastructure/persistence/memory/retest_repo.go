package memory

import (
	"context"
	"sort"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// RetestRepository is an in-memory ports.RetestRepository for dev/tests.
type RetestRepository struct {
	mu   sync.Mutex
	rows map[shared.ID][]finding.Retest
}

// NewRetestRepository returns an empty in-memory retest store.
func NewRetestRepository() *RetestRepository {
	return &RetestRepository{rows: make(map[shared.ID][]finding.Retest)}
}

var _ ports.RetestRepository = (*RetestRepository)(nil)

// Add appends a retest.
func (r *RetestRepository) Add(ctx context.Context, rt finding.Retest) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	tenantID, _ := shared.TenantFrom(ctx)
	tenantID = shared.TenantOrDefault(tenantID)
	r.rows[tenantID] = append(r.rows[tenantID], rt)
	return nil
}

// ListByEngagementFinding returns a finding's retests oldest-first, engagement-scoped.
func (r *RetestRepository) ListByEngagementFinding(ctx context.Context, engagementID, findingID shared.ID) ([]finding.Retest, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []finding.Retest{}
	tenantID, _ := shared.TenantFrom(ctx)
	for _, rt := range r.rows[shared.TenantOrDefault(tenantID)] {
		if rt.FindingID == findingID && rt.EngagementID == engagementID {
			out = append(out, rt)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out, nil
}

func (r *RetestRepository) LatestByEngagementFindings(ctx context.Context, engagementID shared.ID, findingIDs []shared.ID) (map[shared.ID]finding.Retest, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() || engagementID.IsZero() || len(findingIDs) > 1000 {
		return nil, shared.ErrValidation
	}
	requested := make(map[shared.ID]bool, len(findingIDs))
	for _, id := range findingIDs {
		if id.IsZero() {
			return nil, shared.ErrValidation
		}
		requested[id] = true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[shared.ID]finding.Retest)
	for _, value := range r.rows[tenantID] {
		if value.EngagementID != engagementID || !requested[value.FindingID] {
			continue
		}
		previous, exists := out[value.FindingID]
		if !exists || value.At.After(previous.At) || value.At.Equal(previous.At) && value.ID > previous.ID {
			out[value.FindingID] = value
		}
	}
	return out, nil
}

var _ ports.RetestLatestReader = (*RetestRepository)(nil)
