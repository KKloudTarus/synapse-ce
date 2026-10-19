package memory

import (
	"context"
	"fmt"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.FindingPageReader = (*FindingRepository)(nil)

// ListFindingPage mirrors the PostgreSQL keyset contract for local/test runs.
func (r *FindingRepository) ListFindingPage(_ context.Context, engagementID, afterID shared.ID, limit int) (ports.FindingPage, error) {
	if engagementID.IsZero() || limit < 1 {
		return ports.FindingPage{}, fmt.Errorf("%w: finding page arguments are invalid", shared.ErrValidation)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	items := make([]finding.Finding, 0, len(r.data[engagementID]))
	byKey := r.data[engagementID]
	for _, item := range byKey {
		if item.ID > afterID {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(left, right int) bool { return items[left].ID < items[right].ID })
	page := ports.FindingPage{Items: make([]finding.Finding, 0, min(limit, len(items)))}
	for index, item := range items {
		if index >= limit {
			page.NextAfter = page.Items[len(page.Items)-1].ID
			break
		}
		page.Items = append(page.Items, cloneFinding(item))
	}
	return page, nil
}
