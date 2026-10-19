package findings

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	defaultFindingPageSize = 50
	maxFindingPageSize     = 100
)

// ListPage reads an ID-keyset page. It never falls back to loading a full
// engagement when the configured repository lacks bounded-read support.
func (s *Service) ListPage(ctx context.Context, engagementID, afterID shared.ID, limit int) (ports.FindingPage, error) {
	if engagementID.IsZero() {
		return ports.FindingPage{}, fmt.Errorf("%w: engagement is required", shared.ErrValidation)
	}
	if limit == 0 {
		limit = defaultFindingPageSize
	}
	if limit < 0 || limit > maxFindingPageSize {
		return ports.FindingPage{}, fmt.Errorf("%w: finding page limit must be between 1 and %d", shared.ErrValidation, maxFindingPageSize)
	}
	reader, ok := s.repo.(ports.FindingPageReader)
	if !ok {
		return ports.FindingPage{}, fmt.Errorf("%w: finding repository does not support bounded pages", shared.ErrValidation)
	}
	page, err := reader.ListFindingPage(ctx, engagementID, afterID, limit)
	if err != nil {
		return ports.FindingPage{}, fmt.Errorf("list finding page: %w", err)
	}
	if len(page.Items) > limit {
		return ports.FindingPage{}, fmt.Errorf("%w: finding repository returned an oversized page", shared.ErrValidation)
	}
	return page, nil
}

// Get reads one finding from the already-scoped engagement without exposing an
// internal context identifier to transport callers.
func (s *Service) Get(ctx context.Context, engagementID, findingID shared.ID) (finding.Finding, error) {
	if engagementID.IsZero() || findingID.IsZero() {
		return finding.Finding{}, fmt.Errorf("%w: finding scope is required", shared.ErrValidation)
	}
	f, err := s.repo.GetByEngagementAndID(ctx, engagementID, findingID)
	if err != nil {
		return finding.Finding{}, fmt.Errorf("get finding: %w", err)
	}
	return f, nil
}
