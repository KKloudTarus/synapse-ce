package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// FindingPage is a stable, ID-ordered slice of one engagement's findings.
// NextAfter is empty when no further row exists.
type FindingPage struct {
	Items     []finding.Finding
	NextAfter shared.ID
}

// FindingPageReader is intentionally optional on FindingRepository so existing
// readers keep their narrow contract. Callers that require bounded reads must
// fail closed when the concrete repository does not implement it.
type FindingPageReader interface {
	ListFindingPage(ctx context.Context, engagementID, afterID shared.ID, limit int) (FindingPage, error)
}
