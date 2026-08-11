package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/purplecoverage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// PurpleCoverageStore persists purple-team coverage records (#426): the per-technique verdict for an
// emulation run, keyed by (run, technique) so coverage over time is a trend and a covered->uncovered
// transition is a detectable regression. Tenant-scoped through the chokepoint.
type PurpleCoverageStore interface {
	// SaveCoverage upserts a run's coverage records (immutable per run+technique) under the ctx tenant.
	SaveCoverage(ctx context.Context, records []purplecoverage.Coverage) error
	// ListByRun returns one run's coverage records, tenant-scoped.
	ListByRun(ctx context.Context, runID shared.ID) ([]purplecoverage.Coverage, error)
	// ListByEngagement returns all coverage records for an engagement (across runs), oldest first, so a
	// trend across runs is queryable. Tenant-scoped.
	ListByEngagement(ctx context.Context, engagementID shared.ID) ([]purplecoverage.Coverage, error)
}
