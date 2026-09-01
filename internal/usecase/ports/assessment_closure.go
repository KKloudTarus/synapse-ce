package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentclosure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type AssessmentClosureCommit struct {
	Manifest             *assessmentclosure.Manifest
	Cycle                *assessmentcycle.AssessmentCycle
	ExpectedCycleVersion int64
}

type AssessmentClosureReopen struct {
	Manifest             *assessmentclosure.Manifest
	Cycle                *assessmentcycle.AssessmentCycle
	ExpectedCycleVersion int64
}

// AssessmentClosureRepository persists immutable closure history and the matching Cycle transition atomically.
type AssessmentClosureRepository interface {
	NextManifestVersion(ctx context.Context, tenantID, cycleID shared.ID) (int64, error)
	CommitClosure(ctx context.Context, commit AssessmentClosureCommit) error
	ReopenClosure(ctx context.Context, reopen AssessmentClosureReopen) error
	GetClosureManifest(ctx context.Context, tenantID, cycleID, manifestID shared.ID) (*assessmentclosure.Manifest, error)
	GetActiveClosureManifest(ctx context.Context, tenantID, cycleID shared.ID) (*assessmentclosure.Manifest, error)
	ListClosureManifests(ctx context.Context, tenantID, cycleID shared.ID) ([]assessmentclosure.Manifest, error)
}
