package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type AssessmentClosureReportArtifact struct {
	TenantID                shared.ID
	CycleID                 shared.ID
	ManifestID              shared.ID
	RendererContractVersion string
	ContentHash             string
	Content                 []byte
	GeneratedAt             time.Time
}

type AssessmentClosureReportStore interface {
	SaveClosureReport(ctx context.Context, report AssessmentClosureReportArtifact) (AssessmentClosureReportArtifact, bool, error)
	GetClosureReport(ctx context.Context, tenantID, cycleID, manifestID shared.ID, rendererVersion string) (AssessmentClosureReportArtifact, error)
}

type AssessmentClosureReportObserver interface {
	ObserveAssessmentClosureReport(outcome, reason string)
}
