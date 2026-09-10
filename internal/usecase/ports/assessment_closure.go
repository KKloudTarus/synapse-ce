package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentclosure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sla"
)

type AssessmentClosureReferenceQuery struct {
	CycleID         shared.ID
	SnapshotIDs     []shared.ID
	VerificationIDs []shared.ID
	AsOfAt          time.Time
}

// AssessmentClosureDecisionReader binds closure manifests to the exact
// immutable Finding/SLA/retest artifacts used by the decision and resolves
// those artifacts again before a historical report is rendered.
type AssessmentClosureDecisionReader interface {
	ListAssessmentClosureReferences(context.Context, shared.ID, AssessmentClosureReferenceQuery) ([]assessmentclosure.Reference, error)
	ResolveAssessmentClosureReference(context.Context, shared.ID, AssessmentClosureReferenceQuery, assessmentclosure.Reference) error
}

// AssessmentClosureReferenceBatchResolver resolves a report's retained sources
// in one pass, avoiding a complete history reload for each reference.
type AssessmentClosureReferenceBatchResolver interface {
	ResolveAssessmentClosureReferences(context.Context, shared.ID, AssessmentClosureReferenceQuery, []assessmentclosure.Reference) error
}

// Closure history batches preserve append-only artifacts, including superseded
// decisions. Implementations accept at most 1,000 Finding IDs and must never
// silently truncate histories: historical reports depend on exact source hashes.
type RetestHistoryBatchReader interface {
	RetestHistories(context.Context, shared.ID, []shared.ID) (map[shared.ID][]finding.Retest, error)
}

type SLAHistoryBatch struct {
	Assessments map[shared.ID][]sla.Assessment
	Events      map[shared.ID][]sla.LifecycleEvent
}

type SLAHistoryBatchReader interface {
	SLAHistories(context.Context, shared.ID, shared.ID, []shared.ID) (SLAHistoryBatch, error)
}

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
