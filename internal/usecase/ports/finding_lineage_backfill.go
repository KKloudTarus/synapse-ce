package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type FindingLineageBackfillState string

const (
	FindingLineageBackfillRunning   FindingLineageBackfillState = "running"
	FindingLineageBackfillCompleted FindingLineageBackfillState = "completed"
	FindingLineageBackfillCancelled FindingLineageBackfillState = "cancelled"
	FindingLineageBackfillFailed    FindingLineageBackfillState = "failed"
)

type FindingLineageBackfillRun struct {
	TenantID                  shared.ID
	ID                        shared.ID
	SchemaVersion             int
	DryRun                    bool
	BatchSize                 int
	ProducerFilters           []string
	SnapshotAt                time.Time
	CheckpointFinding         shared.ID
	State                     FindingLineageBackfillState
	LeaseOwner                string
	LeaseToken                shared.ID
	LeaseExpiresAt            time.Time
	ProcessedCount            int
	ObservationCreatedCount   int
	ProvisionalCandidateCount int
	SkippedCount              int
	CreatedBy                 string
	CreatedAt                 time.Time
	UpdatedAt                 time.Time
	CompletedAt               *time.Time
}

type FindingLineageBackfillAcquireRequest struct {
	Run               FindingLineageBackfillRun
	InitialCheckpoint shared.ID
	LeaseDuration     time.Duration
}

type FindingLineageBackfillItem struct {
	TenantID        shared.ID
	RunID           shared.ID
	AssessmentID    shared.ID
	CycleID         shared.ID
	SnapshotID      shared.ID
	SourceFindingID shared.ID
	SchemaVersion   int
	MatcherVersion  int
	IdempotencyKey  string
	SourceHash      string
	Outcome         string
	ReasonCode      string
	ProcessedAt     time.Time
}

type FindingLineageBackfillSourceRow struct {
	TenantID             shared.ID
	AssessmentID         shared.ID
	CycleID              shared.ID
	SnapshotID           shared.ID
	SnapshotContentHash  string
	OwnershipValid       bool
	FindingID            shared.ID
	Kind                 finding.Kind
	RuleKey              string
	DedupKey             string
	AdvisoryID           string
	OccurrenceID         shared.ID
	ComponentFingerprint string
	Severity             shared.Severity
	RiskScore            float64
	Reachability         string
	SourceLocation       *finding.SourceLocation
	ObservedAt           time.Time
}

type FindingLineageBackfillSource interface {
	ListFindingLineageBackfillSources(ctx context.Context, tenantID, after shared.ID, snapshotAt time.Time, producerFilters []string, limit int) ([]FindingLineageBackfillSourceRow, error)
}

type FindingLineageBackfillStore interface {
	AcquireFindingLineageBackfillRun(ctx context.Context, request FindingLineageBackfillAcquireRequest) (run FindingLineageBackfillRun, resumed bool, err error)
	GetFindingLineageBackfillRun(ctx context.Context, tenantID, runID shared.ID) (FindingLineageBackfillRun, error)
	GetFindingLineageBackfillItem(ctx context.Context, tenantID, runID, sourceFindingID shared.ID) (FindingLineageBackfillItem, error)
	CommitFindingLineageBackfillItem(ctx context.Context, tenantID, runID, leaseToken shared.ID, now time.Time, build func(context.Context) (FindingLineageBackfillItem, error)) (item FindingLineageBackfillItem, created bool, err error)
	AdvanceFindingLineageBackfillRun(ctx context.Context, tenantID, runID shared.ID, leaseOwner string, leaseToken, checkpoint shared.ID, now time.Time, leaseDuration time.Duration) (FindingLineageBackfillRun, error)
	FinishFindingLineageBackfillRun(ctx context.Context, tenantID, runID shared.ID, leaseOwner string, leaseToken shared.ID, state FindingLineageBackfillState, now time.Time) (FindingLineageBackfillRun, error)
}
