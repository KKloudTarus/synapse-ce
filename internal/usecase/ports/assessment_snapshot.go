package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type AssessmentSnapshotDefault struct {
	TenantID     shared.ID
	AssessmentID shared.ID
	SnapshotID   shared.ID
	Version      int64
	UpdatedAt    time.Time
	UpdatedBy    string
}

type AssessmentSnapshotRepository interface {
	CreateFinalizedCAS(ctx context.Context, snapshot *assessmentsnapshot.Snapshot, expectedDefaultVersion int64) (*assessmentsnapshot.Snapshot, bool, error)
	CreateLegacyProjection(ctx context.Context, snapshot *assessmentsnapshot.Snapshot) (*assessmentsnapshot.Snapshot, bool, error)
	Get(ctx context.Context, tenantID, snapshotID shared.ID) (*assessmentsnapshot.Snapshot, error)
	GetByRequestKey(ctx context.Context, tenantID, assessmentID shared.ID, requestKey string) (*assessmentsnapshot.Snapshot, error)
	GetDefault(ctx context.Context, tenantID, assessmentID shared.ID) (*assessmentsnapshot.Snapshot, AssessmentSnapshotDefault, error)
	ListByAssessment(ctx context.Context, tenantID, assessmentID shared.ID) ([]assessmentsnapshot.Snapshot, error)
}

type AssessmentSnapshotDefaultReader interface {
	GetDefault(ctx context.Context, tenantID, assessmentID shared.ID) (*assessmentsnapshot.Snapshot, AssessmentSnapshotDefault, error)
}

// AssessmentSnapshotRunReader exposes the tenant-scoped provenance reads used by
// snapshot finalization and backfill without coupling them to legacy scan-run writes.
type AssessmentSnapshotRunReader interface {
	GetScanRun(ctx context.Context, tenantID shared.ID, runID string) (scanrun.ScanRun, error)
	ListScanRuns(ctx context.Context, tenantID, engagementID shared.ID) ([]scanrun.ScanRun, error)
}

type AssessmentSnapshotBackfillState string

const (
	AssessmentSnapshotBackfillRunning   AssessmentSnapshotBackfillState = "running"
	AssessmentSnapshotBackfillCompleted AssessmentSnapshotBackfillState = "completed"
	AssessmentSnapshotBackfillCancelled AssessmentSnapshotBackfillState = "cancelled"
	AssessmentSnapshotBackfillFailed    AssessmentSnapshotBackfillState = "failed"
)

type AssessmentSnapshotBackfillRun struct {
	TenantID             shared.ID
	ID                   shared.ID
	SchemaVersion        int
	DryRun               bool
	BatchSize            int
	SnapshotAt           time.Time
	CheckpointAssessment shared.ID
	State                AssessmentSnapshotBackfillState
	LeaseOwner           string
	LeaseToken           shared.ID
	LeaseExpiresAt       time.Time
	ProcessedCount       int
	CreatedCount         int
	WouldCreateCount     int
	SkippedCount         int
	FailedCount          int
	CreatedBy            string
	CreatedAt            time.Time
	UpdatedAt            time.Time
	CompletedAt          *time.Time
}

type AssessmentSnapshotBackfillAcquireRequest struct {
	Run               AssessmentSnapshotBackfillRun
	InitialCheckpoint shared.ID
	LeaseDuration     time.Duration
}

type AssessmentSnapshotBackfillItem struct {
	TenantID       shared.ID
	RunID          shared.ID
	AssessmentID   shared.ID
	SchemaVersion  int
	IdempotencyKey string
	SourceHash     string
	SnapshotID     shared.ID
	Outcome        string
	ReasonCode     string
	Retryable      bool
	RepairGuidance string
	ProcessedAt    time.Time
}

type AssessmentSnapshotBackfillSource interface {
	ListAssessmentSnapshotBackfillEngagements(ctx context.Context, tenantID, after shared.ID, snapshotAt time.Time, limit int) ([]*engdom.Engagement, error)
}

type AssessmentSnapshotBackfillStore interface {
	AcquireAssessmentSnapshotBackfillRun(ctx context.Context, request AssessmentSnapshotBackfillAcquireRequest) (run AssessmentSnapshotBackfillRun, resumed bool, err error)
	GetAssessmentSnapshotBackfillRun(ctx context.Context, tenantID, runID shared.ID) (AssessmentSnapshotBackfillRun, error)
	GetAssessmentSnapshotBackfillItem(ctx context.Context, tenantID, runID, assessmentID shared.ID) (AssessmentSnapshotBackfillItem, error)
	CommitAssessmentSnapshotBackfillItem(ctx context.Context, tenantID, runID, leaseToken shared.ID, now time.Time, build func(context.Context) (AssessmentSnapshotBackfillItem, error)) (item AssessmentSnapshotBackfillItem, created bool, err error)
	AdvanceAssessmentSnapshotBackfillRun(ctx context.Context, tenantID, runID shared.ID, leaseOwner string, leaseToken, checkpoint shared.ID, now time.Time, leaseDuration time.Duration) (AssessmentSnapshotBackfillRun, error)
	FinishAssessmentSnapshotBackfillRun(ctx context.Context, tenantID, runID shared.ID, leaseOwner string, leaseToken shared.ID, state AssessmentSnapshotBackfillState, now time.Time) (AssessmentSnapshotBackfillRun, error)
}
