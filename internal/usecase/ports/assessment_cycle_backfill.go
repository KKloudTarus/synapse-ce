package ports

import (
	"context"
	"time"

	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type AssessmentCycleBackfillState string

const (
	AssessmentCycleBackfillRunning   AssessmentCycleBackfillState = "running"
	AssessmentCycleBackfillCompleted AssessmentCycleBackfillState = "completed"
	AssessmentCycleBackfillCancelled AssessmentCycleBackfillState = "cancelled"
	AssessmentCycleBackfillFailed    AssessmentCycleBackfillState = "failed"
)

type AssessmentCycleBackfillRun struct {
	TenantID             shared.ID
	ID                   shared.ID
	SchemaVersion        int
	DryRun               bool
	BatchSize            int
	SnapshotAt           time.Time
	CheckpointAssessment shared.ID
	State                AssessmentCycleBackfillState
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

type AssessmentCycleBackfillAcquireRequest struct {
	Run               AssessmentCycleBackfillRun
	InitialCheckpoint shared.ID
	LeaseDuration     time.Duration
}

type AssessmentCycleBackfillItem struct {
	TenantID       shared.ID
	RunID          shared.ID
	AssessmentID   shared.ID
	SchemaVersion  int
	IdempotencyKey string
	CycleID        shared.ID
	Outcome        string
	ReasonCode     string
	Retryable      bool
	RepairGuidance string
	ProcessedAt    time.Time
}

type AssessmentCycleBackfillSource interface {
	ListAssessmentCycleBackfillEngagements(ctx context.Context, tenantID, after shared.ID, snapshotAt time.Time, limit int) ([]*engdom.Engagement, error)
}

type AssessmentCycleBackfillStore interface {
	AcquireAssessmentCycleBackfillRun(ctx context.Context, request AssessmentCycleBackfillAcquireRequest) (run AssessmentCycleBackfillRun, resumed bool, err error)
	GetAssessmentCycleBackfillRun(ctx context.Context, tenantID, runID shared.ID) (AssessmentCycleBackfillRun, error)
	GetAssessmentCycleBackfillItem(ctx context.Context, tenantID, runID, assessmentID shared.ID) (AssessmentCycleBackfillItem, error)
	CommitAssessmentCycleBackfillItem(ctx context.Context, tenantID, runID, leaseToken shared.ID, now time.Time, build func(context.Context) (AssessmentCycleBackfillItem, error)) (item AssessmentCycleBackfillItem, created bool, err error)
	AdvanceAssessmentCycleBackfillRun(ctx context.Context, tenantID, runID shared.ID, leaseOwner string, leaseToken, checkpoint shared.ID, now time.Time, leaseDuration time.Duration) (AssessmentCycleBackfillRun, error)
	FinishAssessmentCycleBackfillRun(ctx context.Context, tenantID, runID shared.ID, leaseOwner string, leaseToken shared.ID, state AssessmentCycleBackfillState, now time.Time) (AssessmentCycleBackfillRun, error)
}
