package ports

import (
	"context"
	"time"

	cycledom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type AssessmentCycleIntegrityState string

const (
	AssessmentCycleIntegrityRunning   AssessmentCycleIntegrityState = "running"
	AssessmentCycleIntegrityCompleted AssessmentCycleIntegrityState = "completed"
	AssessmentCycleIntegrityCancelled AssessmentCycleIntegrityState = "cancelled"
	AssessmentCycleIntegrityFailed    AssessmentCycleIntegrityState = "failed"
)

type AssessmentCycleIntegrityRun struct {
	TenantID             shared.ID
	ID                   shared.ID
	BatchSize            int
	SnapshotAt           time.Time
	CheckpointAssessment shared.ID
	State                AssessmentCycleIntegrityState
	LeaseOwner           string
	LeaseExpiresAt       time.Time
	ScannedCount         int
	CleanCount           int
	FindingCount         int
	CreatedBy            string
	CreatedAt            time.Time
	UpdatedAt            time.Time
	CompletedAt          *time.Time
}

type AssessmentCycleIntegrityAcquireRequest struct {
	Run           AssessmentCycleIntegrityRun
	LeaseDuration time.Duration
}

type AssessmentCycleIntegrityMember struct {
	Member           cycledom.Member
	AssessmentExists bool
	AssessmentStatus engdom.Status
	BusinessAssetID  shared.ID
	ProjectID        shared.ID
}

type AssessmentCycleIntegrityCycle struct {
	Cycle                  cycledom.AssessmentCycle
	CycleExists            bool
	SubjectMembershipCount int
	Members                []AssessmentCycleIntegrityMember
}

type AssessmentCycleIntegritySubject struct {
	TenantID     shared.ID
	AssessmentID shared.ID
	Cycles       []AssessmentCycleIntegrityCycle
}

type AssessmentCycleIntegritySubjectResult struct {
	TenantID     shared.ID
	RunID        shared.ID
	AssessmentID shared.ID
	Clean        bool
	FindingCount int
	ProcessedAt  time.Time
}

type AssessmentCycleIntegrityFinding struct {
	TenantID     shared.ID
	RunID        shared.ID
	OccurrenceID string
	AssessmentID shared.ID
	CycleID      shared.ID
	MemberID     shared.ID
	ReasonCode   string
	Severity     string
	RepairPlan   []byte
	DetectedAt   time.Time
}

type AssessmentCycleIntegritySource interface {
	ListAssessmentCycleIntegritySubjects(ctx context.Context, tenantID, after shared.ID, snapshotAt time.Time, limit int) ([]AssessmentCycleIntegritySubject, error)
	CountAssessmentCycleIntegritySubjects(ctx context.Context, tenantID shared.ID, snapshotAt time.Time) (eligible int, memberships int, err error)
}

type AssessmentCycleIntegrityStore interface {
	AcquireAssessmentCycleIntegrityRun(ctx context.Context, request AssessmentCycleIntegrityAcquireRequest) (run AssessmentCycleIntegrityRun, resumed bool, err error)
	GetAssessmentCycleIntegrityRun(ctx context.Context, tenantID, runID shared.ID) (AssessmentCycleIntegrityRun, error)
	GetAssessmentCycleIntegritySubject(ctx context.Context, tenantID, runID, assessmentID shared.ID) (AssessmentCycleIntegritySubjectResult, error)
	ListAssessmentCycleIntegrityFindings(ctx context.Context, tenantID, runID shared.ID) ([]AssessmentCycleIntegrityFinding, error)
	SaveAssessmentCycleIntegritySubject(ctx context.Context, result AssessmentCycleIntegritySubjectResult, findings []AssessmentCycleIntegrityFinding) (created bool, err error)
	AdvanceAssessmentCycleIntegrityRun(ctx context.Context, tenantID, runID shared.ID, leaseOwner string, checkpoint shared.ID, now time.Time, leaseDuration time.Duration) (AssessmentCycleIntegrityRun, error)
	FinishAssessmentCycleIntegrityRun(ctx context.Context, tenantID, runID shared.ID, leaseOwner string, state AssessmentCycleIntegrityState, now time.Time) (AssessmentCycleIntegrityRun, error)
}
