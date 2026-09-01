package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcomparison"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type AssessmentComparisonVerification struct {
	ID                  shared.ID
	IdentityID          shared.ID
	EffectiveSnapshotID shared.ID
	State               string
	Remediated          bool
}

type AssessmentComparisonVerificationReader interface {
	ListEffectiveComparisonVerifications(context.Context, shared.ID, shared.ID, []shared.ID) ([]AssessmentComparisonVerification, error)
}

type AssessmentComparisonObserver interface {
	ObserveAssessmentComparison(status, mode, reason string)
}

type AssessmentComparisonBacklog struct {
	Queued         int
	Generating     int
	Failed         int
	DeadLettered   int
	OldestActiveAt *time.Time
}

func (backlog AssessmentComparisonBacklog) Active() int {
	return backlog.Queued + backlog.Generating
}

type AssessmentComparisonBacklogReader interface {
	GetAssessmentComparisonBacklog(context.Context, shared.ID) (AssessmentComparisonBacklog, error)
}

type AssessmentComparisonBacklogObserver interface {
	ObserveAssessmentComparisonBacklog(tenantID string, backlog AssessmentComparisonBacklog, observedAt time.Time)
}

type AssessmentComparisonGenerationObserver interface {
	ObserveAssessmentComparisonGeneration(tenantID, mode, status string, fingerprintVersion, riskModelVersion, itemCount int, duration time.Duration)
}

type AssessmentComparisonRepairRepository interface {
	AssessmentComparisonBacklogReader
	GetMetadata(context.Context, shared.ID, shared.ID) (assessmentcomparison.Comparison, error)
	ListFailedAssessmentComparisons(context.Context, shared.ID, int) ([]assessmentcomparison.Comparison, error)
}

type AssessmentComparisonItemFilter struct {
	AfterPosition int
	Limit         int
	Presence      string
	ChangeFlag    assessmentcomparison.ChangeFlag
	Severity      shared.Severity
	ProducerKind  string
	FindingKind   string
	Disposition   string
	ReviewState   string
}

type AssessmentComparisonItemPage struct {
	Items        []assessmentcomparison.Item
	NextPosition int
	HasMore      bool
}

type AssessmentComparisonRepository interface {
	CreateQueued(context.Context, assessmentcomparison.Comparison) (assessmentcomparison.Comparison, bool, error)
	Get(context.Context, shared.ID, shared.ID) (assessmentcomparison.Comparison, error)
	GetMetadata(context.Context, shared.ID, shared.ID) (assessmentcomparison.Comparison, error)
	GetByInputHash(context.Context, shared.ID, string) (assessmentcomparison.Comparison, error)
	ListMetadataByCycle(context.Context, shared.ID, shared.ID) ([]assessmentcomparison.Comparison, error)
	GetItem(context.Context, shared.ID, shared.ID, shared.ID) (assessmentcomparison.Item, error)
	ListItems(context.Context, shared.ID, shared.ID, AssessmentComparisonItemFilter) (AssessmentComparisonItemPage, error)
	UpdateCAS(context.Context, assessmentcomparison.Comparison, int64) error
}
