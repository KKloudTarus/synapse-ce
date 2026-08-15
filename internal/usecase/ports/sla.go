package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sla"
)

// SLAStore is the tenant-isolated source of truth for remediation governance. Assessments and
// policies are immutable; their current pointers may advance. SaveTransition is the only operation
// allowed to modify human remediation state and must enforce event.BeforeVersion atomically.
type SLAStore interface {
	PutPolicy(ctx context.Context, policy sla.Policy, activate bool) (created bool, err error)
	ActivePolicy(ctx context.Context, tenantID shared.ID) (sla.Policy, error)
	PolicyHistory(ctx context.Context, tenantID shared.ID) ([]sla.Policy, error)

	UpsertAssessment(ctx context.Context, assessment sla.Assessment) (sla.AssessmentUpsertResult, error)
	Current(ctx context.Context, tenantID, engagementID, findingID shared.ID) (sla.Current, error)
	ListCurrent(ctx context.Context, tenantID, engagementID shared.ID) ([]sla.Current, error)
	AssessmentHistory(ctx context.Context, tenantID, engagementID, findingID shared.ID) ([]sla.Assessment, error)

	SaveTransition(ctx context.Context, next sla.Lifecycle, event sla.LifecycleEvent) error
	LifecycleEvents(ctx context.Context, tenantID, engagementID, findingID shared.ID) ([]sla.LifecycleEvent, error)
}

// SLAAssessor is the narrow integration boundary used by finding-producing pipelines. Keeping the
// input in the domain means SCA and continuous intelligence do not depend on the concrete SLA
// use-case, and deployments can leave the capability unwired while SYNAPSE_SLA_ENABLED is false.
type SLAAssessor interface {
	Assess(ctx context.Context, input sla.AssessmentInput) (sla.View, error)
}

// FindingSLAAssessor is the pipeline-facing convenience projection for finding producers that do not
// own continuous-intelligence detail. The concrete service derives only signals present on the row.
type FindingSLAAssessor interface {
	AssessFinding(ctx context.Context, tenantID shared.ID, item finding.Finding) (sla.View, error)
}
