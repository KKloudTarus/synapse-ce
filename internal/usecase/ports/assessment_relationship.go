package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentrelationship"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type AssessmentRelationshipCandidateFilter struct {
	Status string
	Limit  int
}

type AssessmentRelationshipRepository interface {
	CreateCandidate(context.Context, assessmentrelationship.Candidate) (assessmentrelationship.Record, bool, error)
	GetCandidate(context.Context, shared.ID, shared.ID) (assessmentrelationship.Record, error)
	ListCandidates(context.Context, shared.ID, AssessmentRelationshipCandidateFilter) ([]assessmentrelationship.Record, error)
	DecideCandidateCAS(context.Context, assessmentrelationship.Decision, *assessmentrelationship.RepairPlan) (assessmentrelationship.Record, bool, error)
}

type AssessmentRelationshipObserver interface {
	ObserveAssessmentRelationshipCandidate(outcome, confidence string)
	ObserveAssessmentRelationshipDecision(action, outcome string)
}
