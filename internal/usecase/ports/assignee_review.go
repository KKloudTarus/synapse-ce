package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type AssigneeReviewItem struct {
	EngagementID   shared.ID `json:"engagement_id"`
	FindingID      shared.ID `json:"finding_id"`
	LegacyAssignee string    `json:"legacy_assignee"`
	Reason         string    `json:"reason"`
}

type AssigneeReviewReader interface {
	ListAssigneeReview(context.Context, shared.ID, shared.ID, shared.ID, int) ([]AssigneeReviewItem, error)
}
