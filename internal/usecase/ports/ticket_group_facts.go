package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TicketGroupFact carries stored native-finding facts and observed attribution, never an asset
// inferred from prose. Empty AssetID/AssetName means no attribution is known.
type TicketGroupFact struct {
	EngagementID          shared.ID
	FindingID             shared.ID
	AssetID               shared.ID
	AssetName             string
	Title                 string
	Severity              shared.Severity
	Status                finding.Status
	FindingVersion        int
	GroupRevision         int
	ExternalNotifications notification.EngagementNotifications
}

type TicketGroupFactsReader interface {
	GroupTicketFacts(ctx context.Context, tenant, mappingID, projectID shared.ID, vulnerability string, candidate TicketGroupMember) ([]TicketGroupFact, error)
}
