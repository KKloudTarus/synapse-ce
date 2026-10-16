package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// NotificationFindingFacts is the tenant-bound identity snapshot captured with
// a finding notification source. IDs are present only for active users in the
// same tenant; a producer's opaque actor string never becomes an identity by
// itself.
type NotificationFindingFacts struct {
	ActorUserID    shared.ID
	ActorName      string
	AssigneeUserID shared.ID
	TeamID         shared.ID
	LeadUserID     shared.ID
}

// NotificationFindingFactsReader reads the small immutable-at-capture subset
// of finding facts that cannot safely be reconstructed by the notification
// worker after mutable identities or ownership change.
type NotificationFindingFactsReader interface {
	SnapshotFindingNotificationFacts(ctx context.Context, tenantID, engagementID, findingID, assigneeID shared.ID, actor string) (NotificationFindingFacts, error)
}
