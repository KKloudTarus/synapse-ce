package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// NotificationLifecycleFacts is captured with a producer transaction. IDs never
// derive from display labels and are revalidated before personal delivery.
type NotificationLifecycleFacts struct {
	EngagementName, ActorName string
	ActorUserID, LeadUserID   shared.ID
}

type NotificationLifecycleFactsReader interface {
	SnapshotNotificationLifecycleFacts(context.Context, shared.ID, shared.ID, string) (NotificationLifecycleFacts, error)
}

// NotificationApproverFactsReader captures the eligible human reviewer roster.
// The producer stores this routing-only fact in its relational recipient snapshot;
// it is not copied into the bounded public event payload.
type NotificationApproverFactsReader interface {
	SnapshotNotificationApprovers(context.Context, shared.ID) ([]shared.ID, error)
}

type NotificationEngagementWindowRelevance interface {
	WindowStillCurrent(context.Context, shared.ID, shared.ID, notification.EventType, time.Time) (bool, error)
}
