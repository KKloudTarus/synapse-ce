package postgres

import (
	"context"

	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// deliveryStillRelevant asks the worker's question: the event builders decide which fact to check,
// and the repository answers it.
func deliveryStillRelevant(repo *NotificationRepository, ctx context.Context, work ports.NotificationWork) (bool, error) {
	return notificationuc.NewEventBuilders().StillRelevant(ctx, repo, work)
}
