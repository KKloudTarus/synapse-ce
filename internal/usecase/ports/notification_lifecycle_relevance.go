package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// NotificationLifecycleRelevance reads the current source of queued lifecycle alerts.
// Historical creation events do not need this check.
type NotificationLifecycleRelevance interface {
	SLABreachCurrent(context.Context, shared.ID, string, string, time.Time, int) (bool, error)
	RiskAcceptanceCurrent(context.Context, shared.ID, string, string, int, time.Time, bool) (bool, error)
}
