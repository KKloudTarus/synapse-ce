package postgres

import (
	"context"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"time"
)

var _ ports.NotificationEngagementWindowRelevance = (*NotificationRepository)(nil)

func (r *NotificationRepository) WindowStillCurrent(ctx context.Context, tenant, engagement shared.ID, event notification.EventType, boundary time.Time) (bool, error) {
	column := "authorized_from"
	switch event {
	case notification.EventEngagementWindowStarting:
	case notification.EventEngagementWindowEnding:
		column = "authorized_to"
	default:
		return false, nil
	}
	return r.exists(ctx, tenant, `SELECT EXISTS(SELECT 1 FROM engagements WHERE tenant_id=$1 AND id=$2 AND status IN ('draft','active') AND project_id IS NULL AND host_asset_id IS NULL AND `+column+`=$3 AND `+column+`>now())`, tenant, engagement, boundary)
}
