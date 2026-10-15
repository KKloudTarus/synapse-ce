package notification

import (
	"context"
	"fmt"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func engagementWindowStillCurrent(ctx context.Context, relevance ports.NotificationRelevance, work ports.NotificationWork, data eventData) (bool, error) {
	reader, ok := relevance.(ports.NotificationEngagementWindowRelevance)
	if !ok {
		return false, fmt.Errorf("%w: engagement window relevance reader unavailable", shared.ErrValidation)
	}
	name := "authorized_from"
	if work.Event.Type == domain.EventEngagementWindowEnding {
		name = "authorized_to"
	}
	if data.text("boundary") != name {
		return false, nil
	}
	boundary, ok := data.time(name)
	if !ok {
		return false, nil
	}
	return reader.WindowStillCurrent(ctx, work.Event.TenantID, work.Event.EngagementID, work.Event.Type, boundary)
}
