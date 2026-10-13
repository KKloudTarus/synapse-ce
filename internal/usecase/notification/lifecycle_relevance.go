package notification

import (
	"context"
	"fmt"
	"strconv"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func lifecycleStillCurrent(ctx context.Context, facts ports.NotificationRelevance, work ports.NotificationWork, data eventData) (bool, error) {
	reader, ok := facts.(ports.NotificationLifecycleRelevance)
	if !ok {
		return false, fmt.Errorf("%w: lifecycle notification relevance reader unavailable", shared.ErrValidation)
	}
	engagement, finding := data.text("engagement_id"), data.text("finding_id")
	if engagement == "" || finding == "" {
		return false, fmt.Errorf("%w: lifecycle notification subject missing", shared.ErrValidation)
	}
	if work.Event.Type == domain.EventSLABreached {
		deadline, ok := data.time("deadline")
		if !ok {
			return false, fmt.Errorf("%w: breach deadline missing", shared.ErrValidation)
		}
		version, err := strconv.Atoi(data.text("episode_version"))
		if err != nil || version <= 0 {
			return false, fmt.Errorf("%w: breach episode identity missing", shared.ErrValidation)
		}
		return reader.SLABreachCurrent(ctx, work.Event.TenantID, engagement, finding, deadline, version)
	}
	expiry, valid := data.time("expires_at")
	version, err := strconv.Atoi(data.text("acceptance_version"))
	if !valid || err != nil || version <= 0 {
		return false, fmt.Errorf("%w: risk acceptance identity missing", shared.ErrValidation)
	}
	return reader.RiskAcceptanceCurrent(ctx, work.Event.TenantID, engagement, finding, version, expiry, work.Event.Type == domain.EventRiskAcceptanceExpiring)
}
