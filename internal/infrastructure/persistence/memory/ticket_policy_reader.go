package memory

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TicketPolicyReader gives the development ticket workflow an authoritative
// engagement ownership check. Development does not persist notification
// overrides, so an owned engagement receives the documented inherit default.
type TicketPolicyReader struct {
	engagements ports.EngagementOwnershipReader
}

var _ ports.TicketPolicyReader = (*TicketPolicyReader)(nil)

func NewTicketPolicyReader(engagements ports.EngagementOwnershipReader) (*TicketPolicyReader, error) {
	if engagements == nil {
		return nil, fmt.Errorf("%w: ticket policy reader requires engagement ownership reader", shared.ErrValidation)
	}
	return &TicketPolicyReader{engagements: engagements}, nil
}

func (r *TicketPolicyReader) GetEngagementNotificationSetting(ctx context.Context, tenant, engagementID shared.ID) (notification.EngagementNotificationSetting, error) {
	if err := ctx.Err(); err != nil {
		return notification.EngagementNotificationSetting{}, err
	}
	tenant = shared.TenantOrDefault(tenant)
	if _, err := r.engagements.GetByIDInTenant(ctx, tenant, engagementID); err != nil {
		return notification.EngagementNotificationSetting{}, err
	}
	return notification.EngagementNotificationSetting{
		TenantID:              tenant,
		EngagementID:          engagementID,
		ExternalNotifications: notification.EngagementNotificationsInherit,
	}, nil
}
