package notification

import (
	"context"
	"fmt"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Data classes per destination (#1360): a channel's class, an engagement's override, and the
// worker's suppression of deliveries an engagement keeps inside Synapse.

var errClassRaise = fmt.Errorf("%w: raising a data class requires the administer capability", shared.ErrForbidden)

// channelDataClass is the class a create or update stores: the requested one, or current when the
// request names none. A raise needs allowRaise.
func channelDataClass(current domain.DataClass, in ChannelInput, allowRaise bool) (domain.DataClass, error) {
	if in.DataClass == nil {
		return current, nil
	}
	next := *in.DataClass
	if !next.Valid() {
		return "", fmt.Errorf("%w: data class must be signal, summary or detail", shared.ErrValidation)
	}
	if current.Raises(next) && !allowRaise {
		return "", errClassRaise
	}
	return next, nil
}

// EngagementSettingInput changes an engagement's override.
type EngagementSettingInput struct {
	ExternalNotifications domain.EngagementNotifications `json:"external_notifications"`
	// Revision is the revision the caller read; 0 when the engagement had no stored setting.
	Revision int `json:"revision"`
	// AllowRaise is set by the caller, never decoded: true only when the principal holds
	// PermAdminister. Letting more data out about an engagement needs it.
	AllowRaise bool `json:"-"`
}

// EngagementNotificationSetting returns the engagement's override, inherit when none is stored.
func (s *Service) EngagementNotificationSetting(ctx context.Context, engagement shared.ID) (domain.EngagementNotificationSetting, error) {
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return domain.EngagementNotificationSetting{}, err
	}
	return s.repo.GetEngagementNotificationSetting(ctx, tenant, engagement)
}

// SetEngagementNotificationSetting stores an engagement's override and audits the change.
func (s *Service) SetEngagementNotificationSetting(ctx context.Context, actor string, engagement shared.ID, in EngagementSettingInput) (domain.EngagementNotificationSetting, error) {
	return mutation(ctx, s, func(ctx context.Context) (domain.EngagementNotificationSetting, error) {
		return s.setEngagementNotificationSetting(ctx, actor, engagement, in)
	})
}

func (s *Service) setEngagementNotificationSetting(ctx context.Context, actor string, engagement shared.ID, in EngagementSettingInput) (domain.EngagementNotificationSetting, error) {
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return domain.EngagementNotificationSetting{}, err
	}
	if !in.ExternalNotifications.Valid() {
		return domain.EngagementNotificationSetting{}, fmt.Errorf("%w: external_notifications must be inherit, signal or none", shared.ErrValidation)
	}
	current, err := s.repo.GetEngagementNotificationSetting(ctx, tenant, engagement)
	if err != nil {
		return domain.EngagementNotificationSetting{}, err
	}
	if in.Revision != current.Revision {
		return domain.EngagementNotificationSetting{}, fmt.Errorf("engagement notification setting revision is stale: %w", shared.ErrConflict)
	}
	if current.ExternalNotifications.Raises(in.ExternalNotifications) && !in.AllowRaise {
		return domain.EngagementNotificationSetting{}, errClassRaise
	}
	now := s.clock.Now().UTC()
	next := domain.EngagementNotificationSetting{TenantID: tenant, EngagementID: engagement, ExternalNotifications: in.ExternalNotifications,
		Revision: current.Revision + 1, UpdatedAt: &now, UpdatedBy: actor}
	stored, err := s.repo.PutEngagementNotificationSetting(ctx, next)
	if err != nil {
		return domain.EngagementNotificationSetting{}, err
	}
	meta := map[string]string{"engagement_id": engagement.String(), "external_notifications": string(stored.ExternalNotifications),
		"previous_external_notifications": string(current.ExternalNotifications)}
	if err := s.record(ctx, actor, "notification.engagement_setting.updated", engagement.String(), meta); err != nil {
		return domain.EngagementNotificationSetting{}, err
	}
	return stored, nil
}
