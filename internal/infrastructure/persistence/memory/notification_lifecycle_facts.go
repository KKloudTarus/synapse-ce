package memory

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type notificationEngagementSettingReader interface {
	GetEngagementNotificationSetting(context.Context, shared.ID, shared.ID) (notification.EngagementNotificationSetting, error)
}
type NotificationLifecycleFactsReader struct {
	users       ports.UserRepository
	engagements ports.EngagementRepository
	settings    notificationEngagementSettingReader
}

var _ ports.NotificationLifecycleFactsReader = (*NotificationLifecycleFactsReader)(nil)
var _ ports.NotificationApproverFactsReader = (*NotificationLifecycleFactsReader)(nil)

func NewNotificationLifecycleFactsReader(users ports.UserRepository, engagements ports.EngagementRepository, settings notificationEngagementSettingReader) *NotificationLifecycleFactsReader {
	return &NotificationLifecycleFactsReader{users, engagements, settings}
}
func (r *NotificationLifecycleFactsReader) SnapshotNotificationLifecycleFacts(ctx context.Context, tenant, engagement shared.ID, actor string) (facts ports.NotificationLifecycleFacts, err error) {
	if current, ok := shared.TenantFrom(ctx); ok && shared.TenantOrDefault(current) != shared.TenantOrDefault(tenant) {
		return facts, fmt.Errorf("%w: notification facts tenant mismatch", shared.ErrValidation)
	}
	if !engagement.IsZero() {
		e, err := r.engagements.GetByIDInTenant(ctx, tenant, engagement)
		if err != nil {
			return facts, err
		}
		facts.EngagementName = e.Name
		if r.settings != nil {
			setting, err := r.settings.GetEngagementNotificationSetting(ctx, tenant, engagement)
			if err != nil && !errors.Is(err, shared.ErrNotFound) {
				return facts, err
			}
			if err == nil && !setting.LeadUserID.IsZero() {
				u, err := r.users.GetByID(ctx, tenant, setting.LeadUserID)
				if err != nil && !errors.Is(err, shared.ErrNotFound) {
					return facts, err
				}
				if err == nil && !u.Disabled && u.Role.Can(user.PermView) {
					facts.LeadUserID = u.ID
				}
			}
		}
	}
	if actor = strings.TrimSpace(actor); actor != "" {
		u, err := r.users.GetByID(ctx, tenant, shared.ID(actor))
		if err != nil && !errors.Is(err, shared.ErrNotFound) {
			return facts, err
		}
		if err == nil && !u.Disabled && u.Role.Can(user.PermView) {
			facts.ActorUserID, facts.ActorName = u.ID, u.Name
		}
	}
	return facts, nil
}
func (r *NotificationLifecycleFactsReader) SnapshotNotificationApprovers(ctx context.Context, tenant shared.ID) ([]shared.ID, error) {
	if current, ok := shared.TenantFrom(ctx); ok && shared.TenantOrDefault(current) != shared.TenantOrDefault(tenant) {
		return nil, fmt.Errorf("%w: notification facts tenant mismatch", shared.ErrValidation)
	}
	users, err := r.users.List(ctx, tenant)
	if err != nil {
		return nil, err
	}
	var ids []shared.ID
	for _, u := range users {
		if !u.Disabled && u.Role.Can(user.PermReview) {
			ids = append(ids, u.ID)
		}
	}
	return ids, nil
}
