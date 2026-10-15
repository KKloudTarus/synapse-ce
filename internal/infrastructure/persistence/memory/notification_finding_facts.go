package memory

import (
	"context"
	"errors"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// NotificationFindingFactsReader snapshots tenant-local user identities for
// finding producers. Memory has no ownership assignment store, so TeamID is
// intentionally absent until an assignment implementation is configured.
type NotificationFindingFactsReader struct {
	users    ports.UserRepository
	settings notificationEngagementSettingReader
}

func NewNotificationFindingFactsReader(users ports.UserRepository, settings ...notificationEngagementSettingReader) *NotificationFindingFactsReader {
	r := &NotificationFindingFactsReader{users: users}
	if len(settings) > 0 {
		r.settings = settings[0]
	}
	return r
}

var _ ports.NotificationFindingFactsReader = (*NotificationFindingFactsReader)(nil)

func (r *NotificationFindingFactsReader) SnapshotFindingNotificationFacts(ctx context.Context, tenantID, engagementID, _, assigneeID shared.ID, actor string) (ports.NotificationFindingFacts, error) {
	var facts ports.NotificationFindingFacts
	if r == nil || r.users == nil {
		return facts, nil
	}
	if r.settings != nil {
		setting, err := r.settings.GetEngagementNotificationSetting(ctx, tenantID, engagementID)
		if err != nil && !errors.Is(err, shared.ErrNotFound) {
			return facts, err
		}
		if err == nil && !setting.LeadUserID.IsZero() {
			u, err := r.users.GetByID(ctx, tenantID, setting.LeadUserID)
			if err != nil && !errors.Is(err, shared.ErrNotFound) {
				return facts, err
			}
			if err == nil && u != nil && !u.Disabled && u.Role.Can(user.PermView) {
				facts.LeadUserID = u.ID
			}
		}
	}
	if candidate := shared.ID(strings.TrimSpace(actor)); !candidate.IsZero() {
		if u, err := r.users.GetByID(ctx, tenantID, candidate); err == nil && activeUser(u) {
			facts.ActorUserID, facts.ActorName = u.ID, u.Name
		} else if err != nil && !errors.Is(err, shared.ErrNotFound) {
			return facts, err
		}
	}
	if !assigneeID.IsZero() {
		if u, err := r.users.GetByID(ctx, tenantID, assigneeID); err == nil && activeUser(u) {
			facts.AssigneeUserID = u.ID
		} else if err != nil && !errors.Is(err, shared.ErrNotFound) {
			return facts, err
		}
	}
	return facts, nil
}

func activeUser(u *user.User) bool { return u != nil && !u.Disabled }
