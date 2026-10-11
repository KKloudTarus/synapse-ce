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
type NotificationFindingFactsReader struct{ users ports.UserRepository }

func NewNotificationFindingFactsReader(users ports.UserRepository) *NotificationFindingFactsReader {
	return &NotificationFindingFactsReader{users: users}
}

var _ ports.NotificationFindingFactsReader = (*NotificationFindingFactsReader)(nil)

func (r *NotificationFindingFactsReader) SnapshotFindingNotificationFacts(ctx context.Context, tenantID, _, _, assigneeID shared.ID, actor string) (ports.NotificationFindingFacts, error) {
	var facts ports.NotificationFindingFacts
	if r == nil || r.users == nil {
		return facts, nil
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
