package memory

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func (r *NotificationRepository) CreateRule(_ context.Context, rule notification.Rule) (notification.Rule, error) {
	if err := rule.Normalize(); err != nil {
		return notification.Rule{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.countRules(rule.TenantID) >= maxNotificationRules {
		return notification.Rule{}, capacityReached("rule")
	}
	key := notificationKey{rule.TenantID, rule.ID}
	if _, exists := r.rules[key]; exists {
		return notification.Rule{}, fmt.Errorf("notification rule %s: %w", rule.ID, shared.ErrConflict)
	}
	if err := r.checkRuleReferences(rule); err != nil {
		return notification.Rule{}, err
	}
	r.rules[key] = cloneRule(rule)
	return cloneRule(rule), nil
}

func (r *NotificationRepository) UpdateRule(_ context.Context, rule notification.Rule) (notification.Rule, error) {
	if err := rule.Normalize(); err != nil {
		return notification.Rule{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := notificationKey{rule.TenantID, rule.ID}
	current, ok := r.rules[key]
	if !ok || current.Revision != rule.Revision-1 {
		return notification.Rule{}, staleRevision("rule")
	}
	if err := r.checkRuleReferences(rule); err != nil {
		return notification.Rule{}, err
	}
	rule.CreatedAt = current.CreatedAt
	r.rules[key] = cloneRule(rule)
	return cloneRule(rule), nil
}

func (r *NotificationRepository) DeleteRule(_ context.Context, tenant, id shared.ID, revision int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := notificationKey{tenant, id}
	current, ok := r.rules[key]
	if !ok || current.Revision != revision {
		return staleRevision("rule")
	}
	delete(r.rules, key)
	return nil
}

func (r *NotificationRepository) GetRule(_ context.Context, tenant, id shared.ID) (notification.Rule, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rule, ok := r.rules[notificationKey{tenant, id}]
	if !ok {
		return notification.Rule{}, fmt.Errorf("notification rule %s: %w", id, shared.ErrNotFound)
	}
	return cloneRule(rule), nil
}

func (r *NotificationRepository) ListRules(_ context.Context, tenant shared.ID) ([]notification.Rule, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []notification.Rule
	for key, rule := range r.rules {
		if key.tenant == tenant {
			out = append(out, cloneRule(rule))
		}
	}
	slices.SortFunc(out, func(a, b notification.Rule) int {
		if a.Name != b.Name {
			return strings.Compare(a.Name, b.Name)
		}
		return strings.Compare(a.ID.String(), b.ID.String())
	})
	return out, nil
}

func (r *NotificationRepository) countRules(tenant shared.ID) int {
	n := 0
	for key := range r.rules {
		if key.tenant == tenant {
			n++
		}
	}
	return n
}

// checkRuleReferences refuses a rule scoped to a team or engagement the tenant does not own, or
// routed to a channel that does not exist or was deleted, in the order the Postgres insert checks
// them.
func (r *NotificationRepository) checkRuleReferences(rule notification.Rule) error {
	for _, id := range rule.TeamIDs {
		if !r.teams[notificationKey{rule.TenantID, id}] {
			return fmt.Errorf("notification team %s: %w", id, shared.ErrNotFound)
		}
	}
	for _, id := range rule.EngagementIDs {
		if !r.engagements[notificationKey{rule.TenantID, id}] {
			return fmt.Errorf("notification engagement %s: %w", id, shared.ErrNotFound)
		}
	}
	for _, id := range rule.ChannelIDs {
		c, ok := r.channels[notificationKey{rule.TenantID, id}]
		if !ok || c.DeletedAt != nil {
			return fmt.Errorf("notification channel %s: %w", id, shared.ErrNotFound)
		}
	}
	return nil
}

// cloneRule copies the slices and returns them sorted, as the Postgres aggregate orders channel
// and team IDs.
func cloneRule(rule notification.Rule) notification.Rule {
	rule.ActionTypes = slices.Clone(rule.ActionTypes)
	rule.EngagementIDs = slices.Clone(rule.EngagementIDs)
	rule.TeamIDs = sortedIDs(rule.TeamIDs)
	rule.ChannelIDs = sortedIDs(rule.ChannelIDs)
	return rule
}

func sortedIDs(ids []shared.ID) []shared.ID {
	out := slices.Clone(ids)
	if out == nil {
		out = []shared.ID{}
	}
	slices.Sort(out)
	return out
}
