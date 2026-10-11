package memory

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Publish records the event once per source key and fans it out to the channels of every enabled
// rule that matches it. Replaying the same source returns the deliveries created the first time.
func (r *NotificationRepository) Publish(ctx context.Context, e notification.Event) ([]shared.ID, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.publish(ctx, e, "")
}

// PublishToChannel publishes to one channel regardless of rules. Channel tests are limited to
// ten per channel per minute.
func (r *NotificationRepository) PublishToChannel(ctx context.Context, e notification.Event, channel shared.ID) (shared.ID, error) {
	if err := e.Validate(); err != nil {
		return "", err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.enabledChannel(e.TenantID, channel)
	if !ok {
		return "", fmt.Errorf("notification channel %s: %w", channel, shared.ErrNotFound)
	}
	if e.Type == notification.EventTest {
		if c.Health.Paused() {
			return "", fmt.Errorf("notification channel is paused; resume it before sending a test: %w", shared.ErrConflict)
		}
		if r.recentChannelTests(e.TenantID, channel) >= maxChannelTestsPerMinute {
			return "", fmt.Errorf("notification channel test rate limit exceeded: %w", shared.ErrSaturated)
		}
	}
	ids, err := r.publish(ctx, e, channel)
	if err != nil {
		return "", err
	}
	if len(ids) == 0 {
		return "", fmt.Errorf("notification channel %s: %w", channel, shared.ErrNotFound)
	}
	return ids[0], nil
}

type fanoutTarget struct {
	channel notification.Channel
	rules   []shared.ID
}

func (r *NotificationRepository) publish(ctx context.Context, e notification.Event, only shared.ID) ([]shared.ID, error) {
	source := eventSourceKey{e.TenantID, e.SourceKind, e.SourceID}
	if existing, ok := r.eventIDs[source]; ok {
		return r.deliveryIDsOf(e.TenantID, existing), nil
	}
	if r.projector != nil {
		projected, err := r.projector.Project(ctx, e)
		if err != nil {
			return nil, fmt.Errorf("project notification event: %w", err)
		}
		if err := projected.Validate(); err != nil {
			return nil, err
		}
		e = projected
	}
	targets, revisions := r.fanoutTargets(e, only)
	if len(targets) > 0 && r.countOpenDeliveries(e.TenantID) >= maxOpenDeliveries {
		return nil, capacityReached("delivery")
	}
	created := r.now().UTC()
	var newDeliveries []notificationKey
	matched := []shared.ID{}
	for _, t := range targets {
		for _, recipient := range deliveryRecipients(t.channel) {
			key := r.addDelivery(e, t, recipient, created)
			newDeliveries = append(newDeliveries, key)
		}
		matched = append(matched, t.rules...)
	}
	r.events[notificationKey{e.TenantID, e.ID}] = storedEvent{event: cloneNotificationEvent(e), matched: matched, revisions: revisions}
	r.eventIDs[source] = e.ID
	if err := r.enqueueDeliveries(ctx, newDeliveries); err != nil {
		r.forgetEvent(e, newDeliveries)
		return nil, err
	}
	ids := make([]shared.ID, len(newDeliveries))
	for i, key := range newDeliveries {
		ids[i] = key.id
	}
	return ids, nil
}

// fanoutTargets selects the enabled channels an event goes to and the rules that chose them. With
// only set, the one channel is the target and no rule is consulted.
func (r *NotificationRepository) fanoutTargets(e notification.Event, only shared.ID) (map[shared.ID]*fanoutTarget, map[shared.ID]int) {
	targets := map[shared.ID]*fanoutTarget{}
	revisions := map[shared.ID]int{}
	if !only.IsZero() {
		if c, ok := r.activeChannel(e.TenantID, only); ok {
			targets[only] = &fanoutTarget{channel: c, rules: []shared.ID{}}
		}
		return targets, revisions
	}
	for key, rule := range r.rules {
		if key.tenant != e.TenantID || !rule.Enabled || rule.EventType != e.Type || !rule.Matches(e) {
			continue
		}
		revisions[rule.ID] = rule.Revision
		for _, channel := range rule.ChannelIDs {
			if targets[channel] == nil {
				targets[channel] = &fanoutTarget{rules: []shared.ID{}}
			}
			targets[channel].rules = append(targets[channel].rules, rule.ID)
		}
	}
	for id, t := range targets {
		c, ok := r.activeChannel(e.TenantID, id)
		if !ok {
			delete(targets, id)
			continue
		}
		t.channel = c
		slices.Sort(t.rules)
	}
	return targets, revisions
}

// deliveryRecipients is one delivery per email recipient, one per channel otherwise.
func deliveryRecipients(c notification.Channel) []string {
	if c.Type == notification.ChannelEmail {
		return c.Recipients
	}
	return []string{""}
}

func (r *NotificationRepository) addDelivery(e notification.Event, t *fanoutTarget, recipient string, created time.Time) notificationKey {
	id := notificationStableID(e.TenantID.String(), e.ID.String(), t.channel.ID.String(), strings.ToLower(recipient))
	key := notificationKey{e.TenantID, id}
	r.deliveries[key] = storedDelivery{
		delivery: notification.Delivery{
			TenantID: e.TenantID, ID: id, EventID: e.ID, ChannelID: t.channel.ID, ChannelType: t.channel.Type,
			Recipient: recipient, MatchedRuleIDs: slices.Clone(t.rules), State: notification.DeliveryPending,
			CreatedAt: created, UpdatedAt: created,
		},
		channelVersion: t.channel.SecretVersion,
	}
	return key
}

// enqueueDeliveries adds one worker job per new delivery. The Postgres repository inserts the jobs
// in the publishing transaction; here a failed enqueue undoes the publication instead.
func (r *NotificationRepository) enqueueDeliveries(ctx context.Context, keys []notificationKey) error {
	if r.jobs == nil {
		return nil
	}
	for _, key := range keys {
		payload, _ := json.Marshal(map[string]string{"delivery_id": key.id.String()})
		jobID, err := r.jobs.Enqueue(shared.WithTenant(ctx, key.tenant), notificationDeliverJobKey, payload)
		if err != nil {
			return fmt.Errorf("enqueue notification delivery: %w", err)
		}
		stored := r.deliveries[key]
		stored.jobID = jobID
		r.deliveries[key] = stored
	}
	return nil
}

func (r *NotificationRepository) forgetEvent(e notification.Event, keys []notificationKey) {
	for _, key := range keys {
		delete(r.deliveries, key)
	}
	delete(r.events, notificationKey{e.TenantID, e.ID})
	delete(r.eventIDs, eventSourceKey{e.TenantID, e.SourceKind, e.SourceID})
}

func (r *NotificationRepository) deliveryIDsOf(tenant, event shared.ID) []shared.ID {
	var ids []shared.ID
	for key, stored := range r.deliveries {
		if key.tenant == tenant && stored.delivery.EventID == event {
			ids = append(ids, key.id)
		}
	}
	slices.Sort(ids)
	return ids
}

func (r *NotificationRepository) countOpenDeliveries(tenant shared.ID) int {
	n := 0
	for key, stored := range r.deliveries {
		if key.tenant == tenant && openDelivery(stored.delivery.State) {
			n++
		}
	}
	return n
}

// recentChannelTests counts test events delivered to the channel in the last minute.
func (r *NotificationRepository) recentChannelTests(tenant, channel shared.ID) int {
	since := r.now().UTC().Add(-time.Minute)
	events := map[shared.ID]bool{}
	for key, stored := range r.deliveries {
		d := stored.delivery
		if key.tenant != tenant || d.ChannelID != channel || d.CreatedAt.Before(since) {
			continue
		}
		if event, ok := r.events[notificationKey{tenant, d.EventID}]; ok && event.event.Type == notification.EventTest {
			events[d.EventID] = true
		}
	}
	return len(events)
}

func cloneNotificationEvent(e notification.Event) notification.Event {
	e.Data = slices.Clone(e.Data)
	e.Context = slices.Clone(e.Context)
	return e
}

// MatchedRules returns the rule IDs and revisions recorded for an event, the columns the Postgres
// repository writes on notification_events. Tests use it to assert rule matching.
func (r *NotificationRepository) MatchedRules(tenant, event shared.ID) ([]shared.ID, map[shared.ID]int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	stored, ok := r.events[notificationKey{tenant, event}]
	if !ok {
		return nil, nil
	}
	return slices.Clone(stored.matched), maps.Clone(stored.revisions)
}
