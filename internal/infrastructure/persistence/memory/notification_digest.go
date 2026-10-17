package memory

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type memoryDigestKey struct {
	tenant, rule, channel shared.ID
	cadence               notification.DeliveryCadence
	start                 time.Time
	chunk                 int
}

const maxDigestMembers = notification.MaxDigestMembers

type digestMembershipTarget struct {
	rule      notification.Rule
	channelID shared.ID
}

type memoryDigestWindow struct {
	outcome string
	eventID shared.ID
}

func (r *NotificationRepository) recordMemoryDigestMembers(event notification.Event, targets []digestMembershipTarget) []memoryDigestKey {
	now := r.now().UTC()
	keys := make([]memoryDigestKey, 0, len(targets))
	for _, target := range targets {
		if _, active := r.activeChannel(event.TenantID, target.channelID); !active {
			continue
		}
		start, _ := target.rule.Cadence.Window(now)
		latest := -1
		for key := range r.digestMembers {
			if key.tenant == event.TenantID && key.rule == target.rule.ID && key.channel == target.channelID && key.cadence == target.rule.Cadence && key.start.Equal(start) && key.chunk > latest {
				latest = key.chunk
			}
		}
		for key := range r.digestWindows {
			if key.tenant == event.TenantID && key.rule == target.rule.ID && key.channel == target.channelID && key.cadence == target.rule.Cadence && key.start.Equal(start) && key.chunk > latest {
				latest = key.chunk
			}
		}
		if latest < 0 {
			latest = 0
		}
		key := memoryDigestKey{tenant: event.TenantID, rule: target.rule.ID, channel: target.channelID, cadence: target.rule.Cadence, start: start, chunk: latest}
		if _, finalized := r.digestWindows[key]; finalized || len(r.digestMembers[key]) >= maxDigestMembers {
			key.chunk++
		}
		members := r.digestMembers[key]
		if members == nil {
			members = map[shared.ID]struct{}{}
			r.digestMembers[key] = members
		}
		members[event.ID] = struct{}{}
		keys = append(keys, key)
	}
	return keys
}

// suppressMemoryPendingDigests finalizes the current queued work of a channel
// when a channel is disabled, paused, deleted, or reconfigured. Subsequent
// events in the same UTC window are assigned a fresh chunk on resume.
func (r *NotificationRepository) suppressMemoryPendingDigests(tenant, channel shared.ID) {
	for key := range r.digestMembers {
		if key.tenant == tenant && key.channel == channel {
			if _, finalized := r.digestWindows[key]; !finalized {
				r.digestWindows[key] = memoryDigestWindow{outcome: "suppressed"}
			}
		}
	}
}

func (r *NotificationRepository) forgetMemoryDigestMembers(event shared.ID, keys []memoryDigestKey) {
	for _, key := range keys {
		members := r.digestMembers[key]
		delete(members, event)
		if len(members) == 0 {
			delete(r.digestMembers, key)
		}
	}
}

// materializeDigests closes publication-time windows under the repository mutex.
// Closed outcomes remain final so re-enabling a rule or destination cannot release
// members that were suppressed at close.
func (r *NotificationRepository) materializeDigests(ctx context.Context, tenant shared.ID, now time.Time, limit int) (int, error) {
	if limit <= 0 {
		return 0, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	keys := make([]memoryDigestKey, 0)
	for key := range r.digestMembers {
		if key.tenant == tenant {
			_, finalized := r.digestWindows[key]
			_, end := key.cadence.Window(key.start)
			if !finalized && !end.After(now.UTC()) {
				keys = append(keys, key)
			}
		}
	}
	slices.SortFunc(keys, func(left, right memoryDigestKey) int {
		_, leftEnd := left.cadence.Window(left.start)
		_, rightEnd := right.cadence.Window(right.start)
		if !leftEnd.Equal(rightEnd) {
			return leftEnd.Compare(rightEnd)
		}
		if left.rule != right.rule {
			if left.rule < right.rule {
				return -1
			}
			return 1
		}
		if left.channel < right.channel {
			return -1
		}
		if left.channel > right.channel {
			return 1
		}
		if left.chunk < right.chunk {
			return -1
		}
		if left.chunk > right.chunk {
			return 1
		}
		return 0
	})
	if len(keys) > limit {
		keys = keys[:limit]
	}
	for _, key := range keys {
		if err := r.materializeMemoryDigest(ctx, key, now.UTC()); err != nil {
			return 0, err
		}
	}
	return len(keys), nil
}

func (r *NotificationRepository) materializeMemoryDigest(ctx context.Context, key memoryDigestKey, now time.Time) error {
	rule, ruleOK := r.rules[notificationKey{key.tenant, key.rule}]
	channel, channelOK := r.channels[notificationKey{key.tenant, key.channel}]
	if !ruleOK || !channelOK || !rule.Enabled || rule.Cadence != key.cadence || !channel.Enabled || channel.DeletedAt != nil || channel.Health.Paused() {
		r.digestWindows[key] = memoryDigestWindow{outcome: "suppressed"}
		return nil
	}
	items := r.memoryDigestItems(key)
	_, end := key.cadence.Window(key.start)
	context, count, err := notification.BuildDigestContext(items, key.cadence, key.start, end, channel.Class())
	if err != nil {
		return err
	}
	if count == 0 {
		r.digestWindows[key] = memoryDigestWindow{outcome: "empty"}
		return nil
	}
	encoded, err := context.Encode()
	if err != nil {
		return err
	}
	data, err := json.Marshal(notification.DigestData{Cadence: key.cadence, WindowStart: key.start, WindowEnd: end, EventIDs: memoryDigestEventIDs(items, channel.Class()), TotalCount: count})
	if err != nil {
		return err
	}
	event := notification.Event{TenantID: key.tenant, ID: notificationStableID("digest", key.tenant.String(), key.rule.String(), key.channel.String(), string(key.cadence), key.start.Format(time.RFC3339Nano), fmt.Sprintf("%d", key.chunk)), Type: notification.EventDigest, SourceKind: "digest", SourceID: memoryDigestSourceID(key), Severity: notification.DigestSeverity(items), SchemaVersion: 1, OccurredAt: end, Data: data, Context: encoded}
	ids, err := r.publish(ctx, event, key.channel)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return fmt.Errorf("digest channel %s: %w", key.channel, shared.ErrNotFound)
	}
	r.digestWindows[key] = memoryDigestWindow{outcome: "published", eventID: event.ID}
	return nil
}

func (r *NotificationRepository) memoryDigestItems(key memoryDigestKey) []notification.DigestItem {
	ids := make([]shared.ID, 0, len(r.digestMembers[key]))
	for id := range r.digestMembers[key] {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	items := make([]notification.DigestItem, 0, len(ids))
	for _, id := range ids {
		stored, ok := r.events[notificationKey{key.tenant, id}]
		if !ok {
			continue
		}
		override := r.engagementNotifications(key.tenant, stored.event.EngagementID)
		items = append(items, notification.DigestItem{Event: cloneNotificationEvent(stored.event), Override: override})
	}
	return items
}

func (r *NotificationRepository) memoryDigestKeyForEvent(tenant, eventID shared.ID) (memoryDigestKey, bool) {
	for key, window := range r.digestWindows {
		if key.tenant == tenant && window.eventID == eventID {
			return key, true
		}
	}
	return memoryDigestKey{}, false
}

func memoryDigestEventIDs(items []notification.DigestItem, class notification.DataClass) []shared.ID {
	ordered := slices.Clone(items)
	slices.SortFunc(ordered, func(left, right notification.DigestItem) int {
		if !left.Event.OccurredAt.Equal(right.Event.OccurredAt) {
			return left.Event.OccurredAt.Compare(right.Event.OccurredAt)
		}
		if left.Event.ID < right.Event.ID {
			return -1
		}
		if left.Event.ID > right.Event.ID {
			return 1
		}
		return 0
	})
	ids := make([]shared.ID, 0, min(len(ordered), notification.MaxDigestItems))
	for _, item := range ordered {
		if _, deliver := notification.EffectiveDataClass(class, item.Override); deliver {
			ids = append(ids, item.Event.ID)
			if len(ids) == notification.MaxDigestItems {
				break
			}
		}
	}
	return ids
}

func memoryDigestSourceID(key memoryDigestKey) string {
	return "digest:" + key.tenant.String() + ":" + key.rule.String() + ":" + key.channel.String() + ":" + string(key.cadence) + ":" + key.start.UTC().Format(time.RFC3339Nano) + ":" + fmt.Sprintf("%d", key.chunk)
}
