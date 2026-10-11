package memory

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Channel health (#1464), as postgres.NotificationRepository keeps it: the counting rules live in
// the domain (notification.ChannelHealth.Observe), and the transition to paused records the pause,
// cancels the channel's queued deliveries and publishes the administrators' notice at once.

const (
	pausedDeliveryReason   = "channel_paused"
	maxChannelHealthEvents = 100
	maxHealthActorLength   = 200
)

func (r *NotificationRepository) RecordChannelOutcome(ctx context.Context, tenant shared.ID, o ports.NotificationChannelOutcome) (ports.NotificationChannelTransition, error) {
	var out ports.NotificationChannelTransition
	if o.Class == notification.AttemptIgnored {
		return out, nil
	}
	if tenant.IsZero() || o.ChannelID.IsZero() || o.At.IsZero() {
		return out, fmt.Errorf("%w: channel outcome requires tenant, channel and time", shared.ErrValidation)
	}
	if o.Class != notification.AttemptDelivered && (o.DeliveryID.IsZero() || o.AttemptID.IsZero()) {
		return out, fmt.Errorf("%w: a counted failure must name its delivery and attempt", shared.ErrValidation)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := notificationKey{tenant, o.ChannelID}
	channel, ok := r.channels[key]
	if !ok || channel.DeletedAt != nil {
		return out, nil // deleted meanwhile: there is no health left to keep
	}
	next, effect := channel.Health.Observe(o.Class, o.Code, o.At, o.Threshold)
	out.Health = cloneHealth(next)
	if effect == notification.HealthUnchanged {
		return out, nil
	}
	previous := channel.Health
	channel.Health = next
	r.channels[key] = channel
	if effect != notification.HealthPausedNow {
		return out, nil
	}
	pauseID, err := r.pauseChannel(ctx, channel, o)
	if err != nil {
		channel.Health = previous
		r.channels[key] = channel
		return ports.NotificationChannelTransition{}, err
	}
	out.Paused, out.PauseID = true, pauseID
	return out, nil
}

// pauseChannel performs the side effects of a pause: the history row, the cancelled deliveries
// and the notice event.
func (r *NotificationRepository) pauseChannel(ctx context.Context, channel notification.Channel, o ports.NotificationChannelOutcome) (shared.ID, error) {
	health := channel.Health
	pauseID := notificationStableID(channel.TenantID.String(), channel.ID.String(), "pause", o.AttemptID.String())
	event, err := notification.NewChannelPausedEvent(channel.TenantID, channel.ID, channel.Type, channel.Name, health, pauseID)
	if err != nil {
		return "", err
	}
	event.ID = notificationStableID(channel.TenantID.String(), event.SourceKind, event.SourceID)
	if _, err := r.publish(ctx, event, ""); err != nil {
		return "", fmt.Errorf("publish channel pause notice: %w", err)
	}
	r.appendHealthEvent(notification.ChannelHealthEvent{
		ID: pauseID, ChannelID: channel.ID, Action: notification.HealthActionPaused, Reason: health.PausedReason,
		FailureCode: health.LastFailureCode, Failures: health.ConsecutiveFailures, DeliveryID: o.DeliveryID,
		AttemptID: o.AttemptID, Actor: "system", OccurredAt: *health.PausedAt,
	}, channel.TenantID)
	// Queued work is cancelled rather than held, as disabling a channel does. An attempt already
	// in flight finishes; its outcome no longer changes the paused health.
	r.cancelOpenDeliveries(channel.TenantID, channel.ID, pausedDeliveryReason, *health.PausedAt)
	return pauseID, nil
}

func (r *NotificationRepository) ResumeChannel(_ context.Context, tenant, id shared.ID, revision int, actor string, at time.Time) (notification.Channel, error) {
	actor = strings.TrimSpace(actor)
	if tenant.IsZero() || id.IsZero() || revision < 1 || actor == "" || len(actor) > maxHealthActorLength || at.IsZero() {
		return notification.Channel{}, fmt.Errorf("%w: resume requires a channel, revision and actor", shared.ErrValidation)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := notificationKey{tenant, id}
	channel, ok := r.channels[key]
	if !ok || channel.DeletedAt != nil {
		return notification.Channel{}, fmt.Errorf("notification channel %s: %w", id, shared.ErrNotFound)
	}
	if channel.Revision != revision {
		return notification.Channel{}, staleRevision("channel")
	}
	previous := channel.Health
	next, err := previous.Resume()
	if err != nil {
		return notification.Channel{}, err
	}
	at = at.UTC()
	channel.Health, channel.Revision, channel.UpdatedAt = next, revision+1, at
	r.channels[key] = channel
	r.appendHealthEvent(notification.ChannelHealthEvent{
		ID: notificationStableID(tenant.String(), id.String(), "resume", strconv.Itoa(revision)), ChannelID: id,
		Action: notification.HealthActionResumed, Reason: previous.PausedReason, FailureCode: previous.LastFailureCode,
		Failures: previous.ConsecutiveFailures, Actor: actor, OccurredAt: at,
	}, tenant)
	return cloneChannel(channel), nil
}

// ListChannelHealthEvents returns a channel's pause and resume history, newest first.
func (r *NotificationRepository) ListChannelHealthEvents(_ context.Context, tenant, channel shared.ID, limit int) ([]notification.ChannelHealthEvent, error) {
	if limit <= 0 || limit > maxChannelHealthEvents {
		limit = maxChannelHealthEvents
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := notificationKey{tenant, channel}
	if c, ok := r.channels[key]; !ok || c.DeletedAt != nil {
		return nil, fmt.Errorf("notification channel %s: %w", channel, shared.ErrNotFound)
	}
	out := slices.Clone(r.healthEvents[key])
	slices.SortFunc(out, func(a, b notification.ChannelHealthEvent) int {
		if !a.OccurredAt.Equal(b.OccurredAt) {
			return b.OccurredAt.Compare(a.OccurredAt)
		}
		return strings.Compare(b.ID.String(), a.ID.String())
	})
	if out == nil {
		out = []notification.ChannelHealthEvent{}
	}
	return out[:min(len(out), limit)], nil
}

// appendHealthEvent keeps the first row for an ID, as the Postgres insert does with ON CONFLICT
// DO NOTHING.
func (r *NotificationRepository) appendHealthEvent(e notification.ChannelHealthEvent, tenant shared.ID) {
	key := notificationKey{tenant, e.ChannelID}
	if slices.ContainsFunc(r.healthEvents[key], func(existing notification.ChannelHealthEvent) bool { return existing.ID == e.ID }) {
		return
	}
	r.healthEvents[key] = append(r.healthEvents[key], e)
}
