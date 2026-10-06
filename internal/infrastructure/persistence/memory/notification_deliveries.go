package memory

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	defaultDeliveryPage = 50
	maxDeliveryPage     = 200
	maxErrorCodeLength  = 160
)

func (r *NotificationRepository) GetDelivery(_ context.Context, tenant, id shared.ID) (notification.Delivery, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	stored, ok := r.deliveries[notificationKey{tenant, id}]
	if !ok {
		return notification.Delivery{}, deliveryNotFound(id)
	}
	return r.deliveryWithFence(stored), nil
}

// ListDeliveries pages newest first with the same filters and cursor as the Postgres query.
func (r *NotificationRepository) ListDeliveries(_ context.Context, f ports.NotificationDeliveryFilter) (notification.Page, error) {
	f.Limit = min(max(f.Limit, 0), maxDeliveryPage)
	if f.Limit == 0 {
		f.Limit = defaultDeliveryPage
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var items []notification.Delivery
	for key, stored := range r.deliveries {
		if key.tenant == f.TenantID && r.deliveryMatches(stored.delivery, f) {
			items = append(items, r.deliveryWithFence(stored))
		}
	}
	slices.SortFunc(items, newestDeliveryFirst)
	var page notification.Page
	if len(items) > f.Limit {
		last := items[f.Limit-1]
		items = items[:f.Limit]
		page.Next = last.CreatedAt.UTC().Format(time.RFC3339Nano) + "|" + last.ID.String()
	}
	page.Items = items
	return page, nil
}

func (r *NotificationRepository) deliveryMatches(d notification.Delivery, f ports.NotificationDeliveryFilter) bool {
	switch {
	case !f.From.IsZero() && d.CreatedAt.Before(f.From):
		return false
	case !f.Until.IsZero() && d.CreatedAt.After(f.Until):
		return false
	case !f.ChannelID.IsZero() && d.ChannelID != f.ChannelID:
		return false
	case f.State != "" && d.State != f.State:
		return false
	case !f.Before.IsZero() && !deliveryBefore(d, f.Before, f.BeforeID):
		return false
	case f.EventType != "":
		event, ok := r.events[notificationKey{d.TenantID, d.EventID}]
		return ok && event.event.Type == f.EventType
	}
	return true
}

// deliveryBefore is the row comparison (created_at, id) < (before, beforeID).
func deliveryBefore(d notification.Delivery, before time.Time, beforeID shared.ID) bool {
	if !d.CreatedAt.Equal(before) {
		return d.CreatedAt.Before(before)
	}
	return d.ID < beforeID
}

func newestDeliveryFirst(a, b notification.Delivery) int {
	if !a.CreatedAt.Equal(b.CreatedAt) {
		return b.CreatedAt.Compare(a.CreatedAt)
	}
	return strings.Compare(b.ID.String(), a.ID.String())
}

func (r *NotificationRepository) ListAttempts(_ context.Context, tenant, delivery shared.ID) ([]notification.Attempt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := notificationKey{tenant, delivery}
	if _, ok := r.deliveries[key]; !ok {
		return nil, deliveryNotFound(delivery)
	}
	out := make([]notification.Attempt, len(r.attempts[key]))
	for i, a := range r.attempts[key] {
		out[i] = cloneAttempt(a)
	}
	return out, nil
}

// LoadWork joins the delivery with its event, channel and the channel version pinned at
// projection, like the Postgres query.
func (r *NotificationRepository) LoadWork(_ context.Context, tenant, delivery shared.ID) (ports.NotificationWork, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	stored, ok := r.deliveries[notificationKey{tenant, delivery}]
	if !ok {
		return ports.NotificationWork{}, deliveryNotFound(delivery)
	}
	d := stored.delivery
	event, eventOK := r.events[notificationKey{tenant, d.EventID}]
	channel, channelOK := r.channels[notificationKey{tenant, d.ChannelID}]
	sealed, sealedOK := r.versions[channelVersionKey{tenant, d.ChannelID, stored.channelVersion}]
	if !eventOK || !channelOK || !sealedOK {
		return ports.NotificationWork{}, deliveryNotFound(delivery)
	}
	channel = cloneChannel(channel)
	channel.SecretVersion = stored.channelVersion
	channel.DeletedAt = nil
	return ports.NotificationWork{Delivery: cloneDelivery(d), Event: cloneNotificationEvent(event.event), Channel: channel, Sealed: sealed,
		Engagement: r.engagementNotifications(tenant, event.event.EngagementID)}, nil
}

// ScanJobSucceeded, SLAReminderDue and FleetAgentLastSeen report true: the scan job, SLA and fleet
// agent rows they read have no memory counterpart (see the type documentation), so every queued
// delivery stays relevant.
func (r *NotificationRepository) ScanJobSucceeded(context.Context, shared.ID, string) (bool, error) {
	return true, nil
}

func (r *NotificationRepository) SLAReminderDue(context.Context, shared.ID, ports.SLAReminder) (bool, error) {
	return true, nil
}

func (r *NotificationRepository) FleetAgentLastSeen(context.Context, shared.ID, string, time.Time) (bool, error) {
	return true, nil
}

// BeginAttempt records a started attempt on an open delivery, after the same checks as the
// Postgres repository: the worker holds the job's claim, the channel is enabled, and neither the
// tenant nor the channel is inside its delivery rate limit.
func (r *NotificationRepository) BeginAttempt(_ context.Context, tenant, delivery shared.ID, jobID string, fence int64, attempt shared.ID, at time.Time) (notification.Attempt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := notificationKey{tenant, delivery}
	stored, ok := r.deliveries[key]
	if !ok {
		return notification.Attempt{}, deliveryNotFound(delivery)
	}
	if !r.holdsClaim(stored, tenant, jobID, fence) {
		return notification.Attempt{}, ports.ErrStaleLease
	}
	channel := notificationKey{tenant, stored.delivery.ChannelID}
	if err := r.checkDeliveryRate(tenant, channel, at); err != nil {
		return notification.Attempt{}, err
	}
	if event, ok := r.events[notificationKey{tenant, stored.delivery.EventID}]; ok &&
		r.engagementNotifications(tenant, event.event.EngagementID) == notification.EngagementNotificationsNone {
		// The override was set to none after LoadWork; the retry reloads the work and cancels it.
		return notification.Attempt{}, fmt.Errorf("%w: engagement suppressed", ports.ErrRetryable)
	}
	if !openDelivery(stored.delivery.State) {
		return notification.Attempt{}, fmt.Errorf("notification delivery is terminal: %w", shared.ErrConflict)
	}
	r.tenantAttemptAt[tenant], r.channelAttemptAt[channel] = at, at
	stored.delivery.Attempts++
	stored.delivery.UpdatedAt = at
	r.deliveries[key] = stored
	started := notification.Attempt{ID: attempt, DeliveryID: delivery, Number: stored.delivery.Attempts, StartedAt: at, Outcome: "started"}
	r.attempts[key] = append(r.attempts[key], started)
	return cloneAttempt(started), nil
}

// checkDeliveryRate applies the Postgres order: tenant budget, then channel enabled and not
// paused, then the per-channel interval. Each refusal is retryable.
func (r *NotificationRepository) checkDeliveryRate(tenant shared.ID, channel notificationKey, at time.Time) error {
	if last, ok := r.tenantAttemptAt[tenant]; ok && at.Sub(last) < tenantAttemptInterval {
		return fmt.Errorf("%w: tenant rate limited", ports.ErrRetryable)
	}
	c, enabled := r.enabledChannel(tenant, channel.id)
	if !enabled {
		return fmt.Errorf("%w: channel disabled", ports.ErrRetryable)
	}
	if c.Health.Paused() {
		// The pause landed after LoadWork; the retry reloads the work and cancels it.
		return fmt.Errorf("%w: channel paused", ports.ErrRetryable)
	}
	if last, ok := r.channelAttemptAt[channel]; ok && at.Sub(last) < channelAttemptInterval {
		return fmt.Errorf("%w: channel rate limited", ports.ErrRetryable)
	}
	return nil
}

// holdsClaim is the fence check: the worker's job is the delivery's job and its claim is live.
func (r *NotificationRepository) holdsClaim(stored storedDelivery, tenant shared.ID, jobID string, fence int64) bool {
	if r.jobs == nil {
		return true
	}
	return stored.jobID == jobID && r.jobs.holdsClaim(jobID, tenant, fence)
}

// FinishAttempt finalizes a started attempt and moves the delivery to the matching state.
func (r *NotificationRepository) FinishAttempt(_ context.Context, tenant, delivery shared.ID, jobID string, fence int64, attempt shared.ID, at time.Time, outcome string, status int, errorCode string, next *time.Time) error {
	state, ok := attemptOutcomeState(outcome)
	if !ok {
		return fmt.Errorf("%w: invalid notification attempt outcome", shared.ErrValidation)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := notificationKey{tenant, delivery}
	if stored, found := r.deliveries[key]; found && !r.holdsClaim(stored, tenant, jobID, fence) {
		return ports.ErrStaleLease
	}
	index := slices.IndexFunc(r.attempts[key], func(a notification.Attempt) bool { return a.ID == attempt && a.Outcome == "started" })
	if index < 0 {
		return fmt.Errorf("notification attempt %s: %w", attempt, shared.ErrConflict)
	}
	stored, ok := r.deliveries[key]
	if !ok || !openDelivery(stored.delivery.State) {
		return fmt.Errorf("notification delivery %s: %w", delivery, shared.ErrConflict)
	}
	finished := at
	a := &r.attempts[key][index]
	a.FinishedAt, a.Outcome, a.ResponseCode, a.ErrorCode = &finished, outcome, status, errorCode
	d := &stored.delivery
	d.State, d.LastError, d.NextAttemptAt, d.UpdatedAt = state, errorCode, cloneTime(next), at
	if outcome == "delivered" {
		d.LastError, d.DeliveredAt = "", &finished
	}
	r.deliveries[key] = stored
	return nil
}

func attemptOutcomeState(outcome string) (notification.DeliveryState, bool) {
	switch outcome {
	case "delivered":
		return notification.DeliverySucceeded, true
	case "retrying":
		return notification.DeliveryRetrying, true
	case "failed":
		return notification.DeliveryDead, true
	case "cancelled":
		return notification.DeliveryCancelled, true
	}
	return "", false
}

// CancelDelivery cancels an open delivery for the worker holding its job. A terminal delivery is
// left unchanged.
func (r *NotificationRepository) CancelDelivery(_ context.Context, tenant, delivery shared.ID, jobID string, fence int64, reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := notificationKey{tenant, delivery}
	if stored, found := r.deliveries[key]; found && !r.holdsClaim(stored, tenant, jobID, fence) {
		return ports.ErrStaleLease
	}
	r.closeDelivery(key, notification.DeliveryCancelled, reason)
	return nil
}

// DeadLetterDelivery moves an open delivery whose job was dead-lettered to dead_letter and reports
// whether this call did it, so a repeated callback does not count the same dead letter twice.
func (r *NotificationRepository) DeadLetterDelivery(_ context.Context, tenant, delivery shared.ID, fence int64, reason string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := notificationKey{tenant, delivery}
	if stored, found := r.deliveries[key]; found && r.jobs != nil {
		r.jobs.mu.Lock()
		defer r.jobs.mu.Unlock()
		job := r.jobs.jobs[stored.jobID]
		if job == nil || job.tenantID != tenant || job.status != "failed" || job.claimFence != fence {
			return false, nil
		}
	}
	return r.closeDelivery(key, notification.DeliveryDead, reason), nil
}

// deliveryWithFence is called with the repository lock held.
func (r *NotificationRepository) deliveryWithFence(stored storedDelivery) notification.Delivery {
	d := cloneDelivery(stored.delivery)
	if r.jobs != nil {
		r.jobs.mu.Lock()
		defer r.jobs.mu.Unlock()
		if job := r.jobs.jobs[stored.jobID]; job != nil && job.tenantID == d.TenantID {
			d.RedriveFence = job.claimFence
		}
	}
	return d
}

// RedriveDelivery updates the delivery and its queue job under both locks.
func (r *NotificationRepository) RedriveDelivery(_ context.Context, tenant, id shared.ID, expectedFence int64) (notification.Delivery, notification.Channel, error) {
	fail := func(err error) (notification.Delivery, notification.Channel, error) {
		return notification.Delivery{}, notification.Channel{}, err
	}
	if expectedFence < 1 {
		return fail(fmt.Errorf("positive queue fence required: %w", shared.ErrValidation))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := notificationKey{tenant, id}
	stored, ok := r.deliveries[key]
	if !ok {
		return fail(deliveryNotFound(id))
	}
	if r.countOpenDeliveries(tenant) >= maxOpenDeliveries {
		return fail(capacityReached("delivery"))
	}
	c, active := r.activeChannel(tenant, stored.delivery.ChannelID)
	if !active || c.SecretVersion != stored.channelVersion || c.Type != stored.delivery.ChannelType || stored.delivery.State != notification.DeliveryDead {
		return fail(fmt.Errorf("notification delivery or channel configuration changed: %w", shared.ErrConflict))
	}
	if c.Type == notification.ChannelEmail && !slices.ContainsFunc(c.Recipients, func(recipient string) bool {
		return strings.EqualFold(recipient, stored.delivery.Recipient)
	}) {
		return fail(fmt.Errorf("notification recipient is no longer configured: %w", shared.ErrConflict))
	}
	if r.jobs == nil {
		return fail(fmt.Errorf("notification delivery queue missing: %w", shared.ErrConflict))
	}
	r.jobs.mu.Lock()
	defer r.jobs.mu.Unlock()
	job := r.jobs.jobs[stored.jobID]
	if job == nil || job.tenantID != tenant || job.kind != notificationDeliverJobKey || job.status != "failed" || job.claimFence != expectedFence || !job.claimedUntil.IsZero() {
		return fail(fmt.Errorf("notification delivery queue state changed: %w", shared.ErrConflict))
	}
	var payload struct {
		DeliveryID shared.ID `json:"delivery_id"`
	}
	if json.Unmarshal(job.payload, &payload) != nil || payload.DeliveryID != id {
		return fail(fmt.Errorf("notification delivery queue identity changed: %w", shared.ErrConflict))
	}
	job.status, job.attempts, job.claimFence, job.availableAt = "queued", 0, job.claimFence+1, r.now().UTC()
	d := &stored.delivery
	d.State, d.LastError, d.NextAttemptAt, d.DeliveredAt = notification.DeliveryPending, "", nil, nil
	d.RedriveFence, d.UpdatedAt = job.claimFence, r.now().UTC()
	r.deliveries[key] = stored
	return cloneDelivery(*d), cloneChannel(c), nil
}

func (r *NotificationRepository) closeDelivery(key notificationKey, state notification.DeliveryState, reason string) bool {
	stored, ok := r.deliveries[key]
	if !ok || !openDelivery(stored.delivery.State) {
		return false
	}
	d := &stored.delivery
	d.State, d.LastError, d.NextAttemptAt, d.UpdatedAt = state, sanitizeErrorCode(reason), nil, r.now().UTC()
	r.deliveries[key] = stored
	return true
}

func sanitizeErrorCode(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > maxErrorCodeLength {
		v = v[:maxErrorCodeLength]
	}
	return v
}

func deliveryNotFound(id shared.ID) error {
	return fmt.Errorf("notification delivery %s: %w", id, shared.ErrNotFound)
}

func cloneDelivery(d notification.Delivery) notification.Delivery {
	d.MatchedRuleIDs = slices.Clone(d.MatchedRuleIDs)
	if d.MatchedRuleIDs == nil {
		d.MatchedRuleIDs = []shared.ID{}
	}
	d.NextAttemptAt = cloneTime(d.NextAttemptAt)
	d.DeliveredAt = cloneTime(d.DeliveredAt)
	return d
}

func cloneAttempt(a notification.Attempt) notification.Attempt {
	a.FinishedAt = cloneTime(a.FinishedAt)
	return a
}

func cloneTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := *t
	return &v
}

// recordSourceFailure keeps a quarantined source record for ListSourceFailures: its identity and
// reason only, never the captured data, like the failed_reason column in Postgres.
func (r *NotificationRepository) recordSourceFailure(record notification.SourceRecord, at time.Time, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sourceFailures = append(r.sourceFailures, storedSourceFailure{tenant: record.TenantID, failure: notification.SourceFailure{
		SourceKind: record.SourceKind, SourceID: record.SourceID, EventType: record.EventType,
		OccurredAt: record.OccurredAt, ProcessedAt: at.UTC(), FailedReason: reason,
	}})
}

// ListSourceFailures pages quarantined source records newest first, with the Postgres filters and
// offset paging.
func (r *NotificationRepository) ListSourceFailures(_ context.Context, f ports.NotificationSourceFailureFilter) (notification.SourceFailurePage, error) {
	f.Limit = min(max(f.Limit, 0), maxDeliveryPage)
	if f.Limit == 0 {
		f.Limit = defaultDeliveryPage
	}
	f.Offset = max(f.Offset, 0)
	r.mu.Lock()
	defer r.mu.Unlock()
	var items []notification.SourceFailure
	for _, stored := range r.sourceFailures {
		failure := stored.failure
		switch {
		case stored.tenant != f.TenantID:
		case f.EventType != "" && failure.EventType != f.EventType:
		case !f.From.IsZero() && failure.ProcessedAt.Before(f.From):
		case !f.Until.IsZero() && failure.ProcessedAt.After(f.Until):
		default:
			items = append(items, failure)
		}
	}
	slices.SortFunc(items, func(a, b notification.SourceFailure) int {
		if !a.ProcessedAt.Equal(b.ProcessedAt) {
			return b.ProcessedAt.Compare(a.ProcessedAt)
		}
		if a.SourceKind != b.SourceKind {
			return strings.Compare(a.SourceKind, b.SourceKind)
		}
		return strings.Compare(a.SourceID, b.SourceID)
	})
	var page notification.SourceFailurePage
	items = items[min(f.Offset, len(items)):]
	if len(items) > f.Limit {
		items = items[:f.Limit]
		next := f.Offset + f.Limit
		page.NextOffset = &next
	}
	page.Items = items
	return page, nil
}
