package memory

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type memoryPagerEpisodeKey struct {
	tenant        shared.ID
	kind, subject string
	episode       int64
}
type memoryPagerOperationKey struct {
	episode  memoryPagerEpisodeKey
	channel  shared.ID
	close    bool
	delivery shared.ID
}
type memoryPagerOperation struct {
	delivery, operation    shared.ID
	version                int
	state, request, remote string
}

var _ ports.NotificationPagerRepository = (*NotificationRepository)(nil)

func memoryPagerEpisode(e notification.Event) memoryPagerEpisodeKey {
	return memoryPagerEpisodeKey{e.TenantID, e.SubjectKind, e.SubjectID, e.PagerLifecycle.Episode}
}
func memoryPagerChannel(c notification.ChannelType) bool {
	return c == notification.ChannelJSM || c == notification.ChannelPagerDuty
}

// Caller holds r.mu. Terminal intent applies even when no rule selects a channel.
func (r *NotificationRepository) filterPagerTargets(e notification.Event, targets map[shared.ID]*fanoutTarget) {
	if e.PagerLifecycle.Episode == 0 {
		return
	}
	ep := memoryPagerEpisode(e)
	for channel, target := range targets {
		if !memoryPagerChannel(target.channel.Type) {
			continue
		}
		if e.PagerLifecycle.Terminal || !r.pagerEpisodes[ep].IsZero() {
			delete(targets, channel)
		}
	}
}
func (r *NotificationRepository) registerPagerPublication(e notification.Event, deliveries []notificationKey) []memoryPagerOperationKey {
	if e.PagerLifecycle.Episode == 0 {
		return nil
	}
	ep := memoryPagerEpisode(e)
	if e.PagerLifecycle.Terminal && r.pagerEpisodes[ep].IsZero() {
		r.pagerEpisodes[ep] = e.ID
	}
	var added []memoryPagerOperationKey
	for _, delivery := range deliveries {
		d := r.deliveries[delivery]
		if !memoryPagerChannel(d.delivery.ChannelType) {
			continue
		}
		k := memoryPagerOperationKey{episode: ep, channel: d.delivery.ChannelID, delivery: delivery.id}
		for existing, operation := range r.pagerOperations {
			if existing.episode == ep && existing.channel == k.channel && !existing.close {
				d.channelVersion = operation.version
				r.deliveries[delivery] = d
				break
			}
		}
		r.pagerOperations[k] = memoryPagerOperation{delivery: delivery.id, version: d.channelVersion, state: "pending"}
		r.pagerDeliveries[delivery] = k
		added = append(added, k)
	}
	return added
}

// laneState selects one acknowledged anchor and detects unresolved mutations.
func (r *NotificationRepository) laneState(ep memoryPagerEpisodeKey, channel shared.ID) (memoryPagerOperation, bool, bool) {
	var anchor memoryPagerOperation
	var anchorKey shared.ID
	var anchorTime time.Time
	done, unresolved := false, false
	for key, op := range r.pagerOperations {
		if key.episode != ep || key.channel != channel || key.close {
			continue
		}
		if op.state == "sending" || op.state == "confirming" || op.state == "unknown" {
			unresolved = true
		}
		created := r.deliveries[notificationKey{ep.tenant, key.delivery}].delivery.CreatedAt
		if op.state == "done" && (!done || created.Before(anchorTime) || (created.Equal(anchorTime) && key.delivery < anchorKey)) {
			anchor, anchorKey, anchorTime, done = op, key.delivery, created, true
		}
	}
	return anchor, done, unresolved
}
func (r *NotificationRepository) schedulePagerCloses(e notification.Event) []notificationKey {
	ep := memoryPagerEpisode(e)
	terminal := r.pagerEpisodes[ep]
	if terminal.IsZero() {
		return nil
	}
	event, ok := r.events[notificationKey{ep.tenant, terminal}]
	if !ok {
		return nil
	}
	channels := map[shared.ID]bool{}
	for key := range r.pagerOperations {
		if key.episode == ep && !key.close {
			channels[key.channel] = true
		}
	}
	var added []notificationKey
	for id := range channels {
		anchor, done, unresolved := r.laneState(ep, id)
		if !done || unresolved {
			continue
		}
		existing := false
		for key := range r.pagerOperations {
			if key.episode == ep && key.channel == id && key.close {
				existing = true
				break
			}
		}
		if existing {
			continue
		}
		channel, exists := r.channels[notificationKey{ep.tenant, id}]
		if !exists {
			continue
		}
		delivery := r.addDelivery(event.event, &fanoutTarget{channel: channel}, "", r.now().UTC())
		d := r.deliveries[delivery]
		d.channelVersion = anchor.version
		r.deliveries[delivery] = d
		closeKey := memoryPagerOperationKey{episode: ep, channel: id, close: true, delivery: delivery.id}
		r.pagerOperations[closeKey] = memoryPagerOperation{delivery: delivery.id, version: anchor.version, state: "pending"}
		r.pagerDeliveries[delivery] = closeKey
		added = append(added, delivery)
	}
	return added
}
func (r *NotificationRepository) forgetPagerPublication(e notification.Event, registered []memoryPagerOperationKey, deliveries []notificationKey) {
	for _, key := range registered {
		delete(r.pagerOperations, key)
	}
	for _, delivery := range deliveries {
		if key, ok := r.pagerDeliveries[delivery]; ok {
			delete(r.pagerOperations, key)
			delete(r.pagerDeliveries, delivery)
		}
	}
	ep := memoryPagerEpisode(e)
	if r.pagerEpisodes[ep] == e.ID {
		delete(r.pagerEpisodes, ep)
	}
}

func (r *NotificationRepository) AdmitPagerMutation(_ context.Context, tenant, delivery shared.ID, jobID string, fence int64, operation shared.ID) (ports.PagerMutation, error) {
	var out ports.PagerMutation
	if operation.IsZero() {
		return out, fmt.Errorf("%w: invalid pager operation", shared.ErrValidation)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.deliveries[notificationKey{tenant, delivery}]
	if !ok {
		return out, deliveryNotFound(delivery)
	}
	if !r.holdsClaim(d, tenant, jobID, fence) {
		return out, ports.ErrStaleLease
	}
	started := false
	for _, attempt := range r.attempts[notificationKey{tenant, delivery}] {
		if attempt.ID == operation && attempt.Outcome == "started" {
			started = true
			break
		}
	}
	if !started {
		return out, fmt.Errorf("%w: pager attempt missing", shared.ErrConflict)
	}
	key, ok := r.pagerDeliveries[notificationKey{tenant, delivery}]
	if !ok {
		return out, fmt.Errorf("%w: pager operation not found", shared.ErrNotFound)
	}
	op := r.pagerOperations[key]
	out.OperationID, out.ProviderRequestRef, out.RemoteRef = op.operation, op.request, op.remote
	switch op.state {
	case "done":
		out.Action = "complete"
		return out, nil
	case "suppressed":
		out.Action = "suppressed"
		return out, nil
	case "unknown", "sending", "failed":
		out.Action, out.Code = "blocked", "pager_"+op.state
		return out, nil
	}
	if op.state == "pending" && !key.close && !r.pagerEpisodes[key.episode].IsZero() {
		op.state = "suppressed"
		r.pagerOperations[key] = op
		if r.jobs != nil {
			r.jobs.mu.Lock()
			r.wakePagerLaneLocked(key.episode, key.channel)
			r.jobs.mu.Unlock()
		}
		out.Action = "suppressed"
		return out, nil
	}
	channel, ok := r.activeChannel(tenant, key.channel)
	if !ok || channel.SecretVersion != op.version || r.engagementNotifications(tenant, r.events[notificationKey{tenant, d.delivery.EventID}].event.EngagementID) == notification.EngagementNotificationsNone {
		out.Action, out.Code = "blocked", "pager_channel_unavailable"
		return out, nil
	}
	if op.state == "confirming" {
		out.Action = "poll"
		return out, nil
	}
	anchor, done, unresolved := r.laneState(key.episode, key.channel)
	if unresolved {
		out.Action, out.Code = "blocked", "pager_waiting"
		return out, nil
	}
	if key.close && (!done || anchor.remote == "") {
		out.Action, out.Code = "blocked", "pager_missing_anchor"
		return out, nil
	}
	if done {
		out.SubjectAnchor = anchor.remote
	}
	op.state, op.operation = "sending", operation
	r.pagerOperations[key] = op
	out.Action, out.OperationID = "send", operation
	return out, nil
}

func (r *NotificationRepository) RecordPagerReceipt(ctx context.Context, tenant, delivery, operation shared.ID, result ports.NotificationSendResult) error {
	if operation.IsZero() || len(result.ProviderRequestRef) > 512 || len(result.RemoteRef) > 512 {
		return fmt.Errorf("%w: invalid pager receipt", shared.ErrValidation)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key, ok := r.pagerDeliveries[notificationKey{tenant, delivery}]
	if !ok {
		return fmt.Errorf("%w: pager operation not found", shared.ErrNotFound)
	}
	op := r.pagerOperations[key]
	if op.operation != operation {
		return fmt.Errorf("%w: pager operation mismatch", shared.ErrConflict)
	}
	if op.state != "done" && op.state != "failed" && op.state != "suppressed" {
		switch {
		case result.RemoteRef != "" && result.ErrorCode == "" && result.StatusCode >= 200 && result.StatusCode < 300:
			op.state, op.remote = "done", result.RemoteRef
		case result.ErrorCode == "jsm_request_failed":
			op.state = "failed"
		case result.ProviderRequestRef != "":
			if op.request != "" && op.request != result.ProviderRequestRef {
				return fmt.Errorf("%w: pager request mismatch", shared.ErrConflict)
			}
			op.state, op.request = "confirming", result.ProviderRequestRef
		case op.state == "confirming": // Keep the accepted request for read-only polling.
		case result.StatusCode == 429:
			op.state, op.operation = "pending", ""
		case result.StatusCode >= 400 && result.StatusCode < 500:
			op.state = "failed"
		case result.ErrorCode == "channel_config_invalid" || result.ErrorCode == "format_failed" || result.ErrorCode == "pager_key_unavailable" || result.ErrorCode == "pager_resolve_unpaired" || result.ErrorCode == "request_invalid":
			if result.Retryable {
				op.state, op.operation = "pending", ""
			} else {
				op.state = "failed"
			}
		default:
			op.state = "unknown"
		}
		r.pagerOperations[key] = op
	}
	if (op.state == "confirming" || op.state == "done") && r.jobs != nil {
		r.jobs.mu.Lock()
		r.wakePagerConfirmationLocked(notificationKey{tenant, delivery}, 0)
		r.jobs.mu.Unlock()
	}
	if (op.state == "done" || op.state == "failed") && !key.close && !r.pagerEpisodes[key.episode].IsZero() {
		terminal := r.events[notificationKey{tenant, r.pagerEpisodes[key.episode]}].event
		added := r.schedulePagerCloses(terminal)
		if err := r.enqueueDeliveries(ctx, added); err != nil {
			for _, d := range added {
				delete(r.pagerOperations, r.pagerDeliveries[d])
				delete(r.pagerDeliveries, d)
				delete(r.deliveries, d)
			}
			return err
		}
	}
	if (op.state == "done" || op.state == "failed") && r.jobs != nil {
		r.jobs.mu.Lock()
		r.wakePagerLaneLocked(key.episode, key.channel)
		r.jobs.mu.Unlock()
	}
	return nil
}

// wakePagerConfirmationLocked reconciles the race between a blocked claimant
// being dead-lettered and a late accepted request arriving. Both locks are held.
func (r *NotificationRepository) wakePagerConfirmationLocked(delivery notificationKey, fence int64) bool {
	key, ok := r.pagerDeliveries[delivery]
	if !ok || (r.pagerOperations[key].state != "confirming" && r.pagerOperations[key].state != "done") {
		return false
	}
	stored, ok := r.deliveries[delivery]
	if !ok {
		return false
	}
	job := r.jobs.jobs[stored.jobID]
	if job == nil || job.tenantID != delivery.tenant || (fence != 0 && job.claimFence != fence) {
		return false
	}
	op := r.pagerOperations[key]
	failedWaiting := job.status == "failed" && (stored.delivery.LastError == "pager_sending" || stored.delivery.LastError == "pager_unknown")
	cancelledDone := job.status == "done" && stored.delivery.State == notification.DeliveryCancelled
	if !failedWaiting && !cancelledDone {
		return false
	}
	channel, ok := r.activeChannel(delivery.tenant, key.channel)
	event := r.events[notificationKey{delivery.tenant, stored.delivery.EventID}].event
	if op.state != "done" && (!ok || channel.SecretVersion != op.version || r.engagementNotifications(delivery.tenant, event.EngagementID) == notification.EngagementNotificationsNone) {
		return false
	}
	now := r.now().UTC()
	stored.delivery.State, stored.delivery.LastError, stored.delivery.NextAttemptAt, stored.delivery.UpdatedAt = notification.DeliveryPending, "", nil, now
	r.deliveries[delivery] = stored
	job.status, job.attempts, job.claimFence, job.availableAt = "queued", 0, job.claimFence+1, now
	return true
}

// Caller holds both repository and queue locks. Resume only the oldest parked
// delivery after all earlier writes have a definitive outcome.
func (r *NotificationRepository) wakePagerLaneLocked(ep memoryPagerEpisodeKey, channel shared.ID) {
	_, _, unresolved := r.laneState(ep, channel)
	if unresolved {
		return
	}
	var best notificationKey
	var bestTime time.Time
	for key, op := range r.pagerOperations {
		if key.episode != ep || key.channel != channel || op.state != "pending" {
			continue
		}
		dkey := notificationKey{ep.tenant, op.delivery}
		d := r.deliveries[dkey]
		job := r.jobs.jobs[d.jobID]
		if job == nil || job.status != "failed" || d.delivery.LastError != "pager_waiting" {
			continue
		}
		if best.id.IsZero() || d.delivery.CreatedAt.Before(bestTime) || (d.delivery.CreatedAt.Equal(bestTime) && dkey.id < best.id) {
			best, bestTime = dkey, d.delivery.CreatedAt
		}
	}
	if best.id.IsZero() {
		return
	}
	stored := r.deliveries[best]
	event := r.events[notificationKey{ep.tenant, stored.delivery.EventID}].event
	op := r.pagerOperations[r.pagerDeliveries[best]]
	c, ok := r.activeChannel(ep.tenant, channel)
	if r.pagerEpisodes[ep].IsZero() && (!ok || c.SecretVersion != op.version || r.engagementNotifications(ep.tenant, event.EngagementID) == notification.EngagementNotificationsNone) {
		return
	}
	now := r.now().UTC()
	stored.delivery.State, stored.delivery.LastError, stored.delivery.NextAttemptAt, stored.delivery.UpdatedAt = notification.DeliveryPending, "", nil, now
	r.deliveries[best] = stored
	job := r.jobs.jobs[stored.jobID]
	job.status, job.attempts, job.claimFence, job.availableAt = "queued", 0, job.claimFence+1, now
}

func (r *NotificationRepository) ReconcilePagerAcknowledgement(_ context.Context, tenant, delivery shared.ID, jobID string, fence int64) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	dkey := notificationKey{tenant, delivery}
	stored, ok := r.deliveries[dkey]
	if !ok {
		return false, deliveryNotFound(delivery)
	}
	if !r.holdsClaim(stored, tenant, jobID, fence) {
		return false, ports.ErrStaleLease
	}
	key, ok := r.pagerDeliveries[dkey]
	if !ok {
		return false, nil
	}
	op := r.pagerOperations[key]
	if op.state != "done" {
		return false, nil
	}
	now := r.now().UTC()
	stored.delivery.State, stored.delivery.LastError, stored.delivery.NextAttemptAt, stored.delivery.UpdatedAt = notification.DeliverySucceeded, "", nil, now
	stored.delivery.DeliveredAt, stored.delivery.RemoteRef, stored.delivery.ProviderRequestRef = &now, op.remote, ""
	r.deliveries[dkey] = stored
	return true, nil
}

// A worker can cancel and finish its queue job after the receipt callback ran.
// The source poller revisits a bounded number of completed acknowledgements.
func (r *NotificationRepository) reconcilePagerDoneJobs(limit int) {
	if r.jobs == nil || limit <= 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.jobs.mu.Lock()
	defer r.jobs.mu.Unlock()
	checked := 0
	for delivery, key := range r.pagerDeliveries {
		if state := r.pagerOperations[key].state; state != "done" && state != "confirming" {
			continue
		}
		stored := r.deliveries[delivery]
		job := r.jobs.jobs[stored.jobID]
		if stored.delivery.State != notification.DeliveryCancelled || job == nil || job.status != "done" {
			continue
		}
		if r.wakePagerConfirmationLocked(delivery, 0) {
			checked++
		}
		if checked >= limit {
			break
		}
	}
}
