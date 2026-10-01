package memory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// NotificationRepository is the in-memory twin of postgres.NotificationRepository for
// development and for tests of code that publishes notifications. The shared contract in
// internal/testutil/notificationconformance runs against both.
//
// It reproduces the Postgres behaviour for channel and rule administration (revision checks,
// admission caps, channel, engagement and team references), rule matching, idempotent fan-out
// with the same stable IDs, delivery listing, the delivery attempt loop, including job claim
// fencing against the memory JobQueue and the tenant and per-channel delivery rate limits, and
// channel health: the pause after repeated permanent failures and the administrator's resume.
//
// It does not reproduce behaviour that reads stores it does not have, and callers must not rely
// on it for these:
//   - the relevance facts (ScanJobSucceeded, SLAReminderDue, FleetAgentLastSeen) always report
//     true: the scan job, SLA and fleet agent rows they read have no memory counterpart;
//   - the personal inbox projection, destination change notices and delivery audit intents,
//     including the in-app notice of a channel pause.
//
// Without a JobQueue there are no claims to fence, so the attempt methods then skip the fence
// check; DeadLetterDelivery likewise skips the failed-job check.
type NotificationRepository struct {
	mu   sync.Mutex
	now  func() time.Time
	jobs *JobQueue
	// projector names the subject and snapshots the template context of each new event, as the
	// Postgres repository's does.
	projector ports.NotificationEventProjector

	channels   map[notificationKey]notification.Channel
	versions   map[channelVersionKey]string
	rules      map[notificationKey]notification.Rule
	events     map[notificationKey]storedEvent
	eventIDs   map[eventSourceKey]shared.ID
	deliveries map[notificationKey]storedDelivery
	attempts   map[notificationKey][]notification.Attempt

	engagements map[notificationKey]bool
	teams       map[notificationKey]bool
	// channelAttemptAt and tenantAttemptAt carry the delivery rate limits: channels.last_attempt_at
	// and the delivery_rate row of notification_source_state in Postgres.
	channelAttemptAt map[notificationKey]time.Time
	tenantAttemptAt  map[shared.ID]time.Time
	// healthEvents is each channel's append-only pause and resume history, keyed by channel.
	healthEvents map[notificationKey][]notification.ChannelHealthEvent
	// engagementSettings are the engagement overrides (#1360).
	engagementSettings map[notificationKey]notification.EngagementNotificationSetting
	// sourceFailures are the source records NotificationSource quarantined.
	sourceFailures []storedSourceFailure
}

var _ ports.NotificationRepository = (*NotificationRepository)(nil)

// Admission caps match postgres.notificationAdmission.
const (
	maxNotificationChannels   = 50
	maxNotificationRules      = 200
	maxOpenDeliveries         = 10000
	maxChannelTestsPerMinute  = 10
	notificationDeliverJobKey = "notification.deliver"
	// Delivery rate limits, as postgres.NotificationRepository.BeginAttempt applies them.
	tenantAttemptInterval  = 100 * time.Millisecond
	channelAttemptInterval = time.Second
)

type notificationKey struct {
	tenant shared.ID
	id     shared.ID
}

type channelVersionKey struct {
	tenant, channel shared.ID
	version         int
}

type eventSourceKey struct {
	tenant   shared.ID
	kind, id string
}

type storedEvent struct {
	event     notification.Event
	matched   []shared.ID
	revisions map[shared.ID]int
}

type storedSourceFailure struct {
	tenant  shared.ID
	failure notification.SourceFailure
}

type storedDelivery struct {
	delivery       notification.Delivery
	channelVersion int
	jobID          string
}

// NewNotificationRepository returns an empty repository. jobs, when not nil, receives one
// notification.deliver job per new delivery, as the Postgres repository inserts into jobs, and
// fences every attempt transition.
func NewNotificationRepository(jobs *JobQueue, now func() time.Time) *NotificationRepository {
	if now == nil {
		now = time.Now
	}
	return &NotificationRepository{
		now: now, jobs: jobs,
		channels: map[notificationKey]notification.Channel{}, versions: map[channelVersionKey]string{},
		rules: map[notificationKey]notification.Rule{}, events: map[notificationKey]storedEvent{},
		eventIDs: map[eventSourceKey]shared.ID{}, deliveries: map[notificationKey]storedDelivery{},
		attempts:    map[notificationKey][]notification.Attempt{},
		engagements: map[notificationKey]bool{}, teams: map[notificationKey]bool{},
		channelAttemptAt: map[notificationKey]time.Time{}, tenantAttemptAt: map[shared.ID]time.Time{},
		healthEvents:       map[notificationKey][]notification.ChannelHealthEvent{},
		engagementSettings: map[notificationKey]notification.EngagementNotificationSetting{},
	}
}

// SetEventProjector installs the event builders (#1344).
func (r *NotificationRepository) SetEventProjector(projector ports.NotificationEventProjector) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.projector = projector
}

// AddEngagement records an engagement of the tenant that rules may be scoped to. It stands in for
// the engagements table the Postgres repository checks rule references against.
func (r *NotificationRepository) AddEngagement(tenant, engagement shared.ID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.engagements[notificationKey{tenant, engagement}] = true
}

// AddTeam records an ownership team of the tenant that rules may be scoped to.
func (r *NotificationRepository) AddTeam(tenant, team shared.ID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.teams[notificationKey{tenant, team}] = true
}

func (r *NotificationRepository) CreateChannel(_ context.Context, c notification.Channel, sealed string) (notification.Channel, error) {
	if err := c.Validate(); err != nil {
		return notification.Channel{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.countChannels(c.TenantID) >= maxNotificationChannels {
		return notification.Channel{}, capacityReached("channel")
	}
	key := notificationKey{c.TenantID, c.ID}
	if _, exists := r.channels[key]; exists {
		return notification.Channel{}, fmt.Errorf("notification channel %s: %w", c.ID, shared.ErrConflict)
	}
	c = cloneChannel(c)
	if c.Recipients == nil {
		c.Recipients = []string{}
	}
	c.Health = notification.ChannelHealth{State: notification.ChannelActive}
	c.DataClass = c.Class()
	r.channels[key] = c
	r.versions[channelVersionKey{c.TenantID, c.ID, c.SecretVersion}] = sealed
	return cloneChannel(c), nil
}

func (r *NotificationRepository) UpdateChannel(_ context.Context, c notification.Channel, sealed string, replace bool) (notification.Channel, error) {
	if err := c.Validate(); err != nil {
		return notification.Channel{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := notificationKey{c.TenantID, c.ID}
	current, ok := r.channels[key]
	if !ok || current.DeletedAt != nil || current.Revision != c.Revision-1 {
		return notification.Channel{}, staleRevision("channel")
	}
	c = cloneChannel(c)
	c.SecretVersion = current.SecretVersion
	if replace {
		c.SecretVersion++
		r.versions[channelVersionKey{c.TenantID, c.ID, c.SecretVersion}] = sealed
	}
	if c.Recipients == nil {
		c.Recipients = []string{}
	}
	c.CreatedAt = current.CreatedAt
	c.DataClass = c.Class()
	// Health is not configuration: an edit keeps a pause, and a new destination or secret resets
	// the failure count of an active channel, as the Postgres update does.
	c.Health = cloneHealth(current.Health)
	if replace && !c.Health.Paused() {
		c.Health.ConsecutiveFailures = 0
	}
	r.channels[key] = c
	switch {
	case !c.Enabled:
		r.cancelOpenDeliveries(c.TenantID, c.ID, "channel_disabled", c.UpdatedAt)
	case replace || c.Destination != current.Destination:
		r.cancelOpenDeliveries(c.TenantID, c.ID, "destination_changed", c.UpdatedAt)
	}
	return cloneChannel(c), nil
}

func (r *NotificationRepository) DeleteChannel(_ context.Context, tenant, id shared.ID, revision int, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := notificationKey{tenant, id}
	current, ok := r.channels[key]
	if !ok || current.DeletedAt != nil || current.Revision != revision {
		return staleRevision("channel")
	}
	deleted := at
	current.Enabled, current.DeletedAt, current.UpdatedAt, current.Revision = false, &deleted, at, current.Revision+1
	r.channels[key] = current
	r.cancelOpenDeliveries(tenant, id, "channel_deleted", at)
	return nil
}

func (r *NotificationRepository) GetChannel(_ context.Context, tenant, id shared.ID) (notification.Channel, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.channels[notificationKey{tenant, id}]
	if !ok || c.DeletedAt != nil {
		return notification.Channel{}, fmt.Errorf("notification channel %s: %w", id, shared.ErrNotFound)
	}
	return cloneChannel(c), nil
}

func (r *NotificationRepository) ListChannels(_ context.Context, tenant shared.ID) ([]notification.Channel, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []notification.Channel
	for key, c := range r.channels {
		if key.tenant == tenant && c.DeletedAt == nil {
			out = append(out, cloneChannel(c))
		}
	}
	slices.SortFunc(out, func(a, b notification.Channel) int {
		if a.Name != b.Name {
			return strings.Compare(a.Name, b.Name)
		}
		return strings.Compare(a.ID.String(), b.ID.String())
	})
	return out, nil
}

func (r *NotificationRepository) countChannels(tenant shared.ID) int {
	n := 0
	for key, c := range r.channels {
		if key.tenant == tenant && c.DeletedAt == nil {
			n++
		}
	}
	return n
}

// enabledChannel returns a channel that is enabled and not deleted, paused or not.
func (r *NotificationRepository) enabledChannel(tenant, id shared.ID) (notification.Channel, bool) {
	c, ok := r.channels[notificationKey{tenant, id}]
	return c, ok && c.Enabled && c.DeletedAt == nil
}

// activeChannel returns an enabled, not deleted and not paused channel, as the fan-out query
// selects them: a paused channel receives no new deliveries (#1464).
func (r *NotificationRepository) activeChannel(tenant, id shared.ID) (notification.Channel, bool) {
	c, ok := r.enabledChannel(tenant, id)
	return c, ok && !c.Health.Paused()
}

// cancelOpenDeliveries mirrors the Postgres update: pending or retrying deliveries of the channel
// with no attempt in flight are cancelled.
func (r *NotificationRepository) cancelOpenDeliveries(tenant, channel shared.ID, reason string, at time.Time) {
	for key, stored := range r.deliveries {
		d := stored.delivery
		if key.tenant != tenant || d.ChannelID != channel || !openDelivery(d.State) || r.attemptInFlight(key) {
			continue
		}
		d.State, d.LastError, d.NextAttemptAt, d.UpdatedAt = notification.DeliveryCancelled, reason, nil, at
		stored.delivery = d
		r.deliveries[key] = stored
	}
}

func (r *NotificationRepository) attemptInFlight(delivery notificationKey) bool {
	for _, a := range r.attempts[delivery] {
		if a.Outcome == "started" {
			return true
		}
	}
	return false
}

func openDelivery(state notification.DeliveryState) bool {
	return state == notification.DeliveryPending || state == notification.DeliveryRetrying
}

func cloneChannel(c notification.Channel) notification.Channel {
	c.Recipients = slices.Clone(c.Recipients)
	c.DeletedAt = cloneTime(c.DeletedAt)
	c.Health = cloneHealth(c.Health)
	return c
}

func cloneHealth(h notification.ChannelHealth) notification.ChannelHealth {
	h.PausedAt = cloneTime(h.PausedAt)
	h.LastFailureAt = cloneTime(h.LastFailureAt)
	return h
}

func capacityReached(kind string) error {
	return fmt.Errorf("%w: notification %s capacity reached", shared.ErrSaturated, kind)
}

func staleRevision(kind string) error {
	return fmt.Errorf("notification %s revision is stale: %w", kind, shared.ErrConflict)
}

// notificationStableID is the derivation of postgres.stableID, so event and delivery IDs match
// between the two adapters.
func notificationStableID(parts ...string) shared.ID {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return shared.ID(hex.EncodeToString(h[:16]))
}
