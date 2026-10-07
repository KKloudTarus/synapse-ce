package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// NotificationSecretProtector encrypts channel configuration at rest. Implementations
// authenticate aad so ciphertext cannot be moved between tenants or channel versions.
type NotificationSecretProtector interface {
	Seal(plaintext, aad []byte) (string, error)
	Open(ciphertext string, aad []byte) ([]byte, error)
}

type NotificationDeliveryFilter struct {
	TenantID  shared.ID
	ChannelID shared.ID
	EventType notification.EventType
	State     notification.DeliveryState
	Before    time.Time
	BeforeID  shared.ID
	From      time.Time
	Until     time.Time
	Limit     int
}

type NotificationSourceFailureFilter struct {
	TenantID  shared.ID
	EventType notification.EventType
	From      time.Time
	Until     time.Time
	Limit     int
	Offset    int
}

type NotificationWork struct {
	Delivery notification.Delivery
	Event    notification.Event
	// Engagement is the event's engagement override (#1360); inherit when the event has no
	// engagement or the engagement stores none.
	Engagement notification.EngagementNotifications
	Channel    notification.Channel
	Sealed     string
	// CustomWebhookBody is a rendered custom JSON body for a webhook channel that opted into one
	// (#1376). The send-time renderer (#1365) sets it with notification.RenderCustomWebhookBody;
	// nothing sets it yet. When it is not empty the webhook driver sends exactly these bytes instead
	// of the event envelope, signs them and sets X-Synapse-Body: custom.
	CustomWebhookBody []byte
}

type NotificationSendResult struct {
	StatusCode int
	ErrorCode  string
	Retryable  bool
	RetryAfter time.Duration
	// TemplateFallback is true only when the sender rendered built-in fallback
	// content rather than the preferred event fields/template.
	TemplateFallback bool
	// RemoteRef is the provider's handle for the delivered message (a Slack ts, a ticket key), kept
	// on the delivery so a later event about the same subject can reply to it. Empty when the
	// provider returns none.
	RemoteRef string
}

// NotificationDeliveryObserver is optional worker-only instrumentation. Every
// callback follows a committed delivery transition, never a speculative send.
type NotificationDeliveryObserver interface {
	ObserveNotificationAttempt(notification.ChannelType, time.Duration, bool, bool)
	ObserveNotificationDeadLetter(notification.ChannelType)
}

// NotificationPendingMetricsReader returns the oldest pending/retrying delivery
// by channel family across every tenant without exposing tenant identifiers.
type NotificationPendingMetricsReader interface {
	NotificationOldestPending(context.Context) (map[notification.ChannelType]time.Time, error)
}

type NotificationSender interface {
	Send(context.Context, NotificationWork, NotificationChannelConfig) NotificationSendResult
}

// NotificationRepository owns notification administration and delivery work.
// Producers publish through their transactional stores; PublishToChannel is
// retained for targeted channel publication.
type NotificationRepository interface {
	CreateChannel(context.Context, notification.Channel, string) (notification.Channel, error)
	UpdateChannel(context.Context, notification.Channel, string, bool) (notification.Channel, error)
	DeleteChannel(context.Context, shared.ID, shared.ID, int, time.Time) error
	GetChannel(context.Context, shared.ID, shared.ID) (notification.Channel, error)
	ListChannels(context.Context, shared.ID) ([]notification.Channel, error)

	CreateRule(context.Context, notification.Rule) (notification.Rule, error)
	UpdateRule(context.Context, notification.Rule) (notification.Rule, error)
	DeleteRule(context.Context, shared.ID, shared.ID, int) error
	GetRule(context.Context, shared.ID, shared.ID) (notification.Rule, error)
	ListRules(context.Context, shared.ID) ([]notification.Rule, error)

	PublishToChannel(context.Context, notification.Event, shared.ID) (shared.ID, error)
	GetDelivery(context.Context, shared.ID, shared.ID) (notification.Delivery, error)
	ListDeliveries(context.Context, NotificationDeliveryFilter) (notification.Page, error)
	ListSourceFailures(context.Context, NotificationSourceFailureFilter) (notification.SourceFailurePage, error)
	ListAttempts(context.Context, shared.ID, shared.ID) ([]notification.Attempt, error)
	LoadWork(context.Context, shared.ID, shared.ID) (NotificationWork, error)
	NotificationRelevance

	// GetEngagementNotificationSetting returns an engagement's override, or inherit at revision 0
	// when none is stored. It reports ErrNotFound for an engagement the tenant does not have.
	GetEngagementNotificationSetting(ctx context.Context, tenant, engagement shared.ID) (notification.EngagementNotificationSetting, error)
	// PutEngagementNotificationSetting stores an override whose Revision is the stored one plus one
	// (1 for the first), and reports ErrConflict when another write got there first.
	PutEngagementNotificationSetting(ctx context.Context, setting notification.EngagementNotificationSetting) (notification.EngagementNotificationSetting, error)
	BeginAttempt(context.Context, shared.ID, shared.ID, string, int64, shared.ID, time.Time) (notification.Attempt, error)
	FinishAttempt(context.Context, shared.ID, shared.ID, string, int64, shared.ID, time.Time, string, int, string, *time.Time) error
	CancelDelivery(context.Context, shared.ID, shared.ID, string, int64, string) error
	// DeadLetterDelivery reports whether this call durably transitioned a pending
	// delivery to dead_letter for the current queue fence. Delayed callbacks from an
	// earlier redrive cycle return false.
	DeadLetterDelivery(context.Context, shared.ID, shared.ID, int64, string) (bool, error)
	// RedriveDelivery requeues the existing failed notification job and resets its
	// queue retry budget atomically. expectedFence makes repeated/stale UI requests
	// conflict. It refuses stale channel config and active/paused destinations.
	RedriveDelivery(context.Context, shared.ID, shared.ID, int64) (notification.Delivery, notification.Channel, error)

	// RecordChannelOutcome applies one finished attempt to its channel's health (#1464). When the
	// observation pauses the channel, the same transaction appends the pause to the history,
	// cancels the channel's queued deliveries with channel_paused and publishes the in-app notice
	// to tenant administrators. Deleted channels are ignored.
	RecordChannelOutcome(context.Context, shared.ID, NotificationChannelOutcome) (NotificationChannelTransition, error)
	// ResumeChannel clears a pause for an administrator, guarded by the channel revision, and
	// appends the resume to the history. It bumps the revision.
	ResumeChannel(context.Context, shared.ID, shared.ID, int, string, time.Time) (notification.Channel, error)
	// ListChannelHealthEvents returns a channel's pause and resume history, newest first.
	ListChannelHealthEvents(context.Context, shared.ID, shared.ID, int) ([]notification.ChannelHealthEvent, error)
}

// NotificationEventReader reads a tenant's stored notification events for the template preview
// (#1372). Both methods see only the tenant's own events; another tenant's event is not found.
type NotificationEventReader interface {
	// ListRecentNotificationEvents returns up to limit events of one type, newest first.
	ListRecentNotificationEvents(ctx context.Context, tenant shared.ID, eventType notification.EventType, limit int) ([]notification.Event, error)
	// GetNotificationEvent returns one event, or shared.ErrNotFound.
	GetNotificationEvent(ctx context.Context, tenant, id shared.ID) (notification.Event, error)
}

// NotificationChannelOutcome is one finished attempt as channel health reads it.
type NotificationChannelOutcome struct {
	ChannelID  shared.ID
	DeliveryID shared.ID
	AttemptID  shared.ID
	Class      notification.AttemptClass
	// Code is the sanitized attempt error code; empty for a delivered attempt.
	Code string
	At   time.Time
	// Threshold is the pause threshold; zero counts failures without pausing.
	Threshold int
}

// NotificationChannelTransition reports what RecordChannelOutcome committed.
type NotificationChannelTransition struct {
	Paused  bool
	PauseID shared.ID
	Health  notification.ChannelHealth
}

// NotificationSource scans durable source state and publishes due events. It is
// called by the worker maintenance leader and must be safe across restarts.
type NotificationSource interface {
	Poll(context.Context, time.Time, int) (int, error)
}
