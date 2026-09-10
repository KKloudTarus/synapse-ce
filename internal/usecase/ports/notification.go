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

type NotificationWork struct {
	Delivery notification.Delivery
	Event    notification.Event
	Channel  notification.Channel
	Sealed   string
}

type NotificationChannelConfig struct {
	URL        string   `json:"url,omitempty"`
	Secret     string   `json:"secret,omitempty"`
	Username   string   `json:"username,omitempty"`
	Password   string   `json:"password,omitempty"`
	Recipients []string `json:"recipients,omitempty"`
}

type NotificationSendResult struct {
	StatusCode int
	ErrorCode  string
	Retryable  bool
	RetryAfter time.Duration
}

type NotificationSender interface {
	Send(context.Context, NotificationWork, NotificationChannelConfig) NotificationSendResult
}

// NotificationRepository owns the transactional event → rule → delivery → job
// handoff. Publish must be idempotent on (tenant, source kind, source id).
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

	Publish(context.Context, notification.Event) ([]shared.ID, error)
	PublishToChannel(context.Context, notification.Event, shared.ID) (shared.ID, error)
	GetDelivery(context.Context, shared.ID, shared.ID) (notification.Delivery, error)
	ListDeliveries(context.Context, NotificationDeliveryFilter) (notification.Page, error)
	ListAttempts(context.Context, shared.ID, shared.ID) ([]notification.Attempt, error)
	LoadWork(context.Context, shared.ID, shared.ID) (NotificationWork, error)
	DeliveryStillRelevant(context.Context, NotificationWork) (bool, error)
	BeginAttempt(context.Context, shared.ID, shared.ID, string, int64, shared.ID, time.Time) (notification.Attempt, error)
	FinishAttempt(context.Context, shared.ID, shared.ID, string, int64, shared.ID, time.Time, string, int, string, *time.Time) error
	CancelDelivery(context.Context, shared.ID, shared.ID, string, int64, string) error
	DeadLetterDelivery(context.Context, shared.ID, shared.ID, string) error
}

// NotificationSource scans durable source state and publishes due events. It is
// called by the worker maintenance leader and must be safe across restarts.
type NotificationSource interface {
	Poll(context.Context, time.Time, int) (int, error)
}
