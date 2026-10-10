package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// PersonalMessage is one personal notification ready to leave Synapse (#1418): what the inbox row
// says and the verified contact it goes to. Recipient is the contact value: an email address, a
// Slack <workspace>:<member> pair or a Teams Entra object ID.
type PersonalMessage struct {
	TenantID  shared.ID
	UserID    shared.ID
	EventID   shared.ID
	EventType notification.EventType
	Channel   string
	ContactID shared.ID
	Recipient string
	Title     string
	Summary   string
	LinkPath  string
}

// PersonalDeliveryStore re-reads a queued personal message when its job runs. ok is false when the
// person was disabled or lost their role, muted the channel, the tenant default changed to off, the
// contact changed or lost its verification, or the engagement now allows nothing to leave Synapse;
// the job then ends without sending and is never pointed at another contact.
type PersonalDeliveryStore interface {
	LoadPersonalDelivery(ctx context.Context, tenant, user, event, contact shared.ID, version int, channel string) (PersonalMessage, bool, error)
}

// PersonalDefaultsStore keeps a tenant's personal delivery defaults (#1418).
type PersonalDefaultsStore interface {
	ListPersonalDefaults(ctx context.Context, tenant shared.ID) ([]notification.PersonalDefault, error)
	// SavePersonalDefault stores one default whose revision is the stored one plus one (1 for the
	// first) and reports shared.ErrConflict when another write got there first. The audit entry is
	// written in the same transaction.
	SavePersonalDefault(ctx context.Context, tenant shared.ID, actor string, event notification.EventType, channel string, enabled bool, revision int, at time.Time) (notification.PersonalDefault, error)
}

// PersonalChannelSender sends one personal message on a channel that leaves Synapse through a
// provider bot: a Slack direct message (#1419) or a Teams personal chat (#1420). It returns a
// transport result whose error code never holds a token or contact value.
type PersonalChannelSender interface {
	SendPersonal(ctx context.Context, message PersonalMessage) NotificationSendResult
}
