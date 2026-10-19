package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
)

// TicketPolicyReader supplies the engagement privacy setting needed to create a
// ticket. It is deliberately narrower than NotificationRepository because ticket
// workflows only read this policy.
type TicketPolicyReader interface {
	GetEngagementNotificationSetting(context.Context, shared.ID, shared.ID) (notification.EngagementNotificationSetting, error)
}

// TicketStore is independent of the CI scheduler and integration_operations.
// Implementations must enforce tenant scoping, idempotency and CAS transitions atomically.
type TicketStore interface {
	CreateMapping(context.Context, shared.ID, ticketing.Mapping) error
	GetMapping(context.Context, shared.ID, shared.ID) (ticketing.Mapping, error)
	ListMappings(context.Context, shared.ID, int, shared.ID) ([]ticketing.Mapping, error)
	ListScopedMappings(context.Context, shared.ID, ticketing.Scope, shared.ID, int) ([]ticketing.Mapping, error)
	ListFindingMappings(context.Context, shared.ID, shared.ID, int) ([]ticketing.Mapping, error)
	UpdateMapping(context.Context, shared.ID, ticketing.Mapping, int) (ticketing.Mapping, error)
	DeleteMapping(context.Context, shared.ID, shared.ID, int) error
	CreateLink(context.Context, shared.ID, ticketing.Link) (ticketing.Link, bool, error)
	GetLink(context.Context, shared.ID, shared.ID) (ticketing.Link, error)
	ListLinks(context.Context, shared.ID, shared.ID) ([]ticketing.Link, error)
	DeleteLink(context.Context, shared.ID, shared.ID) error
	CreateOrGetIntent(context.Context, shared.ID, ticketing.Intent) (ticketing.Intent, bool, error)
	GetIntent(context.Context, shared.ID, shared.ID) (ticketing.Intent, error)
	ListFindingIntents(context.Context, shared.ID, shared.ID, int) ([]ticketing.Intent, error)
	ListDueIntents(context.Context, shared.ID, time.Time, int) ([]ticketing.Intent, error)
	TransitionIntent(context.Context, shared.ID, shared.ID, int, ticketing.IntentTransition, time.Time) (ticketing.Intent, error)
}

// TicketAuditStore makes an administrative ticketing mutation and its audit record
// one database transaction. Jira workflows require it; plain foundation operations
// remain available to provider-independent consumers.
type TicketAuditStore interface {
	CreateMappingAudited(context.Context, shared.ID, ticketing.Mapping, AuditEntry) error
	UpdateMappingAudited(context.Context, shared.ID, ticketing.Mapping, int, AuditEntry) (ticketing.Mapping, error)
	DeleteMappingAudited(context.Context, shared.ID, shared.ID, int, AuditEntry) error
}

// TicketIntentAuditStore persists durable external-write commands and their audit
// evidence in one transaction. A caller must not fall back to a separate audit write.
type TicketIntentAuditStore interface {
	CreateOrGetIntentAudited(context.Context, shared.ID, ticketing.Intent, AuditEntry) (ticketing.Intent, bool, error)
	TransitionIntentAudited(context.Context, shared.ID, shared.ID, int, ticketing.IntentTransition, time.Time, AuditEntry) (ticketing.Intent, error)
	RetryIntentAudited(context.Context, shared.ID, shared.ID, int, time.Time, AuditEntry) (ticketing.Intent, error)
}

// TicketDispatchStore fences outbound ticket requests by tenant/integration/project/type.
// It deliberately does not hold a database transaction while a provider request is in flight.
type TicketDispatchStore interface {
	AcquireDispatch(context.Context, shared.ID, shared.ID, int, time.Time, time.Time) (ticketing.Intent, bool, error)
	FinishDispatch(context.Context, shared.ID, shared.ID, int, ticketing.IntentTransition, time.Time, *time.Time, string) (ticketing.Intent, error)
	RetryIntentAudited(context.Context, shared.ID, shared.ID, int, time.Time, AuditEntry) (ticketing.Intent, error)
	ResetBreaker(context.Context, shared.ID, shared.ID, string, string, AuditEntry) error
}

// TicketAutoPushEvent is a durable finding status change projected from the
// transactional notification source. It is intentionally narrower than a
// notification feed: consumers resume through durable per-event receipts.
type TicketAutoPushEvent struct {
	ID           shared.ID
	OccurredAt   time.Time
	EngagementID shared.ID
	FindingID    shared.ID
	ToStatus     string
}

// TicketAutoPushStore is an optional extension implemented by durable ticket
// stores. Its receipt is per immutable event, not a time cursor: source events
// can be projected late or carry an older occurrence timestamp.
type TicketAutoPushStore interface {
	ListAutoPushEvents(context.Context, shared.ID, time.Time, int) ([]TicketAutoPushEvent, error)
	CompleteAutoPushEvent(context.Context, shared.ID, TicketAutoPushEvent, time.Time) error
	DeferAutoPushEvent(context.Context, shared.ID, TicketAutoPushEvent, time.Time) error
}

// TicketGroup is a durable reservation for a vulnerability/project ticket. Its
// destination facts are copied at reservation time: a later mapping edit must
// never silently write to a ticket created for a different Jira destination.
type TicketGroup struct {
	ID            shared.ID
	TenantID      shared.ID
	MappingID     shared.ID
	ProjectID     shared.ID
	Vulnerability string
	IntegrationID shared.ID
	Endpoint      string
	ProjectKey    string
	IssueType     string
	SecurityLevel string
	IntentID      shared.ID
	Remote        ticketing.RemoteTicket
	CreatedAt     time.Time
	UpdatedAt     time.Time
	Revision      int
}

type TicketGroupMember struct {
	EngagementID shared.ID
	FindingID    shared.ID
}

// TicketGroupStore is deliberately a narrow extension: it reserves a group and
// its first durable command atomically. A pending or uncertain command remains
// the reservation, so a rescan cannot create a second remote ticket.
type TicketGroupStore interface {
	GetTicketGroup(context.Context, shared.ID, shared.ID, shared.ID, string) (TicketGroup, bool, error)
	CreateOrGetGroupedIntent(context.Context, shared.ID, TicketGroup, TicketGroupMember, ticketing.Intent, AuditEntry) (ticketing.Intent, bool, error)
	CompleteGroupedIntent(context.Context, shared.ID, shared.ID, ticketing.RemoteTicket, time.Time) error
	ValidateTicketGroupDestination(context.Context, shared.ID, TicketGroup) error
}

// TicketStatusTarget is an existing provider ticket whose originating command
// proves its mapping and immutable destination. Manual links intentionally do
// not appear here.
type TicketStatusTarget struct {
	Mapping ticketing.Mapping
	Intent  ticketing.Intent
}

type TicketStatusStore interface {
	ListTicketStatusTargets(context.Context, shared.ID, int) ([]TicketStatusTarget, error)
}
