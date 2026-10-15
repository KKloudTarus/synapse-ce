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
