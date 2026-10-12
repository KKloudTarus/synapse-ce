package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
)

// TicketStore is independent of the CI scheduler and integration_operations.
// Implementations must enforce tenant scoping, idempotency and CAS transitions atomically.
type TicketStore interface {
	CreateMapping(context.Context, shared.ID, ticketing.Mapping) error
	GetMapping(context.Context, shared.ID, shared.ID) (ticketing.Mapping, error)
	CreateLink(context.Context, shared.ID, ticketing.Link) (ticketing.Link, bool, error)
	ListLinks(context.Context, shared.ID, shared.ID) ([]ticketing.Link, error)
	DeleteLink(context.Context, shared.ID, shared.ID) error
	CreateOrGetIntent(context.Context, shared.ID, ticketing.Intent) (ticketing.Intent, bool, error)
	GetIntent(context.Context, shared.ID, shared.ID) (ticketing.Intent, error)
	TransitionIntent(context.Context, shared.ID, shared.ID, int, ticketing.IntentTransition, time.Time) (ticketing.Intent, error)
}
