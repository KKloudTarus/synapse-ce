package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
)

// TicketRequestReader recovers the original command on a lost submit response,
// before regenerating a preview from mutable membership or finding data.
type TicketRequestReader interface {
	FindTicketRequest(context.Context, shared.ID, shared.ID, shared.ID, shared.ID, string) (ticketing.Intent, bool, error)
}
