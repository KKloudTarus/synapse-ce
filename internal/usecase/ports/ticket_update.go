package ports

import (
	"context"
	"encoding/json"
)

// TicketUpdater changes the mutable fields of an existing managed issue. The
// payload has only a fields object; project/type identity and comments are separate
// capabilities. Ambiguous errors must be reconciled before another write.
type TicketUpdater interface {
	UpdateTicket(context.Context, string, json.RawMessage) error
}
