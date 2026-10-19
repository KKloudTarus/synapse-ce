package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
)

type TicketInboundView struct {
	Observations []ticketing.ExternalTicketObservation
	Proposals    []ticketing.RetestProposal
	Comments     []ticketing.ExternalTicketComment
}

type TicketInboundStore interface {
	ResolveInboundTicket(context.Context, shared.ID, shared.ID, string) ([]TicketStatusTarget, error)
	ReduceInboundTicket(context.Context, shared.ID, []ticketing.ExternalTicketObservation, []ticketing.ExternalTicketComment, time.Time) error
	ListInboundTicketView(context.Context, shared.ID, shared.ID, shared.ID) (TicketInboundView, error)
	ListInboundTicketTargets(context.Context, shared.ID, int) ([]TicketStatusTarget, error)
	RecordInboundTicketPoll(context.Context, shared.ID, TicketStatusTarget, time.Time) error
}
