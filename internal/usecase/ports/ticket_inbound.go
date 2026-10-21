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

// TicketInboundPollClaim reserves one durable target before provider I/O. Its
// version fences a crashed or stale worker from replacing a later deferral.
type TicketInboundPollClaim struct {
	Target     TicketStatusTarget
	Version    int
	NextPollAt time.Time
}

// TicketInboundClaimStore is the durable polling extension. The legacy store
// methods remain for read-only compatibility doubles; production stores must
// implement this contract so every provider request has a leased queue turn.
type TicketInboundClaimStore interface {
	ClaimInboundTicketTargets(context.Context, shared.ID, int, time.Time, time.Duration) ([]TicketInboundPollClaim, error)
	CompleteInboundTicketPoll(context.Context, shared.ID, TicketInboundPollClaim, time.Time, time.Time) error
}
