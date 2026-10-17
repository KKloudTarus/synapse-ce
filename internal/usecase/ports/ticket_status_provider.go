package ports

import (
	"context"
	"time"
)

// TicketStatusWriter performs one transition and its explanatory comment in a
// single provider request. Field updates are a separate, subsequent command.
type TicketStatusWriter interface {
	TransitionTicket(context.Context, string, string, string) error
}

type TicketObservation struct {
	ExternalID      string
	StatusCategory  string
	UpdatedAt       time.Time
	AuthorID        string
	StatusChangedAt time.Time // AuthorID is proven for this status episode only.
	Deleted         bool
	ResolutionName  string // Context only; never a closure trigger.
}

type TicketReader interface {
	GetTicket(context.Context, string) (TicketObservation, error)
}

// TicketIdentityReader returns the authenticated integration principal for exact
// own-write echo suppression. A display name is never an identity.
type TicketIdentityReader interface {
	TicketIdentity(context.Context) (string, error)
}
