package ports

import (
	"context"
	"time"
)

// TicketStatusWriter performs a transition. Legacy commands can carry their
// bundled explanatory comment; versioned commands deliberately pass an empty
// comment and use TicketCommentWriter after the transition is durable.
type TicketStatusWriter interface {
	TransitionTicket(context.Context, string, string, string) error
}

// TicketCommentReceipt is deliberately separate from RemoteTicket: an intent's
// durable remote identity remains the managed issue, while this ID only proves
// the provider accepted a particular comment on that issue.
type TicketCommentReceipt struct{ ID string }

// TicketCommentWriter and TicketCommentReader are consumer-owned seams for the
// dedicated Jira comment endpoint and its bounded recovery read.
type TicketCommentWriter interface {
	CommentTicket(context.Context, string, string, string) (TicketCommentReceipt, error)
}

type TicketCommentReader interface {
	FindTicketComment(context.Context, string, string, string, string) (bool, error)
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
