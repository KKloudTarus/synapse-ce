package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
)

// TicketStatusProgress is the durable reducer checkpoint for one linked ticket.
// SourceRevision identifies a status episode, so a later reopen and re-close is
// not collapsed into the earlier close.
type TicketStatusProgress struct {
	TenantID           shared.ID
	MappingID          shared.ID
	EngagementID       shared.ID
	FindingID          shared.ID
	DesiredState       ticketing.SyncState
	AppliedState       ticketing.SyncState
	SourceRevision     string
	TransitionIntentID shared.ID
	UpdateIntentID     shared.ID
	IntegrationAuthor  string
	Episode            int
	Version            int
	CheckedAt          time.Time
}

type TicketStatusProgressStore interface {
	GetTicketStatusProgress(context.Context, shared.ID, shared.ID, shared.ID, shared.ID) (TicketStatusProgress, error)
	CreateTicketStatusProgress(context.Context, shared.ID, TicketStatusProgress) (TicketStatusProgress, bool, error)
	UpdateTicketStatusProgress(context.Context, shared.ID, TicketStatusProgress, int) (TicketStatusProgress, error)
}
