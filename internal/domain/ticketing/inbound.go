package ticketing

import (
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ExternalTicketObservation is provider state only. It never changes a
// finding's security status; a done transition may create a retest proposal.
type ExternalTicketObservation struct {
	TenantID          shared.ID
	IntegrationID     shared.ID
	MappingID         shared.ID
	EngagementID      shared.ID
	FindingID         shared.ID
	RemoteID          string
	StatusCategory    string
	ProviderUpdatedAt time.Time
	StatusChangedAt   time.Time
	AuthorID          string
	ResolutionName    string
	// StatusAuthorKnown is true only when the provider proved AuthorID changed
	// the current status. It is never inferred from a webhook's generic user.
	StatusAuthorKnown bool
	// OwnWrite is trusted application input used only while reducing the current
	// observation. It is intentionally not persisted.
	OwnWrite            bool
	PendingDone         bool
	DeletedOrUnreadable bool
	CheckedAt           time.Time
	Version             int
}

type RetestProposal struct {
	ID             shared.ID
	TenantID       shared.ID
	EngagementID   shared.ID
	FindingID      shared.ID
	IntegrationID  shared.ID
	RemoteID       string
	ResolutionName string
	ObservedAt     time.Time
	State          string
}

type ExternalTicketComment struct {
	ID            shared.ID
	TenantID      shared.ID
	IntegrationID shared.ID
	EngagementID  shared.ID
	FindingID     shared.ID
	RemoteID      string
	AuthorID      string
	Body          string
	ProviderAt    time.Time
	CreatedAt     time.Time
}

func (o ExternalTicketObservation) Valid() bool {
	return !o.TenantID.IsZero() && !o.IntegrationID.IsZero() && !o.MappingID.IsZero() && !o.EngagementID.IsZero() && !o.FindingID.IsZero() && strings.TrimSpace(o.RemoteID) != "" && len(o.ResolutionName) <= 255 && (strings.TrimSpace(o.StatusCategory) != "" || o.DeletedOrUnreadable) && (o.DeletedOrUnreadable || !o.ProviderUpdatedAt.IsZero()) && !o.CheckedAt.IsZero() && o.Version > 0
}
