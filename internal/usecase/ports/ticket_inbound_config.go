package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TicketInboundConfiguration binds the integration principal to the connection
// and credential revisions verified before enabling signed inbound observations.
type TicketInboundConfiguration struct {
	TenantID           shared.ID
	IntegrationID      shared.ID
	Enabled            bool
	IntegrationAuthor  string
	ConnectionRevision int
	CredentialRevision int
	Version            int
	UpdatedAt          time.Time
}

type TicketInboundConfigurationStore interface {
	GetTicketInboundConfiguration(context.Context, shared.ID, shared.ID) (TicketInboundConfiguration, error)
	SaveTicketInboundConfiguration(context.Context, shared.ID, TicketInboundConfiguration, int) (TicketInboundConfiguration, error)
}

// TicketWebhookCapability refuses unsupported server versions before a hook
// credential is provisioned. The returned principal is the authenticated user.
type TicketWebhookCapability interface {
	TicketWebhookPrincipal(context.Context) (string, error)
}

// TicketExternalTextSanitizer applies the shared redactor with the configured
// credential values while they remain inside the provider boundary.
type TicketExternalTextSanitizer interface {
	RedactExternalTicketText(string) (string, error)
}
