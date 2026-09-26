package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// RecipientResolver returns the people a personal notification addresses.
// Implementations return stable user IDs and the roles that selected them.
// They do not return contact addresses, and they do not infer a person from
// free text. Mention, approver, and engagement-lead roles stay unsupported
// until a producer records a verified identity.
type RecipientResolver interface {
	ResolvePersonalRecipients(context.Context, shared.ID, notification.Event) ([]notification.ResolvedRecipient, error)
}
