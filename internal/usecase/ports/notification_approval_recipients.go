package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ApprovalNotificationOutbox captures the immutable approval recipient roster
// with its source record. The source key is the idempotency boundary: if a
// source already exists, implementations retain its first roster unchanged.
type ApprovalNotificationOutbox interface {
	AppendApprovalSource(context.Context, notification.SourceRecord, []shared.ID) error
}

// ApprovalNotificationRecipientReader resolves the roster captured for an
// approval source. It is deliberately separate from the public event payload:
// recipient identities are routing facts, not notification content.
type ApprovalNotificationRecipientReader interface {
	ApprovalNotificationRecipients(context.Context, shared.ID, string, string) ([]shared.ID, error)
}
