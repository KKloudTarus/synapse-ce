package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
)

// NotificationOutbox is how a producer announces a notification-worthy change (EPIC #1327 D2).
// Append must run inside TenantTransactionRunner.Run, in the same transaction as the business
// write it describes: the record commits or rolls back with it, so a notification can neither be
// lost after a commit nor sent for a write that rolled back. Called outside a transaction, or for
// another tenant, Append fails instead of writing on its own.
//
// Append is idempotent on (tenant, source kind, source id): the first record wins. Records dated
// before the tenant's notification framework was activated are dropped, as the capture triggers
// of migration 0163 do.
type NotificationOutbox interface {
	Append(ctx context.Context, record notification.SourceRecord) error
}
