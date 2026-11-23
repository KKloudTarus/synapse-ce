package ports

import (
	"context"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// PagerMutation is a durable decision made before outbound I/O. An existing
// operation never gains permission to repeat a write merely because its lease expired.
type PagerMutation struct {
	OperationID        shared.ID
	Action             string // send, poll, complete, suppressed, blocked
	ProviderRequestRef string
	RemoteRef          string
	SubjectAnchor      string
	Code               string
}

// NotificationPagerRepository owns episode admission and receipts independently
// of queue completion. Late receipts must survive a stale worker lease.
type NotificationPagerRepository interface {
	// ReconcilePagerAcknowledgement records an already accepted operation without
	// admitting another send, including after the channel has been disabled.
	ReconcilePagerAcknowledgement(ctx context.Context, tenant, delivery shared.ID, jobID string, fence int64) (bool, error)
	AdmitPagerMutation(ctx context.Context, tenant, delivery shared.ID, jobID string, fence int64, operation shared.ID) (PagerMutation, error)
	RecordPagerReceipt(ctx context.Context, tenant, delivery, operation shared.ID, result NotificationSendResult) error
}
