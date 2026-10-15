package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// EngagementMutationLocker reads one visible engagement while holding its row
// lock in the caller's ambient tenant transaction. Lifecycle producers use it
// so concurrent status or authorization-window updates cannot capture facts
// from a row that a competing mutation is about to replace.
//
// This is deliberately separate from EngagementRepository: read-only callers
// and focused fakes do not need to implement a write-locking operation.
type EngagementMutationLocker interface {
	GetByIDInTenantForUpdate(context.Context, shared.ID, shared.ID) (*engagement.Engagement, error)
}
