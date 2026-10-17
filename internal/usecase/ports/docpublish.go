package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// DocumentStore persists published-document links and the write intents that produce them.
// It is independent of the CI scheduler, integration_operations and notification deliveries.
// Implementations must enforce tenant scoping, idempotency and CAS transitions atomically,
// and must persist a completion's link in the same unit as the intent that completed it.
type DocumentStore interface {
	GetLink(ctx context.Context, tenant, id shared.ID) (docpublish.Link, error)
	// FindLink returns the single link a target addresses, or shared.ErrNotFound.
	FindLink(ctx context.Context, tenant shared.ID, target docpublish.Target) (docpublish.Link, error)
	// ListLinks returns the newest links of one scope, at most limit of them
	// (1 through docpublish.MaxListLimit).
	ListLinks(ctx context.Context, tenant shared.ID, scope docpublish.Scope, scopeID shared.ID, limit int) ([]docpublish.Link, error)
	// CreateOrGetIntent records a pending command. A replayed request key returns the original
	// command with created=false; the same key with different content is shared.ErrConflict.
	// A create for a target that already has a link is shared.ErrConflict: its page exists.
	CreateOrGetIntent(ctx context.Context, tenant shared.ID, intent docpublish.Intent) (docpublish.Intent, bool, error)
	GetIntent(ctx context.Context, tenant, id shared.ID) (docpublish.Intent, error)
	// TransitionIntent applies one evidence event if the intent is still at expectedVersion.
	// A completing transition writes the resulting link in the same unit; if that write is
	// refused the intent is left exactly as it was.
	TransitionIntent(ctx context.Context, tenant, id shared.ID, expectedVersion int, change docpublish.IntentTransition, at time.Time) (docpublish.Intent, error)
}
