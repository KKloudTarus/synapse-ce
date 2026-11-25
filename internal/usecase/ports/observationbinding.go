package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/observationbinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ObservationBindingStore persists the human-approved links between external observations and canonical
// findings.
//
// One scoped external identity has at most ONE binding in force inside a tenant engagement, and that is
// enforced by the store rather than by the caller: two people adopting the same observation at the same
// moment must end with one binding and one loser, not with two workflows that each believe they own the
// remediation.
//
// Superseded versions are kept. A binding that was replaced is the record of what the workflow used to
// believe and why it stopped, which is the only way an operator can audit a decision that turned out to
// be wrong.
type ObservationBindingStore interface {
	// Adopt records the first binding for a scoped identity.
	//
	// It is idempotent for the SAME finding: re-adopting returns the binding already in force, so a
	// retried request cannot mint a second version. Adopting a DIFFERENT finding while one is in force is
	// shared.ErrConflict, never a silent replacement: changing a decision is Supersede, which demands its
	// own actor and reason.
	Adopt(ctx context.Context, tenantID shared.ID, binding observationbinding.Binding) (observationbinding.Binding, error)

	// Supersede replaces the binding in force with a new version, atomically. It is shared.ErrNotFound
	// when nothing is in force and shared.ErrConflict when the caller's expected version is not the one
	// it is replacing, so a decision made against a stale view is refused rather than applied.
	Supersede(ctx context.Context, tenantID shared.ID, expectedVersion int, binding observationbinding.Binding) (observationbinding.Binding, error)

	// Current returns the binding in force, or shared.ErrNotFound when the observation has never been
	// adopted. A candidate match is not a binding and is never returned here.
	Current(ctx context.Context, tenantID, engagementID shared.ID, identity observationbinding.Identity) (observationbinding.Binding, error)

	// CurrentByEngagement returns only the bindings in force, in no particular order. The page-load path
	// folds them into a map, so ordering every version by decision time would be work with no consumer.
	CurrentByEngagement(ctx context.Context, tenantID, engagementID shared.ID) ([]observationbinding.Binding, error)

	// ListByEngagement returns every version of every binding in the engagement, newest decision first.
	// It carries superseded versions on purpose: the lineage is the point.
	ListByEngagement(ctx context.Context, tenantID, engagementID shared.ID) ([]observationbinding.Binding, error)
}
