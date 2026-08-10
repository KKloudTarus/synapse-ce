package emulation

import "github.com/KKloudTarus/synapse-ce/internal/domain/shared"

// Run is one emulation pass over a set of techniques against an engagement's target, with the coverage
// record it produced per technique.
//
// It lives in the domain rather than the usecase because it is the persisted aggregate — the offensive
// half of the purple ledger — and keeping it here lets the infrastructure stores depend on the domain
// instead of on a usecase package (the dependency rule, and it breaks an import cycle the other way).
type Run struct {
	ID           shared.ID
	TenantID     shared.ID
	EngagementID shared.ID
	Target       shared.ID
	Actor        string
	Coverage     []CoverageRecord
}
