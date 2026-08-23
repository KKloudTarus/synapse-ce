// Package correlation is the pure-domain, deterministic engine that folds runtime detection signals into
// incidents for Phase C of the EDR data plane (#594, C2 #676). It groups related signals by asset +
// entity within an event-time session window into a single incident, emitting the incident.IncidentEvent
// log that C1's Project folds and C7 persists. Correlation is EVENT-TIME, never ingest-order: signals are
// ordered by their OccurredAt (with a stable id tiebreak) before folding, so an out-of-order input yields
// the same incidents. Deduplication (by signal id), a bounded session window, and anti-storm suppression
// keep a flood of repeats from exploding an incident while staying coverage-honest (the suppressed count
// is recorded, never silently dropped).
package correlation

import (
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Signal is one thing to correlate — a runtime detection with the identity, entity, and event time needed
// to group it. ID is the detection id and the dedupe key; EntityID is the process/network/file entity the
// detection concerns (zero for an asset-level detection).
type Signal struct {
	ID         shared.ID
	AssetID    shared.ID
	EntityID   shared.ID
	OccurredAt time.Time
	Severity   shared.Severity
	RuleID     string
	Title      string
}

// Validate enforces a well-formed signal.
func (s Signal) Validate() error {
	if s.ID.IsZero() {
		return fmt.Errorf("%w: correlation signal has no id", shared.ErrValidation)
	}
	if s.AssetID.IsZero() {
		return fmt.Errorf("%w: correlation signal has no asset id", shared.ErrValidation)
	}
	if s.OccurredAt.IsZero() {
		return fmt.Errorf("%w: correlation signal has no occurred-at time", shared.ErrValidation)
	}
	if s.Severity != "" && !s.Severity.Valid() {
		return fmt.Errorf("%w: correlation signal has invalid severity %q", shared.ErrValidation, s.Severity)
	}
	return nil
}

// correlationKey is the grouping key: an incident collects signals for one (asset, entity). An asset-level
// signal (no entity) groups under the asset alone.
type correlationKey struct {
	asset  shared.ID
	entity shared.ID
}

func (s Signal) key() correlationKey { return correlationKey{asset: s.AssetID, entity: s.EntityID} }
