// Package telemetryschema owns the wire-format version of telemetry events and batches (A0.3, epic #594).
//
// The schema version is versioned INDEPENDENTLY of the agent binary version: a fleet of mixed agent
// builds may all ship the same schema, and one agent build may emit an evolving schema across releases.
// Ingest keys on THIS version, never on the agent version — so the wire contract can evolve without a
// lockstep fleet upgrade, and upgrading the agent binary does not silently change how its data is read.
//
// Compatibility rules:
//   - Current is the schema this build emits.
//   - [MinSupported, MaxSupported] is the range a reader accepts. Within the range a reader tolerates
//     additive fields (a newer minor schema stays readable by an older reader; unknown fields are ignored).
//   - A version outside the range — or an unset/non-positive version — is REJECTED explicitly by the
//     ingest gate, never parsed under a guessed shape. The range widens (MaxSupported bumps) only when a
//     new schema version is actually defined; today only v1 exists.
package telemetryschema

import (
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	// Current is the telemetry schema version this build emits. Bump it when the wire shape changes; it
	// is deliberately NOT derived from the agent binary version.
	Current = 1
	// MinSupported and MaxSupported bound the versions the ingest reader accepts, inclusive.
	MinSupported = 1
	MaxSupported = 1
)

// Supported reports whether v is within the accepted [MinSupported, MaxSupported] range.
func Supported(v int) bool { return v >= MinSupported && v <= MaxSupported }

// Validate returns nil when v is an accepted schema version, and a wrapped shared.ErrValidation otherwise
// so the ingest gate fails closed: a batch that declares no version (0), an impossible version (< 0), or
// a version outside the supported range is rejected rather than parsed under a guessed shape.
func Validate(v int) error {
	if v < MinSupported {
		return fmt.Errorf("%w: telemetry schema version must be >= %d (0/unset is not allowed), got %d", shared.ErrValidation, MinSupported, v)
	}
	if v > MaxSupported {
		return fmt.Errorf("%w: telemetry schema version %d is newer than this reader supports (max %d); upgrade the control plane", shared.ErrValidation, v, MaxSupported)
	}
	return nil
}
