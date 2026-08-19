package telemetry

import (
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ProcessObservation is a raw process exec/fork observation — telemetry's OWN type, distinct from
// detection.ProcessEvent (which is the thin, single-timestamp shape the detection tier matches over). It
// carries the fields D4 was missing: the parent pid, the kernel start time, and stable entity ids for
// both the process and its parent, so a downstream reader can build a process tree without racing PID
// reuse.
type ProcessObservation struct {
	// Kind is "exec" or "fork".
	Kind string
	PID  int
	PPID int
	// StartTimeNanos is the kernel process start time; it pins ProcessEntityID against PID reuse. Zero
	// means the sensor could not read it (the normalizer records QualityMissingStartTime).
	StartTimeNanos uint64
	// EntityID / ParentEntityID are the stable ids the normalizer derives via ProcessEntityID. The domain
	// keeps them on the observation so evidence sealed later cannot be re-derived differently.
	EntityID       shared.ID
	ParentEntityID shared.ID
	Comm           string   // resolved short command name (basename of Path when available)
	Path           string   // resolved executable path
	Args           []string // bounded argv; ArgsTruncated reports when it is a prefix
	ArgsTruncated  bool
	// PathTruncated reports the executable path was cut by the sensor's path buffer (mirrors the honesty
	// signal FileObservation carries; the same fact is also recorded as QualityTruncatedPath on the
	// envelope).
	PathTruncated bool
	UID           int
}

// Validate enforces a well-formed process observation.
func (p ProcessObservation) Validate() error {
	switch p.Kind {
	case "exec", "fork":
	default:
		return fmt.Errorf("%w: process observation has unknown kind %q", shared.ErrValidation, p.Kind)
	}
	if p.PID <= 0 {
		return fmt.Errorf("%w: process observation has non-positive pid %d", shared.ErrValidation, p.PID)
	}
	if p.EntityID.IsZero() {
		return fmt.Errorf("%w: process observation has no entity id", shared.ErrValidation)
	}
	if p.Comm == "" && p.Path == "" {
		return fmt.Errorf("%w: process observation has neither comm nor path", shared.ErrValidation)
	}
	return nil
}

func (p ProcessObservation) clone() *ProcessObservation {
	c := p
	c.Args = append([]string(nil), p.Args...)
	return &c
}
