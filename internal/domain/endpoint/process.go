package endpoint

import (
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
)

// ProcessState is the lifecycle state of a projected process entity.
type ProcessState string

const (
	// ProcessRunning is the state of a process observed to start (fork/exec) and not yet observed to exit.
	ProcessRunning ProcessState = "running"
	// ProcessExited is set once an exit is observed. A1's ProcessObservation carries only exec/fork today,
	// so this state is reserved for the sensor-side exit-event tail; the projection already models it so
	// that leg is a data change, not a schema change.
	ProcessExited ProcessState = "exited"
	// ProcessUnknown is a process referenced only as a parent (by ParentEntityID) that was never itself
	// observed — its lineage link is real but its own start was missed (a coverage gap, not a guess).
	ProcessUnknown ProcessState = "unknown"
)

// ProcessEntity is a stable, PID-reuse-proof process reconstructed from process telemetry (B1). Its
// identity is the A1 ProcessEntityID (hash of asset+boot+pid+start-time), so two processes that reused one
// PID are distinct entities and a reader can build a process tree via ParentEntityID without racing the
// kernel's PID recycling.
type ProcessEntity struct {
	EntityID       shared.ID
	TenantID       shared.ID
	AssetID        shared.ID
	PID            int
	PPID           int
	ParentEntityID shared.ID
	Comm           string
	Path           string
	Args           []string
	ArgsTruncated  bool
	PathTruncated  bool
	UID            int
	Resource       telemetry.ResourceContext
	// StartedAt is the EARLIEST event time (OccurredAt) observed for this entity — a min, so it is
	// independent of the order envelopes are folded in. Zero on an unobserved parent stub.
	StartedAt time.Time
	// LastSeenAt is the latest event time (OccurredAt) of any observation naming this entity — a max, so
	// it too is order-independent. Zero on an unobserved parent stub (never directly seen).
	LastSeenAt time.Time
	// ExitedAt is set only when an exit is observed (reserved tail); nil while running.
	ExitedAt *time.Time
	State    ProcessState
	// descEventID is the EventID of the observation that last set the descriptor fields. It is the
	// tiebreak that keeps the descriptor resolution reorder-invariant when two observations of this entity
	// share an OccurredAt; unexported so it is internal bookkeeping, not part of the public projection.
	descEventID shared.ID
}

// IsRunning reports whether the process is currently believed to be alive.
func (p ProcessEntity) IsRunning() bool { return p.State == ProcessRunning }

// Validate enforces a well-formed process entity.
func (p ProcessEntity) Validate() error {
	if p.EntityID.IsZero() {
		return fmt.Errorf("%w: process entity has no entity id", shared.ErrValidation)
	}
	if p.AssetID.IsZero() {
		return fmt.Errorf("%w: process entity has no asset id", shared.ErrValidation)
	}
	switch p.State {
	case ProcessRunning, ProcessExited, ProcessUnknown:
	default:
		return fmt.Errorf("%w: process entity has unknown state %q", shared.ErrValidation, p.State)
	}
	if p.ExitedAt != nil && p.State != ProcessExited {
		return fmt.Errorf("%w: process entity has an exit time but state %q", shared.ErrValidation, p.State)
	}
	return nil
}

func (p ProcessEntity) clone() ProcessEntity {
	c := p
	c.Args = append([]string(nil), p.Args...)
	if p.ExitedAt != nil {
		t := *p.ExitedAt
		c.ExitedAt = &t
	}
	return c
}
