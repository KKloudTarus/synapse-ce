package ports

import (
	"context"
	"errors"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
)

// SensorStateDeliveryStateVersion is the on-disk schema version of the agent's
// sensor-state delivery journal. A journal written by a newer agent is refused
// rather than silently reinterpreted.
const SensorStateDeliveryStateVersion = 1

// SensorStateJournal is the durable at-most-one-in-flight record for signed
// sensor-state delivery. It lets an agent resume the exact report it was shipping
// when it stopped, instead of re-signing a fresh one and losing the original's
// identity. Implementations must replace the journal atomically so a crash mid-write
// cannot leave a torn state.
type SensorStateJournal interface {
	Load(context.Context) (SensorStateDeliveryState, error)
	Save(context.Context, SensorStateDeliveryState) error
}

// SensorStateDeliveryState is the whole journal: a version plus at most one pending
// report. At most one report is in flight at a time, so the WAL cannot be acked past
// evidence that never reached the control plane.
type SensorStateDeliveryState struct {
	Version int                       `json:"version"`
	Pending *PendingSensorStateReport `json:"pending,omitempty"`
}

// PendingSensorStateReport is one signed report mid-delivery, with the WAL coordinate
// it covers. Acked records that the control plane accepted it, so a resumed agent
// finalizes the WAL rather than shipping the report twice.
type PendingSensorStateReport struct {
	Epoch      uint64                       `json:"epoch"`
	WALThrough uint64                       `json:"wal_through"`
	Acked      bool                         `json:"acked"`
	Report     fleetagent.SensorStateReport `json:"report"`
}

// Validate rejects a journal this build cannot honor: an unknown version, or a
// pending entry whose WAL coordinates or signed report are not well formed. A
// half-understood journal would let an agent ack a WAL range it never delivered.
func (s SensorStateDeliveryState) Validate() error {
	if s.Version != SensorStateDeliveryStateVersion {
		return fmt.Errorf("unsupported sensor-state delivery state version %d", s.Version)
	}
	if s.Pending == nil {
		return nil
	}
	if s.Pending.Epoch == 0 || s.Pending.WALThrough == 0 {
		return errors.New("pending sensor-state WAL coordinates are invalid")
	}
	if err := s.Pending.Report.Validate(); err != nil {
		return fmt.Errorf("pending sensor-state report: %w", err)
	}
	return nil
}
