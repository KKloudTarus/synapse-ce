package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sensorstate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// SensorStateStore retains signed sensor facts as append-only history. Insert is
// idempotent only for an identical report ID; different content is equivocation.
type SensorStateStore interface {
	AppendSensorState(ctx context.Context, observation sensorstate.Observation) error
	ListSensorStates(ctx context.Context, q SensorStateQuery) ([]sensorstate.Observation, error)
}

type SensorStateQuery struct {
	AgentID shared.ID
	AssetID shared.ID
	HostID  shared.ID
	Since   time.Time
	Until   time.Time
	Limit   int
}

func (q SensorStateQuery) Valid() bool {
	return q.Since.IsZero() || q.Until.IsZero() || q.Since.Before(q.Until)
}
