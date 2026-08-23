package ports

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TelemetryTransportStore persists the AGENT→CONTROL-PLANE transport sequencing state (A3, #624).
// It is deliberately separate from the columnar TelemetryStore: this store owns delivery identity,
// immutable per-sequence commitments, highest-contiguous ACK state, explicit delivery gaps, and
// first-class agent-origin loss reports from the durable spool. Asset binding is part of the compile-time
// contract because ingest must resolve the server-authoritative asset before accepting a delivery.
type TelemetryTransportStore interface {
	TelemetryDeliveryGapReader
	TelemetryAgentGapStore
	TelemetryAssetBindingStore
	StreamState(ctx context.Context, agentID, streamID shared.ID, epoch uint64) (TelemetryStreamState, error)
	SaveStreamState(ctx context.Context, state TelemetryStreamState) error
	MaxEpoch(ctx context.Context, agentID, streamID shared.ID) (uint64, error)
	ListGaps(ctx context.Context, agentID, streamID shared.ID) ([]TelemetryGap, error)
	CommitBatch(ctx context.Context, batch TelemetryEventBatch) error
	IngestBatchEvents(ctx context.Context, batch TelemetryEventBatch) (int, error)
	CountBatchEvents(ctx context.Context, agentID, streamID shared.ID, epoch, sequence uint64) (int, error)
}

// TelemetryDeliveryGapReader is the narrow coverage-honesty view consumed by retro-hunt. The filter is
// tenant-scoped from ctx and windows gaps by observed-time OVERLAP, not by detection wall-clock. It
// includes both open delivery holes and durable agent-origin loss records.
type TelemetryDeliveryGapReader interface {
	QueryDeliveryGaps(ctx context.Context, q TelemetryGapQuery) ([]TelemetryGap, error)
}

type TelemetryGapQuery struct {
	AgentID  shared.ID
	AssetID  shared.ID
	Priority *fleetagent.DeliveryPriority
	Since    time.Time
	Until    time.Time
}

type TelemetryEventBatch struct {
	BatchID       shared.ID
	PayloadDigest string
	AgentID       shared.ID
	StreamID      shared.ID
	AssetID       shared.ID
	Epoch         uint64
	Sequence      uint64
	SchemaVersion int
	Events        []StoredTelemetryEvent
}

type StoredTelemetryEvent struct {
	EventID    shared.ID
	Class      detection.Class
	Digest     string
	Payload    []byte
	ObservedAt time.Time
}

func (b TelemetryEventBatch) Validate() error {
	if b.BatchID.IsZero() || b.PayloadDigest == "" {
		return fmt.Errorf("%w: telemetry event batch needs batch id and payload digest", shared.ErrValidation)
	}
	if b.AgentID.IsZero() || b.StreamID.IsZero() || b.AssetID.IsZero() {
		return fmt.Errorf("%w: telemetry event batch needs agent, stream and asset ids", shared.ErrValidation)
	}
	if b.Epoch == 0 || b.Sequence == 0 {
		return fmt.Errorf("%w: telemetry event batch needs a non-zero epoch and sequence", shared.ErrValidation)
	}
	if b.SchemaVersion < 1 {
		return fmt.Errorf("%w: telemetry event batch schema version must be >= 1", shared.ErrValidation)
	}
	if len(b.Events) == 0 {
		return fmt.Errorf("%w: telemetry event batch needs at least one event", shared.ErrValidation)
	}
	for i, e := range b.Events {
		if e.EventID.IsZero() {
			return fmt.Errorf("%w: telemetry event[%d] has no id", shared.ErrValidation, i)
		}
		if !e.Class.Valid() {
			return fmt.Errorf("%w: telemetry event[%d] has an unknown class %q", shared.ErrValidation, i, e.Class)
		}
		if e.Digest == "" {
			return fmt.Errorf("%w: telemetry event[%d] has no digest", shared.ErrValidation, i)
		}
		if len(e.Payload) == 0 {
			return fmt.Errorf("%w: telemetry event[%d] has no payload", shared.ErrValidation, i)
		}
		if e.ObservedAt.IsZero() {
			return fmt.Errorf("%w: telemetry event[%d] has no observed-at", shared.ErrValidation, i)
		}
	}
	return nil
}

type TelemetryStreamState struct {
	AgentID    shared.ID
	StreamID   shared.ID
	Epoch      uint64
	Contiguous uint64
	Pending    []uint64
	Version    uint64
	UpdatedAt  time.Time
}

func (s TelemetryStreamState) Validate() error {
	if s.AgentID.IsZero() {
		return fmt.Errorf("%w: telemetry stream state has no agent id", shared.ErrValidation)
	}
	if s.StreamID.IsZero() {
		return fmt.Errorf("%w: telemetry stream state has no stream id", shared.ErrValidation)
	}
	if s.Epoch == 0 {
		return fmt.Errorf("%w: telemetry stream state epoch must be >= 1", shared.ErrValidation)
	}
	for _, seq := range s.Pending {
		if seq <= s.Contiguous {
			return fmt.Errorf("%w: pending sequence %d is not above the contiguous mark %d", shared.ErrValidation, seq, s.Contiguous)
		}
	}
	return nil
}

// TelemetryGap is a coverage window surfaced to retro-hunt. For inferred delivery holes it carries
// FromSequence..ToSequence; for unknown-coordinate agent-origin loss these sequence fields remain zero.
type TelemetryGap struct {
	AgentID      shared.ID
	AssetID      shared.ID
	StreamID     shared.ID
	Priority     fleetagent.DeliveryPriority
	Epoch        uint64
	FromSequence uint64
	ToSequence   uint64
	FromAt       time.Time
	ToAt         time.Time
	DetectedAt   time.Time
}

func (s TelemetryStreamState) LoadAckLedger() *fleetagent.AckLedger {
	ledger := fleetagent.NewAckLedger()
	ledger.SeedContiguous(s.Contiguous)
	for _, seq := range s.Pending {
		ledger.Observe(seq)
	}
	return ledger
}

func (s TelemetryStreamState) GapsFrom() []TelemetryGap {
	ledger := s.LoadAckLedger()
	var gaps []TelemetryGap
	for _, g := range ledger.Gaps() {
		gaps = append(gaps, TelemetryGap{
			AgentID:      s.AgentID,
			StreamID:     s.StreamID,
			Epoch:        s.Epoch,
			FromSequence: g.From,
			ToSequence:   g.To,
		})
	}
	return gaps
}
