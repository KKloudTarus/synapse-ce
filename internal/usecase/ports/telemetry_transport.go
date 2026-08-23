package ports

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TelemetryTransportStore persists the AGENT→CONTROL-PLANE transport sequencing state (A3, #624), kept
// deliberately separate from the columnar TelemetryStore. It owns delivery identity, immutable
// per-sequence commitments, highest-contiguous ACK state, explicit coverage gaps, first-class agent-origin
// spool-loss reports, and the server-authoritative host-asset binding. Every operation is tenant-scoped
// from ctx; ingest keys it by the AUTHENTICATED agent identity, never by an agent-chosen wire field.
type TelemetryTransportStore interface {
	TelemetryDeliveryGapReader
	TelemetryAgentGapStore
	TelemetryAssetBindingStore
	// StreamState returns the persisted delivery state for (agentID, streamID, epoch): the highest-contiguous
	// acknowledged sequence, received-but-not-yet-contiguous sequences, and optimistic-concurrency version.
	// A stream/epoch never seen returns a zero state (Contiguous=0, Version=0), not an error.
	StreamState(ctx context.Context, agentID, streamID shared.ID, epoch uint64) (TelemetryStreamState, error)
	// SaveStreamState persists the recomputed delivery state under optimistic concurrency, so concurrent
	// batches for one stream cannot lose-update the ACK. The use case computes the state from AckLedger.
	SaveStreamState(ctx context.Context, state TelemetryStreamState) error
	// MaxEpoch returns the highest epoch seen for (agent, stream), or zero when none exists, so ingest can
	// reject a stale incarnation after the stream has advanced.
	MaxEpoch(ctx context.Context, agentID, streamID shared.ID) (uint64, error)
	// ListGaps returns the currently open inferred transport gaps for (agent, stream). Persisted gap history
	// is reconciled against ACK state so a filled range no longer appears open.
	ListGaps(ctx context.Context, agentID, streamID shared.ID) ([]TelemetryGap, error)
	// CommitBatch durably commits one immutable batch coordinate before ACK state advances. Reusing a
	// coordinate with different batch identity/content conflicts; an identical retry is idempotent.
	CommitBatch(ctx context.Context, batch TelemetryEventBatch) error
	// IngestBatchEvents persists verified raw telemetry bytes idempotently by incarnation-aware delivery
	// coordinate plus event id, returning the number of newly stored events.
	IngestBatchEvents(ctx context.Context, batch TelemetryEventBatch) (int, error)
	// CountBatchEvents reports the number of events durably stored for one batch coordinate; used for
	// idempotency assertions and recovery checks.
	CountBatchEvents(ctx context.Context, agentID, streamID shared.ID, epoch, sequence uint64) (int, error)
}

// TelemetryDeliveryGapReader is the narrow coverage-honesty view consumed by retro-hunt. The filter is
// tenant-scoped from ctx and windows gaps by observed-time OVERLAP, not by detection wall-clock. It
// includes both open delivery holes and durable agent-origin loss records.
type TelemetryDeliveryGapReader interface {
	QueryDeliveryGaps(ctx context.Context, q TelemetryGapQuery) ([]TelemetryGap, error)
}

// TelemetryGapQuery filters transport coverage gaps. Empty agent/asset and nil priority are wildcards;
// Since/Until use overlap semantics against the source-observed gap span.
type TelemetryGapQuery struct {
	AgentID  shared.ID
	AssetID  shared.ID
	Priority *fleetagent.DeliveryPriority
	Since    time.Time
	Until    time.Time
}

// TelemetryEventBatch is one accepted batch's raw events to persist durably, already verified against the
// signed manifest (authenticated identity, key, schema, per-event digest, and immutable batch commitment)
// by the ingest use case.
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

// StoredTelemetryEvent is one raw telemetry event persisted by the transport store: its stable id, class,
// content digest (matched against the signed manifest), opaque shipped bytes, and source-observed time.
type StoredTelemetryEvent struct {
	EventID    shared.ID
	Class      detection.Class
	Digest     string
	Payload    []byte
	ObservedAt time.Time
}

// Validate checks that the immutable batch commitment and every stored event are well formed.
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

// TelemetryStreamState is the durable AckLedger snapshot for one (AgentID, StreamID, Epoch): Contiguous
// is the highest sequence with no hole beneath it, Pending are received sequences above that mark waiting
// for predecessors, and Version is the optimistic-concurrency token used by SaveStreamState.
type TelemetryStreamState struct {
	AgentID    shared.ID
	StreamID   shared.ID
	Epoch      uint64
	Contiguous uint64
	// Pending are received sequences strictly above Contiguous whose predecessors have not all arrived;
	// the ingest forward-gap cap bounds this set.
	Pending   []uint64
	Version   uint64
	UpdatedAt time.Time
}

// Validate checks that the stream identity is real and that no pending sequence contradicts Contiguous.
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

// TelemetryGap is a coverage window surfaced to retro-hunt. Inferred delivery holes carry the missing
// transport-batch FromSequence..ToSequence coordinates; unknown-coordinate agent-origin loss keeps those
// fields zero. FromAt..ToAt is source-observed time, not control-plane receipt time.
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

// LoadAckLedger rehydrates the persisted snapshot without observing every sequence below Contiguous.
func (s TelemetryStreamState) LoadAckLedger() *fleetagent.AckLedger {
	ledger := fleetagent.NewAckLedger()
	ledger.SeedContiguous(s.Contiguous)
	for _, seq := range s.Pending {
		ledger.Observe(seq)
	}
	return ledger
}

// GapsFrom derives the open missing transport-batch ranges from the ACK snapshot.
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
