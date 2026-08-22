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
// deliberately separate from the columnar TelemetryStore: it holds per-stream delivery bookkeeping
// (the highest-contiguous ACK snapshot) keyed by the incarnation-aware (AgentID, StreamID, Epoch), which
// the columnar (host, class, sequence) store does not model. It is the durable home for the A0.4 AckLedger.
// Transport gaps are NOT stored: ListGaps derives them from the same snapshot, so the ACK is the single
// source of truth and a filled gap can never linger as a phantom. Every method is keyed by the AUTHENTICATED
// agent id (never an agent-chosen wire field) and tenant-scoped from the ctx.
type TelemetryTransportStore interface {
	// StreamState returns the persisted delivery state for (agentID, streamID, epoch): the highest-contiguous
	// acknowledged sequence, the received-but-not-yet-contiguous sequences, and the optimistic-concurrency
	// version. A stream/epoch never seen returns a zero state (Contiguous=0, Version=0), not an error.
	StreamState(ctx context.Context, agentID, streamID shared.ID, epoch uint64) (TelemetryStreamState, error)
	// SaveStreamState persists the recomputed delivery state under optimistic concurrency: it writes only if
	// the stored version still equals state.Version (else it returns shared.ErrConflict and the caller retries),
	// so two concurrent batches for one (agent, stream, epoch) cannot lose-update the ACK. It is the sole
	// writer of ACK state; the usecase computes it from an AckLedger and writes it back under the ctx tenant.
	SaveStreamState(ctx context.Context, state TelemetryStreamState) error
	// MaxEpoch returns the highest epoch this (agent, stream) has state for (0 if none), so ingest can reject
	// a stale incarnation — a batch addressing an epoch below one the stream has already advanced past.
	MaxEpoch(ctx context.Context, agentID, streamID shared.ID) (uint64, error)
	// ListGaps returns the open transport gaps for (agent, stream), DERIVED from the persisted ACK snapshots
	// (contiguous + pending → AckLedger.Gaps()) across all epochs, so a hunt/coverage query learns the window
	// is lossy from the same source of truth the ACK uses — a filled gap disappears automatically.
	ListGaps(ctx context.Context, agentID, streamID shared.ID) ([]TelemetryGap, error)
	// IngestBatchEvents durably persists the shipped raw telemetry events of one accepted batch, keyed by the
	// incarnation-aware (agentID, streamID, epoch, sequence, eventID). Idempotent: a re-delivered batch stores
	// each event at most once. Returns how many events were newly stored. The bytes are stored opaque +
	// content-addressed by digest; interpretation/columnar-hunt is a later concern.
	IngestBatchEvents(ctx context.Context, batch TelemetryEventBatch) (int, error)
	// CountBatchEvents returns how many events are stored for (agentID, streamID, epoch, sequence) — for tests
	// and idempotency assertions.
	CountBatchEvents(ctx context.Context, agentID, streamID shared.ID, epoch, sequence uint64) (int, error)
}

// TelemetryEventBatch is one accepted batch's raw events to persist durably, already verified against the
// signed manifest (identity, key, schema, per-event digest) by the ingest usecase.
type TelemetryEventBatch struct {
	AgentID       shared.ID
	StreamID      shared.ID
	AssetID       shared.ID
	Epoch         uint64
	Sequence      uint64
	SchemaVersion int
	Events        []StoredTelemetryEvent
}

// StoredTelemetryEvent is one raw telemetry event persisted by the transport store: its stable id, class,
// content digest (matched against the manifest), opaque shipped bytes, and source time.
type StoredTelemetryEvent struct {
	EventID    shared.ID
	Class      detection.Class
	Digest     string
	Payload    []byte
	ObservedAt time.Time
}

// Validate checks the event batch is well-formed and internally consistent.
func (b TelemetryEventBatch) Validate() error {
	if b.AgentID.IsZero() || b.StreamID.IsZero() || b.AssetID.IsZero() {
		return fmt.Errorf("%w: telemetry event batch needs agent, stream and asset ids", shared.ErrValidation)
	}
	if b.Epoch == 0 || b.Sequence == 0 {
		return fmt.Errorf("%w: telemetry event batch needs a non-zero epoch and sequence", shared.ErrValidation)
	}
	if b.SchemaVersion < 1 {
		return fmt.Errorf("%w: telemetry event batch schema version must be >= 1", shared.ErrValidation)
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
	}
	return nil
}

// TelemetryStreamState is the durable AckLedger snapshot for one (AgentID, StreamID, Epoch): the highest
// sequence with no hole beneath it (the ACK returned to the agent so it can delete acked batches), plus the
// received sequences ABOVE the contiguous mark that are waiting for their gap to fill. Rehydrating an
// AckLedger from this state and Observe-ing a new sequence recomputes both fields deterministically. Version
// is the optimistic-concurrency token: read it with the state, write it back unchanged; SaveStreamState
// accepts the write only if the store still holds that version.
type TelemetryStreamState struct {
	AgentID    shared.ID
	StreamID   shared.ID
	Epoch      uint64
	Contiguous uint64
	// Pending are received sequences strictly above Contiguous whose predecessors have not all arrived;
	// bounded by the ingest forward-gap cap. Empty when the stream is fully contiguous.
	Pending   []uint64
	Version   uint64
	UpdatedAt time.Time
}

// Validate checks the state is well-formed: a real agent/stream/epoch and no pending sequence at or below the
// contiguous mark (which would be a contradiction — a contiguous sequence is not pending).
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

// TelemetryGap is a DERIVED transport gap: a run of batch sequences that has not arrived for a stream
// incarnation, computed on read from the ACK snapshot so a hunt over the window learns it is lossy from the
// same source of truth the ACK uses. It is never persisted, so a gap that fills simply stops being returned.
type TelemetryGap struct {
	AgentID      shared.ID
	StreamID     shared.ID
	Epoch        uint64
	FromSequence uint64 // first missing sequence (inclusive)
	ToSequence   uint64 // last missing sequence (inclusive)
}

// LoadAckLedger rehydrates an AckLedger from the persisted state so the usecase can Observe a new
// sequence and recompute (Contiguous, Pending) with the exact A0.4 semantics.
func (s TelemetryStreamState) LoadAckLedger() *fleetagent.AckLedger {
	ledger := fleetagent.NewAckLedger()
	// Seeding: observe every contiguous sequence [1..Contiguous] would be O(n); instead the AckLedger
	// exposes a seed constructor. We reconstruct by observing the pending set on top of a contiguous base.
	ledger.SeedContiguous(s.Contiguous)
	for _, seq := range s.Pending {
		ledger.Observe(seq)
	}
	return ledger
}

// GapsFrom derives the open transport gaps for a stream incarnation from its ACK snapshot, so both the
// store impls and callers compute gaps identically from the single source of truth.
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
