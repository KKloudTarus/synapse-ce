package ports

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
)

// ErrTelemetrySpoolSaturated is the transport-neutral backpressure signal a
// producer may match without importing a concrete filesystem implementation.
var ErrTelemetrySpoolSaturated = errors.New("telemetry spool saturated")

// SpoolRecordKind identifies the durable lane payload without coupling the WAL to a future wire format.
// Telemetry is produced by A1's canonical normalizer; the other kinds reserve the priority lanes A2 owns
// so detection, coverage, sensor-health, and response verification never need a second competing spool.
type SpoolRecordKind string

const (
	SpoolRecordTelemetry            SpoolRecordKind = "telemetry"
	SpoolRecordDetection            SpoolRecordKind = "detection"
	SpoolRecordCoverage             SpoolRecordKind = "coverage"
	SpoolRecordSensorState          SpoolRecordKind = "sensor_state"
	SpoolRecordResponseVerification SpoolRecordKind = "response_verification"
)

// Valid reports whether k is one of the version-one spool record kinds.
func (k SpoolRecordKind) Valid() bool {
	switch k {
	case SpoolRecordTelemetry, SpoolRecordDetection, SpoolRecordCoverage,
		SpoolRecordSensorState, SpoolRecordResponseVerification:
		return true
	default:
		return false
	}
}

// SpoolItem is an immutable security signal submitted to the durable agent WAL. Payload is the canonical
// uncompressed representation owned by the producer. A2 preserves these exact bytes; A3 may batch and
// compress them for transport without changing the durable commitment input.
type SpoolItem struct {
	Kind          SpoolRecordKind
	Priority      fleetagent.DeliveryPriority
	EventID       shared.ID
	EventClass    detection.Class
	ContentType   string
	Payload       []byte
	ObservedAt    time.Time
	MustNotShed   bool
	SchemaVersion int
}

// Validate enforces bounded-at-the-port semantics that do not depend on a concrete disk implementation.
// Concrete size limits are Config-owned because operators choose the record and quota budgets.
func (i SpoolItem) Validate() error {
	if !i.Kind.Valid() {
		return fmt.Errorf("%w: unknown spool record kind %q", shared.ErrValidation, i.Kind)
	}
	if !i.Priority.Valid() {
		return fmt.Errorf("%w: unknown spool priority %d", shared.ErrValidation, int(i.Priority))
	}
	if i.EventID.IsZero() {
		return fmt.Errorf("%w: spool item has no event id", shared.ErrValidation)
	}
	if i.ContentType == "" {
		return fmt.Errorf("%w: spool item has no content type", shared.ErrValidation)
	}
	if len(i.Payload) == 0 {
		return fmt.Errorf("%w: spool item has an empty payload", shared.ErrValidation)
	}
	if i.ObservedAt.IsZero() {
		return fmt.Errorf("%w: spool item has no observed-at timestamp", shared.ErrValidation)
	}
	if i.SchemaVersion <= 0 {
		return fmt.Errorf("%w: spool item schema version must be positive", shared.ErrValidation)
	}
	if i.Kind == SpoolRecordTelemetry && !i.EventClass.Valid() {
		return fmt.Errorf("%w: telemetry spool item has invalid class %q", shared.ErrValidation, i.EventClass)
	}
	if i.Kind == SpoolRecordTelemetry && i.MustNotShed != telemetry.MustNotShed(i.EventClass) {
		return fmt.Errorf("%w: telemetry class %s must-not-shed=%t, got %t", shared.ErrValidation,
			i.EventClass, telemetry.MustNotShed(i.EventClass), i.MustNotShed)
	}
	// The priority contract makes P0..P2 non-sheddable. P3 is the only eviction lane; allowing a caller
	// to mark a higher-priority item sheddable would turn a producer bug into silent security-data loss.
	if i.Priority != fleetagent.PriorityP3 && !i.MustNotShed {
		return fmt.Errorf("%w: %s spool item must be marked must-not-shed", shared.ErrValidation, i.Priority)
	}
	if i.MustNotShed && i.Priority == fleetagent.PriorityP3 {
		return fmt.Errorf("%w: must-not-shed item cannot use the evictable P3 lane", shared.ErrValidation)
	}
	return nil
}

// SpoolRecord is one recovered, ordered WAL entry. The position is assigned durably by the spool; the
// payload is copied on both ingress and egress so callers cannot mutate queued data through shared memory.
type SpoolRecord struct {
	Kind          SpoolRecordKind
	Position      fleetagent.StreamPosition
	EventID       shared.ID
	EventClass    detection.Class
	ContentType   string
	Payload       []byte
	ObservedAt    time.Time
	EnqueuedAt    time.Time
	MustNotShed   bool
	SchemaVersion int
}

// Validate checks both the delivery coordinate and the record metadata recovered from disk.
func (r SpoolRecord) Validate() error {
	if err := r.Position.Validate(); err != nil {
		return err
	}
	return SpoolItem{
		Kind: r.Kind, Priority: r.Position.Priority, EventID: r.EventID, EventClass: r.EventClass,
		ContentType: r.ContentType, Payload: r.Payload, ObservedAt: r.ObservedAt,
		MustNotShed: r.MustNotShed, SchemaVersion: r.SchemaVersion,
	}.Validate()
}

// PeekSpoolRequest bounds one priority-ordered read. Zero MaxRecords/MaxBytes asks the implementation to
// use its safe defaults; a single record may exceed MaxBytes so callers can always make forward progress.
type PeekSpoolRequest struct {
	MaxRecords int
	MaxBytes   int64
	// OnlyPriority restricts the read to one delivery lane. A nil value preserves the normal P0→P3
	// drain order. Dedicated transports use this to ensure a busy coverage or telemetry lane cannot
	// consume the read budget and starve the independent detection queue.
	OnlyPriority *fleetagent.DeliveryPriority
}

// SpoolACK is the highest contiguous record sequence the control plane durably accepted for one priority
// incarnation. Epoch is mandatory: an ACK from before a reboot must never delete a new incarnation's data.
type SpoolACK struct {
	Priority fleetagent.DeliveryPriority
	Epoch    uint64
	Through  uint64
}

// Validate rejects ambiguous or malformed ACK coordinates.
func (a SpoolACK) Validate() error {
	if !a.Priority.Valid() {
		return fmt.Errorf("%w: unknown ACK priority %d", shared.ErrValidation, int(a.Priority))
	}
	if a.Epoch == 0 || a.Through == 0 {
		return fmt.Errorf("%w: ACK epoch and through sequence must be positive", shared.ErrValidation)
	}
	return nil
}

// SpoolACKResult reports the local effect of an idempotent ACK.
type SpoolACKResult struct {
	RemovedRecords int
	ReclaimedBytes int64
	HighestACKed   uint64
}

// SpoolGapReason is why a sequence or physical WAL interval cannot be delivered. These labels are stable
// telemetry for A3/A6; Detail is deliberately not part of the contract because filesystem errors may
// contain sensitive host paths.
type SpoolGapReason string

const (
	SpoolGapQuotaEviction SpoolGapReason = "quota_eviction"
	// SpoolGapQuotaBackpressure records that a non-sheddable producer reached
	// the disk ceiling and was forced to stop/retry instead of silently dropping.
	SpoolGapQuotaBackpressure SpoolGapReason = "quota_backpressure"
	SpoolGapCorruptFrame      SpoolGapReason = "corrupt_frame"
	SpoolGapTornWrite         SpoolGapReason = "torn_write"
	SpoolGapIOFailure         SpoolGapReason = "io_failure"
	SpoolGapUnsyncedTail      SpoolGapReason = "unsynced_tail"
	SpoolGapStateRecovery     SpoolGapReason = "state_recovery"
)

// Valid reports whether r is a defined durable gap reason.
func (r SpoolGapReason) Valid() bool {
	switch r {
	case SpoolGapQuotaEviction, SpoolGapQuotaBackpressure, SpoolGapCorruptFrame, SpoolGapTornWrite,
		SpoolGapIOFailure, SpoolGapUnsyncedTail, SpoolGapStateRecovery:
		return true
	default:
		return false
	}
}

// SpoolGap is the agent-side, durable loss object. KnownSequence=false is reserved for damage so early in
// a frame that even its coordinate could not be trusted; it remains queryable and makes coverage
// incomplete without fabricating a sequence. A3 maps these records to the server's persisted gap model.
type SpoolGap struct {
	ID            shared.ID
	Priority      fleetagent.DeliveryPriority
	Epoch         uint64
	FromSequence  uint64
	ToSequence    uint64
	KnownSequence bool
	Reason        SpoolGapReason
	Count         uint64
	OccurredAt    time.Time
}

// Validate checks an honest gap: exact ranges when known, explicit unknown coordinates otherwise.
func (g SpoolGap) Validate() error {
	if g.ID.IsZero() {
		return fmt.Errorf("%w: spool gap has no id", shared.ErrValidation)
	}
	if !g.Priority.Valid() {
		return fmt.Errorf("%w: spool gap has invalid priority %d", shared.ErrValidation, int(g.Priority))
	}
	if !g.Reason.Valid() {
		return fmt.Errorf("%w: spool gap has invalid reason %q", shared.ErrValidation, g.Reason)
	}
	if g.Epoch == 0 {
		return fmt.Errorf("%w: spool gap has no epoch", shared.ErrValidation)
	}
	if g.OccurredAt.IsZero() {
		return fmt.Errorf("%w: spool gap has no timestamp", shared.ErrValidation)
	}
	if g.Count == 0 {
		return fmt.Errorf("%w: spool gap count must be positive", shared.ErrValidation)
	}
	if g.KnownSequence {
		if g.FromSequence == 0 || g.ToSequence < g.FromSequence {
			return fmt.Errorf("%w: spool gap has invalid sequence range %d..%d", shared.ErrValidation, g.FromSequence, g.ToSequence)
		}
		if want := g.ToSequence - g.FromSequence + 1; g.Count != want {
			return fmt.Errorf("%w: spool gap count %d disagrees with range size %d", shared.ErrValidation, g.Count, want)
		}
	} else if g.FromSequence != 0 || g.ToSequence != 0 {
		return fmt.Errorf("%w: unknown-coordinate spool gap cannot claim a sequence range", shared.ErrValidation)
	}
	return nil
}

// SpoolPriorityStats is a stable snapshot for one delivery lane.
type SpoolPriorityStats struct {
	Priority      fleetagent.DeliveryPriority
	Records       int64
	Bytes         int64
	OldestUnacked time.Time
	CurrentEpoch  uint64
	NextSequence  uint64
	HighestACKed  uint64
}

// SpoolEpochACK preserves the highest durable ACK for one priority incarnation. Historical entries
// let a shipper finish committing local state after a reboot advances CurrentEpoch and reclaimed WAL
// records from the acknowledged epoch are no longer readable.
type SpoolEpochACK struct {
	Priority     fleetagent.DeliveryPriority
	Epoch        uint64
	HighestACKed uint64
}

// SpoolStats is both an operator query and the source for the agent Prometheus collector.
type SpoolStats struct {
	Priorities   []SpoolPriorityStats
	EpochACKs    []SpoolEpochACK
	TotalRecords int64
	// TotalBytes includes WAL records and GapBytes; GapBytes is exposed
	// separately as the loss-evidence subset of the bounded spool quota.
	TotalBytes       int64
	GapRecords       int64
	GapBytes         int64
	EvictedRecords   uint64
	CorruptionEvents uint64
	FsyncCount       uint64
	FsyncTotal       time.Duration
}

// TelemetrySpool is the durable agent-side handoff between observation and transport. Implementations
// must be safe for concurrent producers, preserve priority order, and make every accepted item either
// readable until ACKed or represented by a durable SpoolGap.
type TelemetrySpool interface {
	Enqueue(ctx context.Context, item SpoolItem) (fleetagent.StreamPosition, error)
	Peek(ctx context.Context, req PeekSpoolRequest) ([]SpoolRecord, error)
	Ack(ctx context.Context, ack SpoolACK) (SpoolACKResult, error)
	Flush(ctx context.Context) error
	Gaps(ctx context.Context) ([]SpoolGap, error)
	Stats(ctx context.Context) (SpoolStats, error)
	Close() error
}
