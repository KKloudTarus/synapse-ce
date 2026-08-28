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

var ErrTelemetrySpoolSaturated = errors.New("telemetry spool saturated")

type SpoolRecordKind string

const (
	SpoolRecordTelemetry            SpoolRecordKind = "telemetry"
	SpoolRecordDetection            SpoolRecordKind = "detection"
	SpoolRecordCoverage             SpoolRecordKind = "coverage"
	SpoolRecordSensorState          SpoolRecordKind = "sensor_state"
	SpoolRecordResponseVerification SpoolRecordKind = "response_verification"
)

func (k SpoolRecordKind) Valid() bool {
	switch k {
	case SpoolRecordTelemetry, SpoolRecordDetection, SpoolRecordCoverage,
		SpoolRecordSensorState, SpoolRecordResponseVerification:
		return true
	default:
		return false
	}
}

// MustNotShedRecord is the single classification rule for durable spool records.
// P0 health and response evidence are never shed; raw telemetry follows its
// event-class policy; detections retain the existing P1 must-not-shed semantics.
func MustNotShedRecord(kind SpoolRecordKind, eventClass detection.Class) (bool, error) {
	switch kind {
	case SpoolRecordTelemetry:
		if !eventClass.Valid() {
			return false, fmt.Errorf("%w: telemetry spool item has invalid class %q", shared.ErrValidation, eventClass)
		}
		return telemetry.MustNotShed(eventClass), nil
	case SpoolRecordDetection, SpoolRecordCoverage, SpoolRecordSensorState, SpoolRecordResponseVerification:
		return true, nil
	default:
		return false, fmt.Errorf("%w: unknown spool record kind %q", shared.ErrValidation, kind)
	}
}

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
	wantMustNotShed, err := MustNotShedRecord(i.Kind, i.EventClass)
	if err != nil {
		return err
	}
	if i.MustNotShed != wantMustNotShed {
		return fmt.Errorf("%w: %s spool item must-not-shed=%t, got %t", shared.ErrValidation,
			i.Kind, wantMustNotShed, i.MustNotShed)
	}
	if i.Priority != fleetagent.PriorityP3 && !i.MustNotShed {
		return fmt.Errorf("%w: %s spool item must be marked must-not-shed", shared.ErrValidation, i.Priority)
	}
	if i.MustNotShed && i.Priority == fleetagent.PriorityP3 {
		return fmt.Errorf("%w: must-not-shed item cannot use the evictable P3 lane", shared.ErrValidation)
	}
	return nil
}

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

type PeekSpoolRequest struct {
	MaxRecords int
	MaxBytes   int64
	// OnlyPriority restricts the read to one delivery lane. A nil value preserves the normal P0→P3
	// drain order. Dedicated transports use this to ensure a busy coverage or telemetry lane cannot
	// consume the read budget and starve the independent detection queue.
	OnlyPriority *fleetagent.DeliveryPriority
}

type SpoolACK struct {
	Priority fleetagent.DeliveryPriority
	Epoch    uint64
	Through  uint64
}

func (a SpoolACK) Validate() error {
	if !a.Priority.Valid() {
		return fmt.Errorf("%w: unknown ACK priority %d", shared.ErrValidation, int(a.Priority))
	}
	if a.Epoch == 0 || a.Through == 0 {
		return fmt.Errorf("%w: ACK epoch and through sequence must be positive", shared.ErrValidation)
	}
	return nil
}

type SpoolACKResult struct {
	RemovedRecords int
	ReclaimedBytes int64
	HighestACKed   uint64
}

type SpoolGapReason string

const (
	SpoolGapQuotaEviction     SpoolGapReason = "quota_eviction"
	SpoolGapQuotaBackpressure SpoolGapReason = "quota_backpressure"
	SpoolGapCorruptFrame      SpoolGapReason = "corrupt_frame"
	SpoolGapTornWrite         SpoolGapReason = "torn_write"
	SpoolGapIOFailure         SpoolGapReason = "io_failure"
	SpoolGapUnsyncedTail      SpoolGapReason = "unsynced_tail"
	SpoolGapStateRecovery     SpoolGapReason = "state_recovery"
)

func (r SpoolGapReason) Valid() bool {
	switch r {
	case SpoolGapQuotaEviction, SpoolGapQuotaBackpressure, SpoolGapCorruptFrame, SpoolGapTornWrite,
		SpoolGapIOFailure, SpoolGapUnsyncedTail, SpoolGapStateRecovery:
		return true
	default:
		return false
	}
}

// SpoolGap is the durable local loss object A3 must transport. FromAt/ToAt were
// added after the original journal format; legacy records with both fields zero use
// OccurredAt as a point span so old journals remain readable. New writers always set
// the full span and coalescing extends ToAt, preventing a long loss interval from
// collapsing to one timestamp in retro-hunt coverage.
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
	FromAt        time.Time `json:",omitempty"`
	ToAt          time.Time `json:",omitempty"`
}

// TimeBounds returns the normalized observed/loss interval. Legacy gaps that predate
// FromAt/ToAt fall back to OccurredAt for backward-compatible journal recovery.
func (g SpoolGap) TimeBounds() (time.Time, time.Time) {
	if g.FromAt.IsZero() && g.ToAt.IsZero() {
		at := g.OccurredAt.UTC()
		return at, at
	}
	return g.FromAt.UTC(), g.ToAt.UTC()
}

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
	if (g.FromAt.IsZero()) != (g.ToAt.IsZero()) {
		return fmt.Errorf("%w: spool gap time bounds must be both set or both unset", shared.ErrValidation)
	}
	fromAt, toAt := g.TimeBounds()
	if fromAt.IsZero() || toAt.IsZero() || toAt.Before(fromAt) {
		return fmt.Errorf("%w: spool gap has invalid time bounds", shared.ErrValidation)
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

// SameSnapshot compares the exact reportable state of one durable gap. It deliberately
// ignores time.Time's internal monotonic/location representation and compares instants.
// AckGap uses this to avoid deleting a gap that grew while its older snapshot was in flight.
func (g SpoolGap) SameSnapshot(other SpoolGap) bool {
	if g.ID != other.ID || g.Priority != other.Priority || g.Epoch != other.Epoch ||
		g.FromSequence != other.FromSequence || g.ToSequence != other.ToSequence ||
		g.KnownSequence != other.KnownSequence || g.Reason != other.Reason || g.Count != other.Count ||
		!g.OccurredAt.Equal(other.OccurredAt) {
		return false
	}
	gf, gt := g.TimeBounds()
	of, ot := other.TimeBounds()
	return gf.Equal(of) && gt.Equal(ot)
}

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

type SpoolStats struct {
	Priorities       []SpoolPriorityStats
	EpochACKs        []SpoolEpochACK
	TotalRecords     int64
	TotalBytes       int64
	GapRecords       int64
	GapBytes         int64
	EvictedRecords   uint64
	CorruptionEvents uint64
	FsyncCount       uint64
	FsyncTotal       time.Duration
}

type TelemetrySpool interface {
	Enqueue(ctx context.Context, item SpoolItem) (fleetagent.StreamPosition, error)
	Peek(ctx context.Context, req PeekSpoolRequest) ([]SpoolRecord, error)
	Ack(ctx context.Context, ack SpoolACK) (SpoolACKResult, error)
	Flush(ctx context.Context) error
	Gaps(ctx context.Context) ([]SpoolGap, error)
	// AckGap removes a local gap only if the current durable object still exactly
	// matches the snapshot that the server acknowledged. false,nil means the gap
	// changed (usually coalesced more loss) while the report was in flight and must
	// be sent again; an already-absent gap is an idempotent true,nil.
	AckGap(ctx context.Context, reported SpoolGap) (bool, error)
	Stats(ctx context.Context) (SpoolStats, error)
	Close() error
}
