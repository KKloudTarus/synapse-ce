package ports

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
)

// TelemetryStore is the DEDICATED persistence port for the columnar telemetry tier (#424, ADR 0001). It
// is deliberately separate from the system-of-record ports: the columnar store is NEVER in the path of a
// finding, a judgment, or the evidence chain, and it appears in no domain type (an architecture test
// asserts this). The CE milestone implements it over a time-partitioned Postgres table; ClickHouse is the
// documented fleet-scale implementation that drops into the same port with no domain change.
//
// Telemetry is NOT hash-chained per event (the #405 decision); batches stay sequence-numbered so a hunt
// can tell a complete sequence from a lossy one.
type TelemetryStore interface {
	Ingest(ctx context.Context, batch TelemetryBatch) error
	Query(ctx context.Context, q HuntQuery) (HuntResult, error)
	RetentionSweep(ctx context.Context, now time.Time) (SweepReport, error)
	Footprint(ctx context.Context) (TelemetryFootprint, error)
	LastSequence(ctx context.Context, hostID shared.ID, class detection.Class) (uint64, error)
	RecordLoss(ctx context.Context, loss TelemetryLoss) error
}

// TelemetryLoss is a first-class, persisted record that a batch was cut (Truncated) or observed-then-lost
// (Dropped) at the store-rate stage. Agent-side SAMPLING is not a TelemetryLoss — it rides SampleRate on
// the stored rows (surfaced as HuntResult.Sampled); this type captures the losses D2 used to hide.
type TelemetryLoss struct {
	HostID        shared.ID
	AssetID       shared.ID
	Class         detection.Class
	Sequence      uint64
	Disposition   telemetry.LossDisposition
	ObservedCount int
	KeptCount     int
	DroppedCount  int
	Reason        string
	FromAt        time.Time
	ToAt          time.Time
}

func (l TelemetryLoss) Validate() error {
	if l.HostID == "" {
		return fmt.Errorf("%w: telemetry loss has no host", shared.ErrValidation)
	}
	if l.AssetID == "" {
		return fmt.Errorf("%w: telemetry loss has no asset", shared.ErrValidation)
	}
	if !l.Class.Valid() {
		return fmt.Errorf("%w: telemetry loss has an unknown class %q", shared.ErrValidation, l.Class)
	}
	if l.Sequence == 0 {
		return fmt.Errorf("%w: telemetry loss sequence must be >= 1", shared.ErrValidation)
	}
	if l.Disposition != telemetry.Truncated && l.Disposition != telemetry.Dropped {
		return fmt.Errorf("%w: telemetry loss disposition must be truncated or dropped, got %q", shared.ErrValidation, l.Disposition)
	}
	if err := telemetry.ValidateLossCounts(l.Disposition, l.ObservedCount, l.KeptCount, l.DroppedCount); err != nil {
		return err
	}
	if l.Reason == "" {
		return fmt.Errorf("%w: telemetry loss must carry a reason", shared.ErrValidation)
	}
	if l.FromAt.IsZero() || l.ToAt.IsZero() || l.ToAt.Before(l.FromAt) {
		return fmt.Errorf("%w: telemetry loss must carry a valid observed-time span (from <= to)", shared.ErrValidation)
	}
	return nil
}

// TelemetryBatch is one sequenced, sampled batch of raw events from an agent for a single event class.
type TelemetryBatch struct {
	TenantID      shared.ID
	HostID        shared.ID
	AssetID       shared.ID
	AgentID       shared.ID
	SchemaVersion int
	Class         detection.Class
	Sequence      uint64
	SampleRate    int
	Events        []detection.Event
}

type HuntKind string

const (
	HuntRetroRule  HuntKind = "retro_rule"
	HuntContext    HuntKind = "context"
	HuntAssetPivot HuntKind = "asset_pivot"
)

type HuntQuery struct {
	Kind    HuntKind
	HostID  shared.ID
	AssetID shared.ID
	Class   detection.Class
	Since   time.Time
	Until   time.Time
	Limit   int
}

// HuntResult carries every source of coverage uncertainty. SequenceGaps/Losses come
// from the columnar tier; DeliveryGaps come from the durable A3 ACK/gap ledger. A
// consumer must treat any non-empty gap/loss set as incomplete coverage.
type HuntResult struct {
	Events        []detection.Event
	RowsScanned   int
	Sampled       bool
	MaxSampleRate int
	Complete      bool
	SequenceGaps  []TelemetrySequenceGap
	DeliveryGaps  []TelemetryGap
	Losses        []TelemetryLoss
}

type TelemetrySequenceGap struct {
	HostID   shared.ID
	Class    detection.Class
	Missing  uint64
	LastSeen uint64
	Incoming uint64
}

type SweepReport struct {
	At              time.Time
	WarmDownsampled int64
	Expired         int64
}

type TelemetryFootprint struct {
	Rows  int64
	Bytes int64
}
