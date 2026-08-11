package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
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
	// Ingest persists one batch of raw events. It is the store write only; boundedness/backpressure and
	// gap reporting are the telemetry usecase's job. Idempotent on (host, class, sequence, event index).
	Ingest(ctx context.Context, batch TelemetryBatch) error
	// Query runs a retro-hunt. The three acceptance patterns (retro-run a rule over the hot window,
	// reconstruct context around a detection, pivot an asset to its raw events) are HuntQuery.Kind values.
	Query(ctx context.Context, q HuntQuery) (HuntResult, error)
	// RetentionSweep enforces the tier boundaries as of now: it down-samples the warm window and expires
	// past-warm data, returning what it did so the caller can audit the expiry. Tenant-scoped.
	RetentionSweep(ctx context.Context, now time.Time) (SweepReport, error)
	// Footprint reports the store's size (rows + bytes) so an operator can predict spend (#424 req 8).
	Footprint(ctx context.Context) (TelemetryFootprint, error)
	// LastSequence returns the highest batch sequence stored for a (host, class), 0 if none — so the
	// telemetry usecase can detect a sequence gap and surface a lossy window.
	LastSequence(ctx context.Context, hostID shared.ID, class detection.Class) (uint64, error)
}

// TelemetryBatch is one sequenced, sampled batch of raw events from an agent for a single event class.
type TelemetryBatch struct {
	TenantID shared.ID
	HostID   shared.ID
	AssetID  shared.ID
	AgentID  shared.ID
	Class    detection.Class
	Sequence uint64
	// SampleRate records how the batch was sampled: 1 = full fidelity; N>1 = one event kept per N observed
	// (recorded WITH the data so a hunt knows it is looking at a sample, never a complete window).
	SampleRate int
	Events     []detection.Event
}

// HuntKind is a retro-hunt pattern. These three are the acceptance surface for the store choice (#424).
type HuntKind string

const (
	HuntRetroRule  HuntKind = "retro_rule"  // re-run a detection rule over the hot window
	HuntContext    HuntKind = "context"     // reconstruct the events around an existing detection
	HuntAssetPivot HuntKind = "asset_pivot" // pivot from an asset to its raw events
)

// HuntQuery selects a window of telemetry to hunt over. There is no tenant field: the tenant is bound
// from the authenticated context at the store (the chokepoint), never chosen by the caller. Kind labels
// the retro-hunt pattern for the reader; the actual selection is the populated fields (host/asset/class/
// time window).
type HuntQuery struct {
	Kind    HuntKind
	HostID  shared.ID
	AssetID shared.ID
	Class   detection.Class // empty = all classes
	Since   time.Time
	Until   time.Time
	Limit   int
}

// HuntResult carries the events a hunt matched plus the HONESTY metadata a hunt must not ignore: whether
// the window was sampled (and at what rate), whether it is complete, and any sequence gaps intersecting
// it — so a sampled or lossy window is never presented as the whole truth.
type HuntResult struct {
	Events        []detection.Event
	RowsScanned   int
	Sampled       bool
	MaxSampleRate int // the worst (largest) sample rate in the window; 1 = fully sampled
	Complete      bool
	SequenceGaps  []TelemetrySequenceGap
}

// TelemetrySequenceGap is a missing run of batch sequences for a (host, class), making a window lossy.
type TelemetrySequenceGap struct {
	HostID   shared.ID
	Class    detection.Class
	Missing  uint64
	LastSeen uint64
	Incoming uint64
}

// SweepReport is what a retention sweep did, for the audit trail.
type SweepReport struct {
	At              time.Time
	WarmDownsampled int64 // rows moved from hot to warm (reduced resolution)
	Expired         int64 // rows past the warm window, deleted
}

// TelemetryFootprint is the measured store size, so spend is observable rather than discovered.
type TelemetryFootprint struct {
	Rows  int64
	Bytes int64
}
