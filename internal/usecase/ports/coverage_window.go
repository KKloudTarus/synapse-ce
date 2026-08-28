package ports

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sensorstate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TelemetryBatchAccounting is the immutable, signed disposition accounting for
// one accepted delivery coordinate. Coverage composition consumes only this
// read model; it does not depend on transport persistence internals.
type TelemetryBatchAccounting struct {
	AgentID              shared.ID
	StreamID             shared.ID
	BatchID              shared.ID
	AssetID              shared.ID
	Priority             fleetagent.DeliveryPriority
	Epoch                uint64
	Sequence             uint64
	ObservedCount        int
	KeptCount            int
	SampledOutCount      int
	TruncatedCount       int
	DroppedCount         int
	SamplingPolicyDigest string
	FromAt               time.Time
	ToAt                 time.Time
}

func (a TelemetryBatchAccounting) Validate() error {
	if a.AgentID.IsZero() || a.StreamID.IsZero() || a.BatchID.IsZero() || a.AssetID.IsZero() ||
		!a.Priority.Valid() || a.Epoch == 0 || a.Sequence == 0 || a.FromAt.IsZero() || a.ToAt.IsZero() || a.ToAt.Before(a.FromAt) {
		return fmt.Errorf("%w: telemetry batch accounting has invalid identity or time span", shared.ErrValidation)
	}
	if a.ObservedCount <= 0 || a.KeptCount < 0 || a.SampledOutCount < 0 || a.TruncatedCount < 0 || a.DroppedCount < 0 ||
		a.ObservedCount != a.KeptCount+a.SampledOutCount+a.DroppedCount || a.TruncatedCount > a.KeptCount || a.SamplingPolicyDigest == "" {
		return fmt.Errorf("%w: telemetry batch accounting has invalid signed disposition counts", shared.ErrValidation)
	}
	return nil
}

// TelemetryBatchAccountingReader exposes immutable signed accounting by
// observed-time overlap using half-open query windows.
type TelemetryBatchAccountingReader interface {
	QueryTelemetryBatchAccounting(ctx context.Context, q TelemetryBatchAccountingQuery) ([]TelemetryBatchAccounting, error)
}

type TelemetryBatchAccountingQuery struct {
	AgentID shared.ID
	AssetID shared.ID
	Since   time.Time
	Until   time.Time
}

func (q TelemetryBatchAccountingQuery) Valid() bool {
	return !q.AgentID.IsZero() && !q.AssetID.IsZero() && !q.Since.IsZero() && !q.Until.IsZero() && q.Since.Before(q.Until)
}

// CoverageSensorStateReader returns the state effective at Since plus every
// observation in [Since,Until), so a composer cannot mistake a mid-window gap
// followed by recovery for complete coverage.
type CoverageSensorStateReader interface {
	ListCoverageSensorStates(ctx context.Context, q CoverageSensorStateQuery) ([]sensorstate.Observation, error)
}

type CoverageSensorStateQuery struct {
	AgentID shared.ID
	AssetID shared.ID
	HostID  shared.ID
	Since   time.Time
	Until   time.Time
}

func (q CoverageSensorStateQuery) Valid() bool {
	return !q.AgentID.IsZero() && !q.AssetID.IsZero() && !q.HostID.IsZero() && !q.Since.IsZero() && !q.Until.IsZero() && q.Since.Before(q.Until)
}

// CoverageGapFact is one immutable coverage-loss source fact. Source and FactID
// keep separately auditable agent-origin and inferred delivery facts distinct in
// the coverage input digest; KnownSequence permits honest unknown-coordinate loss.
type CoverageGapFact struct {
	Source        CoverageGapSource
	FactID        shared.ID
	AgentID       shared.ID
	AssetID       shared.ID
	StreamID      shared.ID
	Priority      fleetagent.DeliveryPriority
	Epoch         uint64
	KnownSequence bool
	FromSequence  uint64
	ToSequence    uint64
	Count         uint64
	Reason        string
	FromAt        time.Time
	ToAt          time.Time
	RecordedAt    time.Time
}

// InferredCoverageGapFactID returns the canonical identity for a server-inferred
// delivery gap. Adapters use one representation so revisions remain stable when
// persistence implementations change.
func InferredCoverageGapFactID(
	agentID, streamID shared.ID,
	epoch, fromSequence, toSequence uint64,
	detectedAt time.Time,
) shared.ID {
	return shared.ID(fmt.Sprintf("inferred:%s:%s:%d:%d:%d:%s",
		agentID, streamID, epoch, fromSequence, toSequence,
		detectedAt.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)))
}

type CoverageGapSource string

const (
	CoverageGapInferred CoverageGapSource = "inferred_delivery"
	CoverageGapAgent    CoverageGapSource = "agent_origin"
)

func (s CoverageGapSource) Valid() bool {
	return s == CoverageGapInferred || s == CoverageGapAgent
}

func (g CoverageGapFact) Validate() error {
	if !g.Source.Valid() || g.FactID.IsZero() || g.AgentID.IsZero() ||
		g.AssetID.IsZero() || g.StreamID.IsZero() || !g.Priority.Valid() ||
		g.Epoch == 0 || g.Count == 0 || g.Reason == "" || g.FromAt.IsZero() || g.ToAt.IsZero() ||
		g.ToAt.Before(g.FromAt) || g.RecordedAt.IsZero() {
		return fmt.Errorf("%w: coverage gap fact is incomplete", shared.ErrValidation)
	}
	if g.KnownSequence {
		if g.FromSequence == 0 || g.ToSequence < g.FromSequence ||
			g.Count != g.ToSequence-g.FromSequence+1 {
			return fmt.Errorf("%w: coverage gap fact has invalid sequence range", shared.ErrValidation)
		}
	} else if g.FromSequence != 0 || g.ToSequence != 0 {
		return fmt.Errorf("%w: unknown-coordinate coverage gap cannot claim a sequence range", shared.ErrValidation)
	}
	return nil
}

// CoverageGapReader exposes every immutable source fact independently. It must
// not collapse an agent report and an inferred delivery gap that describe the
// same coordinate; the composer deduplicates only the scored defect count.
type CoverageGapReader interface {
	ListCoverageGapFacts(ctx context.Context, q CoverageGapQuery) ([]CoverageGapFact, error)
}

type CoverageGapQuery struct {
	AgentID shared.ID
	AssetID shared.ID
	Since   time.Time
	Until   time.Time
}

func (q CoverageGapQuery) Valid() bool {
	return !q.AgentID.IsZero() && !q.AssetID.IsZero() &&
		!q.Since.IsZero() && !q.Until.IsZero() && q.Since.Before(q.Until)
}

// CoverageWindowStore retains every materialized revision append-only. An
// identical revision is a no-op and keeps the first server-owned CreatedAt.
type CoverageWindowStore interface {
	AppendCoverageWindow(ctx context.Context, window sensorstate.CoverageWindow) (sensorstate.CoverageWindow, error)
	ListCoverageWindows(ctx context.Context, q CoverageWindowQuery) ([]sensorstate.CoverageWindow, error)
}

// CoverageReconcileRequest identifies the closed source-time span whose fixed
// half-open coverage windows must be recomposed after the source fact is durable.
// Point facts use Since == Until.
type CoverageReconcileRequest struct {
	AgentID shared.ID
	AssetID shared.ID
	HostID  shared.ID
	Since   time.Time
	Until   time.Time
}

func (r CoverageReconcileRequest) Validate() error {
	if r.AgentID.IsZero() || r.AssetID.IsZero() || r.HostID.IsZero() ||
		r.Since.IsZero() || r.Until.IsZero() || r.Until.Before(r.Since) {
		return fmt.Errorf("%w: coverage reconciliation requires identity and a valid closed source-time span", shared.ErrValidation)
	}
	return nil
}

// CoverageReconciler recomposes deterministic fixed windows after a source fact
// has been persisted. Callers surface failures; source durability and window
// materialization deliberately do not share a transaction.
type CoverageReconciler interface {
	ReconcileCoverage(ctx context.Context, request CoverageReconcileRequest) error
}

const (
	DefaultCoverageWindowLimit = 1000
	MaxCoverageWindowLimit     = 1000
)

type CoverageWindowQuery struct {
	AgentID shared.ID
	AssetID shared.ID
	HostID  shared.ID
	Since   time.Time
	Until   time.Time
	Limit   int
}

func (q CoverageWindowQuery) Valid() bool {
	if !q.Since.IsZero() && !q.Until.IsZero() && !q.Since.Before(q.Until) {
		return false
	}
	return q.Limit >= 0 && q.Limit <= MaxCoverageWindowLimit
}

// EffectiveLimit returns the shared adapter limit for a valid query.
func (q CoverageWindowQuery) EffectiveLimit() int {
	if q.Limit == 0 {
		return DefaultCoverageWindowLimit
	}
	return q.Limit
}
