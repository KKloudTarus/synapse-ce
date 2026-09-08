package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/correlation"
	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/detectionprovenance"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// CorrelationDetectionSource is the deliberately narrow, bounded source read used to
// materialize a correlation snapshot. It never exposes the unbounded detection listing.
type CorrelationDetectionSource interface {
	CorrelationHighWater(ctx context.Context, engagementID shared.ID, completed correlation.SourcePosition, retentionAsOf time.Time) (correlation.SourcePosition, bool, error)
	ListCorrelationSourcePage(ctx context.Context, engagementID shared.ID, after, through correlation.SourcePosition, retentionAsOf time.Time, limit int) ([]detection.Record, bool, error)
}

// CorrelationProvenanceSource obtains Received provenance only for the requested source records.
type CorrelationProvenanceSource interface {
	LoadReceivedTransitions(ctx context.Context, engagementID shared.ID, detectionIDs []shared.ID) ([]detectionprovenance.Transition, error)
}

// CorrelationStateStore persists one engagement's two-phase checkpoint, staging rows,
// immutable assignments, and bounded active-session summary. Implementations are tenant-scoped.
type CorrelationStateStore interface {
	LoadCorrelationState(ctx context.Context, engagementID shared.ID, signalIDs []shared.ID, activeLimit int) (correlation.State, error)
	BeginCorrelationSnapshot(ctx context.Context, engagementID shared.ID, expected uint64, upper correlation.SourcePosition, asOf time.Time, digest string) (correlation.Checkpoint, error)
	StageCorrelationSignals(ctx context.Context, engagementID shared.ID, expected uint64, next correlation.Checkpoint, signals []correlation.Signal) error
	ListStagedCorrelationSignals(ctx context.Context, engagementID shared.ID, snapshot correlation.SourcePosition, after correlation.SignalPosition, limit int) ([]correlation.Signal, bool, error)
	CommitCorrelationConsume(ctx context.Context, engagementID shared.ID, expected uint64, next correlation.Checkpoint, added []correlation.Assignment, active []correlation.ActiveSession, snapshot correlation.SourcePosition, complete bool) error
}
