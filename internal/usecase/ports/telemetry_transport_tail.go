package ports

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TelemetryAssetBinding is the server-authoritative mapping from an authenticated
// fleet agent to the canonical host asset produced by host-inventory reconciliation.
type TelemetryAssetBinding struct {
	TenantID  shared.ID
	AgentID   shared.ID
	AssetID   shared.ID
	UpdatedAt time.Time
}

func (b TelemetryAssetBinding) Validate() error {
	if b.TenantID.IsZero() || b.AgentID.IsZero() || b.AssetID.IsZero() || b.UpdatedAt.IsZero() {
		return fmt.Errorf("%w: telemetry asset binding is incomplete", shared.ErrValidation)
	}
	return nil
}

type TelemetryAssetBindingStore interface {
	BindTelemetryAsset(ctx context.Context, binding TelemetryAssetBinding) error
	ResolveTelemetryAsset(ctx context.Context, agentID shared.ID) (shared.ID, error)
}

// TelemetryAgentGap is server-persisted provenance for a durable gap discovered
// by the agent spool itself (quota eviction, corruption, torn write, etc.). It is
// distinct from delivery gaps inferred by AckLedger: a later sequence fill must
// never erase a historical local-loss fact.
type TelemetryAgentGap struct {
	GapID           shared.ID
	AgentID         shared.ID
	AssetID         shared.ID
	StreamID        shared.ID
	Priority        fleetagent.DeliveryPriority
	Epoch           uint64
	KnownSequence   bool
	FromSequence    uint64
	ToSequence      uint64
	Count           uint64
	Reason          fleetagent.TelemetryGapReason
	FromAt          time.Time
	ToAt            time.Time
	FirstReportedAt time.Time
	UpdatedAt       time.Time
}

func (g TelemetryAgentGap) Validate() error {
	if g.GapID.IsZero() || g.AgentID.IsZero() || g.AssetID.IsZero() || g.StreamID.IsZero() {
		return fmt.Errorf("%w: telemetry agent gap is missing identity", shared.ErrValidation)
	}
	if !g.Priority.Valid() || g.Epoch == 0 || !g.Reason.Valid() || g.Count == 0 {
		return fmt.Errorf("%w: telemetry agent gap has invalid lane/epoch/reason/count", shared.ErrValidation)
	}
	if g.KnownSequence {
		if g.FromSequence == 0 || g.ToSequence < g.FromSequence || g.Count != g.ToSequence-g.FromSequence+1 {
			return fmt.Errorf("%w: telemetry agent gap has invalid known sequence range", shared.ErrValidation)
		}
	} else if g.FromSequence != 0 || g.ToSequence != 0 {
		return fmt.Errorf("%w: unknown-coordinate telemetry agent gap cannot claim a sequence range", shared.ErrValidation)
	}
	if g.FromAt.IsZero() || g.ToAt.IsZero() || g.ToAt.Before(g.FromAt) {
		return fmt.Errorf("%w: telemetry agent gap has invalid time span", shared.ErrValidation)
	}
	if g.FirstReportedAt.IsZero() || g.UpdatedAt.IsZero() || g.UpdatedAt.Before(g.FirstReportedAt) {
		return fmt.Errorf("%w: telemetry agent gap has invalid report timestamps", shared.ErrValidation)
	}
	return nil
}

// TelemetryAgentGapStore persists agent-origin gap reports idempotently. Reusing a
// GapID for an identical snapshot is a no-op; monotonic coalescing extensions are
// accepted; incompatible identity/reason/lane reuse or shrinking evidence conflicts.
type TelemetryAgentGapStore interface {
	RecordAgentGap(ctx context.Context, gap TelemetryAgentGap) error
}
