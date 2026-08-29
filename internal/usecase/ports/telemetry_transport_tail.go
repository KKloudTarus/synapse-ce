package ports

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
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

// Validate checks that a binding carries complete tenant, authenticated-agent, asset and timestamp identity.
func (b TelemetryAssetBinding) Validate() error {
	if b.TenantID.IsZero() || b.AgentID.IsZero() || b.AssetID.IsZero() || b.UpdatedAt.IsZero() {
		return fmt.Errorf("%w: telemetry asset binding is incomplete", shared.ErrValidation)
	}
	return nil
}

// TelemetryAssetBindingStore owns the server-authoritative agent→host mapping. BindTelemetryAsset is
// fail-closed: one asset cannot silently move to a different agent; a cross-agent claim returns
// shared.ErrConflict and leaves the existing binding intact. ResolveTelemetryAsset is tenant-scoped from ctx.
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

// Validate checks that the loss identity, lane, optional sequence range, observed-time span and report
// timestamps are internally consistent.
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
// TelemetryAgentGapRevision retains the exact authenticated, signed agent report
// accepted for one current gap projection. SignedContentDigest identifies exact
// retries while later monotonic extensions append distinct immutable revisions.
type TelemetryAgentGapRevision struct {
	Revision             uint64
	ProtocolVersion      int
	GapID                shared.ID
	AuthenticatedAgentID shared.ID
	AgentID              shared.ID
	HostID               shared.ID
	AgentSessionID       fleetagent.SessionID
	AssetID              shared.ID
	StreamID             shared.ID
	Priority             fleetagent.DeliveryPriority
	Epoch                uint64
	KnownSequence        bool
	FromSequence         uint64
	ToSequence           uint64
	Count                uint64
	Reason               fleetagent.TelemetryGapReason
	FromAt               time.Time
	ToAt                 time.Time
	KeyID                string
	Signature            string
	SignedContentDigest  string
	ReceivedAt           time.Time
}

// Validate checks that an immutable revision is a complete valid signed report
// and that its supplied identity is the digest of the exact canonical signed bytes.
func (r TelemetryAgentGapRevision) Validate() error {
	report := r.Report()
	if err := report.Validate(); err != nil {
		return err
	}
	if r.AuthenticatedAgentID.IsZero() || r.AuthenticatedAgentID != r.AgentID || r.ReceivedAt.IsZero() {
		return fmt.Errorf("%w: telemetry agent gap revision has invalid authenticated identity or receipt time", shared.ErrValidation)
	}
	if strings.TrimSpace(r.Signature) == "" {
		return fmt.Errorf("%w: telemetry agent gap revision has no signature", shared.ErrValidation)
	}
	digest := sha256.Sum256(fleetagent.TelemetryGapMessage(report))
	if r.SignedContentDigest != hex.EncodeToString(digest[:]) {
		return fmt.Errorf("%w: telemetry agent gap revision digest does not match signed content", shared.ErrValidation)
	}
	return nil
}

// Report reconstructs the exact signed protocol report retained by this revision.
func (r TelemetryAgentGapRevision) Report() fleetagent.TelemetryGapReport {
	return fleetagent.TelemetryGapReport{
		ProtocolVersion: r.ProtocolVersion,
		GapID:           r.GapID, AgentID: r.AgentID, HostID: r.HostID,
		AgentSessionID: r.AgentSessionID, AssetID: r.AssetID, StreamID: r.StreamID,
		Priority: r.Priority, Epoch: r.Epoch, KnownSequence: r.KnownSequence,
		FromSequence: r.FromSequence, ToSequence: r.ToSequence, Count: r.Count,
		Reason: r.Reason, FromAt: r.FromAt, ToAt: r.ToAt, KeyID: r.KeyID,
		Signature: r.Signature,
	}
}

// Projection derives the mutable current view represented by this immutable revision.
func (r TelemetryAgentGapRevision) Projection() TelemetryAgentGap {
	return TelemetryAgentGap{
		GapID: r.GapID, AgentID: r.AuthenticatedAgentID, AssetID: r.AssetID, StreamID: r.StreamID,
		Priority: r.Priority, Epoch: r.Epoch, KnownSequence: r.KnownSequence,
		FromSequence: r.FromSequence, ToSequence: r.ToSequence, Count: r.Count,
		Reason: r.Reason, FromAt: r.FromAt, ToAt: r.ToAt,
		FirstReportedAt: r.ReceivedAt, UpdatedAt: r.ReceivedAt,
	}
}

type TelemetryAgentGapStore interface {
	// RecordAgentGap preserves compatibility for server-origin projections that do
	// not have an agent signature. Authenticated ingest uses AcceptAgentGapRevision.
	RecordAgentGap(ctx context.Context, gap TelemetryAgentGap) error
	// AcceptAgentGapRevision atomically appends an immutable signed revision and
	// advances its mutable current projection. Exact signed retries are no-ops;
	// incompatible GapID reuse conflicts without a partial append.
	AcceptAgentGapRevision(ctx context.Context, revision TelemetryAgentGapRevision) error
}
