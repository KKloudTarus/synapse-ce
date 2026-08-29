package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// DetectionSensor is the agent-side event source the detection engine consumes: a set of per-class eBPF
// observers. The engine depends on THIS interface, not the concrete infrastructure sensor, so the
// dependency points inward (usecase ← infrastructure) and the engine is testable with a fake source.
//
// The infrastructure implementation lives in internal/infrastructure/ebpf (Linux) with a non-Linux stub.
type DetectionSensor interface {
	// Start begins observation for the configured classes. It fails closed (error) when no class can be
	// observed at all; a per-class failure is reported through Coverage, not this error.
	Start(ctx context.Context) error
	// Events streams decoded domain events from every active class until Close.
	Events() <-chan detection.Event
	// Coverage reports the per-class observation status — one entry per class, a gap for any class not
	// actively observing (never a silent absence, never a clean host for an unobserved class).
	Coverage() []detection.ClassCoverage
	// Dropped reports observed-but-dropped events per class caused by back-pressure, so the engine can
	// treat a class under pressure as degraded rather than fully observed.
	Dropped() map[detection.Class]uint64
	// Close detaches every observer and stops the streams. Idempotent.
	Close() error
}

// DetectionSink receives the detections the engine confirms. Implemented by an adapter that ships them to
// the control plane / seals them as evidence (issue #423). Kept narrow so the engine depends only on
// "somewhere to emit a detection", not on how it is stored or transported.
type DetectionSink interface {
	Emit(ctx context.Context, d detection.Detection) error
}

// DetectionRecordStore persists the control-plane detection ledger projection (#423): the queryable rows
// over the sealed evidence-chain links. Tenant scoping is enforced in the implementation via the tenant
// chokepoint, not by the caller. The projection is retention-bounded; the underlying chain links are
// permanent, so expiry removes rows here, never chain history.
type DetectionRecordStore interface {
	// AppendDetection stores one projection row. It is tenant-scoped and idempotent on (engagement, id):
	// a re-delivery in the same engagement is a no-op, while the same id in a different engagement is a
	// distinct row (never overwritten), matching the per-engagement seal namespace.
	AppendDetection(ctx context.Context, r detection.Record) error
	// HasDetection reports whether a record with this id already exists in the given engagement
	// (tenant-scoped by ctx), so ingest can skip an already-sealed detection on a retry rather than
	// sealing it into the chain twice. It is scoped to the engagement to MATCH the per-engagement seal:
	// the same detection id in a DIFFERENT engagement is a distinct detection and must not be skipped
	// (a tenant-wide skip would silently drop it — a cross-engagement loss/suppression vector).
	HasDetection(ctx context.Context, engagementID, id shared.ID) (bool, error)
	// ListDetections returns the (non-expired) records for an engagement, oldest first, tenant-scoped.
	ListDetections(ctx context.Context, engagementID shared.ID) ([]detection.Record, error)
	// LastBatchSequence returns the highest batch sequence recorded for an agent (0 = none yet), so a gap
	// in the sequence can be detected. Tenant-scoped.
	LastBatchSequence(ctx context.Context, agentID shared.ID) (uint64, error)
	// ListExpiredDetections identifies immutable projection rows eligible for retention expiry without
	// deleting them. Callers can durably record an expiry tombstone before removing each exact row.
	ListExpiredDetections(ctx context.Context, engagementID shared.ID, cutoff time.Time) ([]shared.ID, error)
	// DeleteDetection removes one exact retention-bounded projection row. It is idempotent and never
	// deletes evidence or provenance; deleted reports whether the row existed.
	DeleteDetection(ctx context.Context, engagementID, detectionID shared.ID) (deleted bool, err error)
}
