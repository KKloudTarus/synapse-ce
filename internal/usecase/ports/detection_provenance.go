package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detectionprovenance"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// DetectionProvenanceStore retains an updatable current projection plus an append-only history.
// The caller supplies complete domain transitions; implementations enforce tenant isolation and
// idempotency on the transition sequence.
type DetectionProvenanceStore interface {
	AdmitPending(ctx context.Context, current detectionprovenance.Current, received detectionprovenance.Transition) error
	AppendTransition(ctx context.Context, transition detectionprovenance.Transition) error
	Current(ctx context.Context, engagementID, detectionID shared.ID) (detectionprovenance.Current, bool, error)
	ListCurrent(ctx context.Context, engagementID shared.ID) ([]detectionprovenance.Current, error)
	ListPending(ctx context.Context) ([]detectionprovenance.Current, error)
	ListTransitions(ctx context.Context, engagementID, detectionID shared.ID) ([]detectionprovenance.Transition, error)
}

// PendingDetectionReconciler repairs attributed detections after their referenced telemetry becomes durable.
type PendingDetectionReconciler interface {
	ReconcilePendingDetections(ctx context.Context) (int, error)
}

// DetectionReconciliationTenantStore enumerates tenant scopes for startup and background repair.
type DetectionReconciliationTenantStore interface {
	ListTenantIDs(ctx context.Context) ([]shared.ID, error)
}

// TelemetryReferenceResolver confirms whether causal event references are durable in the existing
// telemetry transport store. A resolver must return false rather than infer durability from a host or time.
type TelemetryReferenceStatus string

const (
	TelemetryReferencesMissing       TelemetryReferenceStatus = "missing"
	TelemetryReferencesDurable       TelemetryReferenceStatus = "durable"
	TelemetryReferencesContradictory TelemetryReferenceStatus = "contradictory"
)

type TelemetryReferenceResolver interface {
	ResolveTelemetryReferences(ctx context.Context, agentID, assetID shared.ID, redactionPolicyDigest string, refs []fleetagent.TelemetryReference) (TelemetryReferenceStatus, error)
}
