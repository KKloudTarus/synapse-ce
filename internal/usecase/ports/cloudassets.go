package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/cloudposture"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// CloudAssetInput is one normalized live cloud asset observation.
type CloudAssetInput struct {
	TenantID   shared.ID
	Kind       asset.Kind
	Key        string
	Name       string
	Attributes map[string]string
}

// CloudEdgeInput is one normalized live cloud relationship observation.
type CloudEdgeInput struct {
	TenantID   shared.ID
	From       shared.ID
	To         shared.ID
	Kind       asset.EdgeKind
	Provenance shared.ID
	Confidence asset.EdgeConfidence
}

// CloudAssetWriter persists cloud observations through the governed asset model.
type CloudAssetWriter interface {
	UpsertCloudAsset(context.Context, string, CloudAssetInput) (*asset.Asset, error)
	UpsertCloudEdge(context.Context, string, CloudEdgeInput) error
}

// CloudEvidenceSealer appends one normalized CSPM snapshot to the engagement evidence chain.
// CloudObservationStore tracks producer-owned current observations without mutating finding triage.
type CloudObservationStore interface {
	ReconcileCloudObservations(context.Context, shared.ID, shared.ID, string, shared.ID, []shared.ID, []shared.ID, []string, bool) error
}

type EvidenceAppender interface {
	Seal(context.Context, shared.ID, string, []byte, string) (evidence.Evidence, error)
}

type CloudEvidenceSealer interface {
	SealCloudSnapshot(context.Context, shared.ID, cloudposture.Inventory, []cloudposture.CoverageIssue, string) (shared.ID, string, error)
}
