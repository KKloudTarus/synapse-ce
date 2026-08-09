package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/attackpath"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// AttackPathStore persists tenant-scoped, recomputable asset-to-finding bindings.
type AttackPathStore interface {
	ReplaceBindings(ctx context.Context, tenantID, engagementID, producer shared.ID, bindings []attackpath.Binding) error
	ListBindings(ctx context.Context, tenantID shared.ID) ([]attackpath.Binding, error)
}

// FindingAttributor validates and records explicit, producer-owned finding attribution.
// It never derives an asset from finding prose or source locations.
type FindingAttributor interface {
	ValidateAsset(ctx context.Context, engagementID, assetID shared.ID) error
	Record(ctx context.Context, engagementID, assetID, producer, provenance shared.ID, confidence asset.EdgeConfidence, findingIDs []shared.ID) error
	RecordTargets(ctx context.Context, engagementID, assetID, producer, provenance shared.ID, confidence asset.EdgeConfidence, targets []attackpath.FindingTarget) error
	InheritedAssetID(ctx context.Context, engagementID shared.ID, findingIDs []shared.ID) (shared.ID, error)
}
