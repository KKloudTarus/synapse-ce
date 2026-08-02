package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// AssetInventoryRepository is the tenant-scoped persistence boundary for the
// bounded AppSec inventory. Implementations MUST treat every referenced ID as
// tenant-owned and reject cross-tenant relationship/link attempts as not found.
type AssetInventoryRepository interface {
	CreateAsset(context.Context, asset.Asset) error
	GetAsset(context.Context, shared.ID) (asset.Asset, error)
	ListAssets(context.Context) ([]asset.Asset, error)
	UpdateAsset(context.Context, asset.Asset, asset.Version) error
	DeleteAsset(context.Context, shared.ID) error
	ListAssetVersions(context.Context, shared.ID) ([]asset.Version, error)
	CreateBusinessService(context.Context, asset.BusinessService) error
	GetBusinessService(context.Context, shared.ID) (asset.BusinessService, error)
	ListBusinessServices(context.Context) ([]asset.BusinessService, error)
	UpdateBusinessService(context.Context, asset.BusinessService) error
	DeleteBusinessService(context.Context, shared.ID) error
	LinkBusinessServiceAsset(context.Context, asset.BusinessServiceAssetLink) error
	ListBusinessServiceAssets(context.Context, shared.ID) ([]asset.BusinessServiceAssetLink, error)
	CreateRelationship(context.Context, asset.Relationship) error
	ListRelationships(context.Context, shared.ID) ([]asset.Relationship, error)
	AssignOwner(context.Context, asset.OwnershipAssignment) error
	ListOwners(context.Context, shared.ID) ([]asset.OwnershipAssignment, error)
}
