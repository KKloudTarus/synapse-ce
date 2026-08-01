package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/businessservice"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// AssetInventoryRepository persists the tenant-scoped AppSec inventory graph.
type AssetInventoryRepository interface {
	CreateBusinessService(context.Context, *businessservice.BusinessService) error
	ListBusinessServices(context.Context, shared.ID) ([]*businessservice.BusinessService, error)
	GetBusinessService(context.Context, shared.ID, shared.ID) (*businessservice.BusinessService, error)

	CreateAsset(context.Context, *asset.Asset) error
	GetAsset(context.Context, shared.ID, shared.ID) (*asset.Asset, error)
	ListAssets(context.Context, shared.ID) ([]*asset.Asset, error)
	CreateVersion(context.Context, asset.Version) error
	ListVersions(context.Context, shared.ID, shared.ID) ([]asset.Version, error)

	LinkBusinessServiceAsset(context.Context, asset.BusinessServiceLink) error
	ListBusinessServiceAssets(context.Context, shared.ID, shared.ID) ([]asset.BusinessServiceLink, error)
	CreateRelationship(context.Context, shared.ID, asset.Relationship) error
	ListRelationships(context.Context, shared.ID, shared.ID) ([]asset.Relationship, error)
}
