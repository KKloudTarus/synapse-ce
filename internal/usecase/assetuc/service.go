// Package assetuc owns tenant-bound Asset Inventory commands.
package assetuc

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type Service struct {
	repo  ports.AssetInventoryRepository
	clock ports.Clock
	ids   ports.IDGenerator
}

func New(repo ports.AssetInventoryRepository, clock ports.Clock, ids ports.IDGenerator) (*Service, error) {
	if repo == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("asset inventory dependencies are required")
	}
	return &Service{repo: repo, clock: clock, ids: ids}, nil
}

type CreateAssetInput struct {
	TenantID       shared.ID
	Actor, Name    string
	Category       asset.Category
	Identity       asset.Identity
	Lifecycle      asset.Lifecycle
	Criticality    asset.Criticality
	Exposure       asset.Exposure
	Classification string
}

func (s *Service) CreateAsset(ctx context.Context, in CreateAssetInput) (asset.Asset, error) {
	now := s.clock.Now()
	a, err := asset.New(s.ids.NewID(), in.TenantID, in.Name, in.Category, in.Identity, now)
	if err != nil {
		return asset.Asset{}, err
	}
	a.Lifecycle = in.Lifecycle
	if a.Lifecycle == "" {
		a.Lifecycle = asset.LifecyclePlanned
	}
	a.Criticality = in.Criticality
	if a.Criticality == "" {
		a.Criticality = asset.CriticalityMedium
	}
	a.Exposure = in.Exposure
	if a.Exposure == "" {
		a.Exposure = asset.ExposureInternal
	}
	a.Classification = strings.TrimSpace(in.Classification)
	a.Audit.CreatedBy, a.Audit.UpdatedBy = in.Actor, in.Actor
	if err := a.Validate(); err != nil {
		return asset.Asset{}, err
	}
	if err := s.repo.CreateAsset(ctx, a); err != nil {
		return asset.Asset{}, err
	}
	return a, nil
}

type CreateBusinessServiceInput struct {
	TenantID                 shared.ID
	Actor, Name, Description string
	Criticality              asset.Criticality
	Lifecycle                asset.Lifecycle
}

func (s *Service) CreateBusinessService(ctx context.Context, in CreateBusinessServiceInput) (asset.BusinessService, error) {
	now := s.clock.Now()
	b := asset.BusinessService{ID: s.ids.NewID(), TenantID: in.TenantID, Name: strings.TrimSpace(in.Name), Description: strings.TrimSpace(in.Description), Criticality: in.Criticality, Lifecycle: in.Lifecycle, Audit: shared.Audit{CreatedAt: now, UpdatedAt: now, CreatedBy: in.Actor, UpdatedBy: in.Actor}}
	if b.Criticality == "" {
		b.Criticality = asset.CriticalityMedium
	}
	if b.Lifecycle == "" {
		b.Lifecycle = asset.LifecyclePlanned
	}
	if err := b.Validate(); err != nil {
		return asset.BusinessService{}, err
	}
	if err := s.repo.CreateBusinessService(ctx, b); err != nil {
		return asset.BusinessService{}, err
	}
	return b, nil
}
func (s *Service) LinkAsset(ctx context.Context, actor string, serviceID, assetID shared.ID, role asset.AssetLinkRole) error {
	return s.repo.LinkBusinessServiceAsset(ctx, asset.BusinessServiceAssetLink{BusinessServiceID: serviceID, AssetID: assetID, Role: role, CreatedAt: s.clock.Now(), CreatedBy: actor})
}
func (s *Service) Relate(ctx context.Context, tenant shared.ID, actor string, from, to shared.ID, typ asset.RelationshipType) error {
	return s.repo.CreateRelationship(ctx, asset.Relationship{ID: s.ids.NewID(), TenantID: tenant, FromAssetID: from, ToAssetID: to, Type: typ, CreatedAt: s.clock.Now(), CreatedBy: actor})
}
func (s *Service) AssignOwner(ctx context.Context, tenant shared.ID, actor, principal, role string, assetID shared.ID) error {
	return s.repo.AssignOwner(ctx, asset.OwnershipAssignment{ID: s.ids.NewID(), TenantID: tenant, AssetID: assetID, Principal: principal, Role: role, CreatedAt: s.clock.Now(), CreatedBy: actor})
}
func (s *Service) GetAsset(ctx context.Context, id shared.ID) (asset.Asset, error) {
	return s.repo.GetAsset(ctx, id)
}
func (s *Service) ListAssets(ctx context.Context) ([]asset.Asset, error) {
	return s.repo.ListAssets(ctx)
}
func (s *Service) GetBusinessService(ctx context.Context, id shared.ID) (asset.BusinessService, error) {
	return s.repo.GetBusinessService(ctx, id)
}
func (s *Service) ListBusinessServices(ctx context.Context) ([]asset.BusinessService, error) {
	return s.repo.ListBusinessServices(ctx)
}

func (s *Service) ListAssetVersions(ctx context.Context, id shared.ID) ([]asset.Version, error) {
	return s.repo.ListAssetVersions(ctx, id)
}

func (s *Service) ListRelationships(ctx context.Context, id shared.ID) ([]asset.Relationship, error) {
	return s.repo.ListRelationships(ctx, id)
}

func (s *Service) ListOwners(ctx context.Context, id shared.ID) ([]asset.OwnershipAssignment, error) {
	return s.repo.ListOwners(ctx, id)
}

func (s *Service) ListBusinessServiceAssets(ctx context.Context, id shared.ID) ([]asset.BusinessServiceAssetLink, error) {
	return s.repo.ListBusinessServiceAssets(ctx, id)
}

func (s *Service) DeleteAsset(ctx context.Context, id shared.ID) error {
	return s.repo.DeleteAsset(ctx, id)
}

func (s *Service) DeleteBusinessService(ctx context.Context, id shared.ID) error {
	return s.repo.DeleteBusinessService(ctx, id)
}

type UpdateBusinessServiceInput struct {
	Actor, Name, Description string
	Criticality              asset.Criticality
	Lifecycle                asset.Lifecycle
}

func (s *Service) UpdateBusinessService(ctx context.Context, id shared.ID, in UpdateBusinessServiceInput) (asset.BusinessService, error) {
	current, err := s.repo.GetBusinessService(ctx, id)
	if err != nil {
		return asset.BusinessService{}, err
	}
	current.Name = strings.TrimSpace(in.Name)
	current.Description = strings.TrimSpace(in.Description)
	current.Criticality = in.Criticality
	current.Lifecycle = in.Lifecycle
	current.Audit.UpdatedAt, current.Audit.UpdatedBy = s.clock.Now(), in.Actor
	if err := current.Validate(); err != nil {
		return asset.BusinessService{}, err
	}
	if err := s.repo.UpdateBusinessService(ctx, current); err != nil {
		return asset.BusinessService{}, err
	}
	return current, nil
}

type UpdateAssetInput struct {
	Actor           string
	ExpectedVersion int
	Lifecycle       asset.Lifecycle
	Criticality     asset.Criticality
	Exposure        asset.Exposure
	Classification  string
}

func (s *Service) UpdateAsset(ctx context.Context, id shared.ID, in UpdateAssetInput) (asset.Asset, error) {
	current, err := s.repo.GetAsset(ctx, id)
	if err != nil {
		return asset.Asset{}, err
	}
	if in.ExpectedVersion != current.Version {
		return asset.Asset{}, fmt.Errorf("asset %s: %w", id, shared.ErrConflict)
	}
	current.Lifecycle, current.Criticality, current.Exposure = in.Lifecycle, in.Criticality, in.Exposure
	current.Classification = strings.TrimSpace(in.Classification)
	current.Version++
	current.Audit.UpdatedAt, current.Audit.UpdatedBy = s.clock.Now(), in.Actor
	snapshot, err := json.Marshal(current)
	if err != nil {
		return asset.Asset{}, err
	}
	version := asset.Version{ID: s.ids.NewID(), TenantID: current.TenantID, AssetID: current.ID, Number: current.Version, Snapshot: snapshot, CreatedAt: current.Audit.UpdatedAt, CreatedBy: in.Actor}
	if err := s.repo.UpdateAsset(ctx, current, version); err != nil {
		return asset.Asset{}, err
	}
	return current, nil
}
