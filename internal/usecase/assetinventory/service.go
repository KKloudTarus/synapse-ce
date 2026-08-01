// Package assetinventory implements durable AppSec asset and Business Service management.
package assetinventory

import (
	"context"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/businessservice"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type Service struct {
	repo  ports.AssetInventoryRepository
	clock ports.Clock
	ids   ports.IDGenerator
	audit ports.AuditLogger
}

func NewService(repo ports.AssetInventoryRepository, clock ports.Clock, ids ports.IDGenerator, audit ports.AuditLogger) *Service {
	return &Service{repo: repo, clock: clock, ids: ids, audit: audit}
}

type CreateBusinessServiceInput struct {
	TenantID    shared.ID
	Actor       string
	Name        string
	Code        string
	Owner       string
	Criticality string
}

func (s *Service) CreateBusinessService(ctx context.Context, in CreateBusinessServiceInput) (*businessservice.BusinessService, error) {
	if err := requireActor(in.Actor); err != nil {
		return nil, err
	}
	now := s.clock.Now()
	service, err := businessservice.New(s.ids.NewID(), in.TenantID, in.Name, in.Code, in.Owner, in.Criticality, now)
	if err != nil {
		return nil, err
	}
	service.Audit.CreatedBy, service.Audit.UpdatedBy = in.Actor, in.Actor
	if err := s.repo.CreateBusinessService(ctx, service); err != nil {
		return nil, fmt.Errorf("persist business service: %w", err)
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{Actor: in.Actor, Action: "appsec.business_service.create", Target: service.ID.String(), Metadata: map[string]string{"code": service.Code}, At: now}); err != nil {
		return nil, fmt.Errorf("audit business service create: %w", err)
	}
	return service, nil
}

func (s *Service) ListBusinessServices(ctx context.Context, tenantID shared.ID) ([]*businessservice.BusinessService, error) {
	return s.repo.ListBusinessServices(ctx, tenantID)
}

type CreateAssetInput struct {
	TenantID       shared.ID
	Actor          string
	Name           string
	Category       asset.Category
	Identity       asset.Identity
	Lifecycle      asset.Lifecycle
	Owner          string
	Criticality    string
	Exposure       string
	Classification string
}

func (s *Service) CreateAsset(ctx context.Context, in CreateAssetInput) (*asset.Asset, error) {
	if err := requireActor(in.Actor); err != nil {
		return nil, err
	}
	now := s.clock.Now()
	a, err := asset.New(s.ids.NewID(), in.TenantID, in.Name, in.Category, in.Identity, in.Lifecycle, in.Owner, in.Criticality, in.Exposure, in.Classification, now)
	if err != nil {
		return nil, err
	}
	a.Audit.CreatedBy, a.Audit.UpdatedBy = in.Actor, in.Actor
	if err := s.repo.CreateAsset(ctx, a); err != nil {
		return nil, fmt.Errorf("persist asset: %w", err)
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{Actor: in.Actor, Action: "appsec.asset.create", Target: a.ID.String(), Metadata: map[string]string{"category": string(a.Category)}, At: now}); err != nil {
		return nil, fmt.Errorf("audit asset create: %w", err)
	}
	return a, nil
}

func (s *Service) ListAssets(ctx context.Context, tenantID shared.ID) ([]*asset.Asset, error) {
	return s.repo.ListAssets(ctx, tenantID)
}

func (s *Service) GetAsset(ctx context.Context, tenantID, assetID shared.ID) (*asset.Asset, error) {
	return s.repo.GetAsset(ctx, tenantID, assetID)
}

func (s *Service) AddVersion(ctx context.Context, actor string, tenantID, assetID shared.ID, value, source string) (asset.Version, error) {
	if err := requireActor(actor); err != nil {
		return asset.Version{}, err
	}
	if _, err := s.repo.GetAsset(ctx, tenantID, assetID); err != nil {
		return asset.Version{}, err
	}
	now := s.clock.Now()
	version, err := asset.NewVersion(s.ids.NewID(), assetID, value, source, now)
	if err != nil {
		return asset.Version{}, err
	}
	version.Audit.CreatedBy, version.Audit.UpdatedBy = actor, actor
	if err := s.repo.CreateVersion(ctx, version); err != nil {
		return asset.Version{}, fmt.Errorf("persist asset version: %w", err)
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{Actor: actor, Action: "appsec.asset.version.create", Target: version.ID.String(), Metadata: map[string]string{"asset_id": assetID.String()}, At: now}); err != nil {
		return asset.Version{}, fmt.Errorf("audit asset version create: %w", err)
	}
	return version, nil
}

func (s *Service) LinkBusinessServiceAsset(ctx context.Context, actor string, tenantID, serviceID, assetID shared.ID, role asset.BusinessServiceRole) (asset.BusinessServiceLink, error) {
	if err := requireActor(actor); err != nil {
		return asset.BusinessServiceLink{}, err
	}
	if _, err := s.repo.GetBusinessService(ctx, tenantID, serviceID); err != nil {
		return asset.BusinessServiceLink{}, err
	}
	if _, err := s.repo.GetAsset(ctx, tenantID, assetID); err != nil {
		return asset.BusinessServiceLink{}, err
	}
	now := s.clock.Now()
	link, err := asset.NewBusinessServiceLink(serviceID, assetID, role, now)
	if err != nil {
		return asset.BusinessServiceLink{}, err
	}
	link.Audit.CreatedBy, link.Audit.UpdatedBy = actor, actor
	if err := s.repo.LinkBusinessServiceAsset(ctx, link); err != nil {
		return asset.BusinessServiceLink{}, fmt.Errorf("link business service asset: %w", err)
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{Actor: actor, Action: "appsec.business_service.asset.link", Target: serviceID.String(), Metadata: map[string]string{"asset_id": assetID.String(), "role": string(role)}, At: now}); err != nil {
		return asset.BusinessServiceLink{}, fmt.Errorf("audit business service asset link: %w", err)
	}
	return link, nil
}

func (s *Service) AddRelationship(ctx context.Context, actor string, tenantID, from, to shared.ID, kind asset.RelationshipType) (asset.Relationship, error) {
	if err := requireActor(actor); err != nil {
		return asset.Relationship{}, err
	}
	if _, err := s.repo.GetAsset(ctx, tenantID, from); err != nil {
		return asset.Relationship{}, err
	}
	if _, err := s.repo.GetAsset(ctx, tenantID, to); err != nil {
		return asset.Relationship{}, err
	}
	now := s.clock.Now()
	rel, err := asset.NewRelationship(from, to, kind, now)
	if err != nil {
		return asset.Relationship{}, err
	}
	for _, existing := range mustListRelationships(ctx, s.repo, tenantID, from) {
		if existing.FromAssetID == to && existing.ToAssetID == from && ((kind == asset.RelationshipContains && existing.Type == asset.RelationshipContains) || (kind == asset.RelationshipPartOf && existing.Type == asset.RelationshipPartOf)) {
			return asset.Relationship{}, fmt.Errorf("%w: direct containment cycle", shared.ErrValidation)
		}
	}
	rel.Audit.CreatedBy, rel.Audit.UpdatedBy = actor, actor
	if err := s.repo.CreateRelationship(ctx, tenantID, rel); err != nil {
		return asset.Relationship{}, fmt.Errorf("persist asset relationship: %w", err)
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{Actor: actor, Action: "appsec.asset.relationship.create", Target: from.String(), Metadata: map[string]string{"to_asset_id": to.String(), "type": string(kind)}, At: now}); err != nil {
		return asset.Relationship{}, fmt.Errorf("audit asset relationship create: %w", err)
	}
	return rel, nil
}

func (s *Service) ListRelationships(ctx context.Context, tenantID, assetID shared.ID) ([]asset.Relationship, error) {
	if _, err := s.repo.GetAsset(ctx, tenantID, assetID); err != nil {
		return nil, err
	}
	return s.repo.ListRelationships(ctx, tenantID, assetID)
}

func mustListRelationships(ctx context.Context, repo ports.AssetInventoryRepository, tenantID, assetID shared.ID) []asset.Relationship {
	rels, err := repo.ListRelationships(ctx, tenantID, assetID)
	if err != nil {
		return nil
	}
	return rels
}

func requireActor(actor string) error {
	if strings.TrimSpace(actor) == "" {
		return fmt.Errorf("%w: actor is required", shared.ErrValidation)
	}
	return nil
}
