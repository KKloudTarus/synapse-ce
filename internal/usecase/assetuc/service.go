// Package assetuc is the use-case layer for the fleet asset model (#431, epic #405). It
// orchestrates the AssetRepository plus the audit log, clock and id generator ports, keeps the
// domain pure, and audits every mutation. Upserts are idempotent by natural key: re-observing an
// unchanged asset reuses its id and produces no duplicate row.
package assetuc

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Service is the asset-model use case.
type Service struct {
	repo  ports.AssetRepository
	audit ports.AuditLogger
	clock ports.Clock
	ids   ports.IDGenerator
}

// NewService validates its dependencies and returns the service.
func NewService(repo ports.AssetRepository, audit ports.AuditLogger, clock ports.Clock, ids ports.IDGenerator) (*Service, error) {
	if repo == nil || audit == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: asset service needs repo + audit + clock + ids", shared.ErrValidation)
	}
	return &Service{repo: repo, audit: audit, clock: clock, ids: ids}, nil
}

// UpsertAssetInput describes an observed asset. TenantID must be non-empty (empty is DENY under
// RLS). Kind+Key are the natural identity; Name defaults to Key.
type UpsertAssetInput struct {
	TenantID   shared.ID
	Kind       asset.Kind
	Key        string
	Name       string
	Attributes map[string]string
}

// UpsertAsset creates or updates the asset identified by (TenantID, Kind, Key). It reuses the
// existing id and creation time when the asset already exists, so ids are stable across
// re-observation and no duplicate row is created.
func (s *Service) UpsertAsset(ctx context.Context, actor string, in UpsertAssetInput) (*asset.Asset, error) {
	now := s.clock.Now()
	id := s.ids.NewID()
	existing, err := s.repo.GetAssetByKey(ctx, in.TenantID, in.Kind, in.Key)
	switch {
	case err == nil:
		id = existing.ID
	case errors.Is(err, shared.ErrNotFound):
		// new asset; keep the freshly generated id
	default:
		return nil, fmt.Errorf("asset upsert: lookup: %w", err)
	}
	a, err := asset.New(id, in.TenantID, in.Kind, in.Key, in.Name, in.Attributes, now)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		a.Audit.CreatedAt = existing.Audit.CreatedAt
	}
	if err := s.repo.UpsertAsset(ctx, a); err != nil {
		return nil, fmt.Errorf("asset upsert: %w", err)
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor:  actor,
		Action: "asset.upserted",
		Target: a.ID.String(),
		Metadata: map[string]string{
			"tenant_id": a.TenantID.String(),
			"kind":      string(a.Kind),
			"key":       a.Key,
		},
		At: now,
	}); err != nil {
		return nil, fmt.Errorf("asset upsert: audit: %w", err)
	}
	return a, nil
}

// GetAssetByKey returns the current asset identified by its tenant-scoped natural key. It is exposed
// narrowly for use cases that must authorize a mutation against server-authored asset state before
// calling UpsertAsset; callers must still use UpsertAsset for writes so mutation auditing is preserved.
func (s *Service) GetAssetByKey(ctx context.Context, tenantID shared.ID, kind asset.Kind, key string) (*asset.Asset, error) {
	return s.repo.GetAssetByKey(ctx, tenantID, kind, key)
}

// EdgeInput describes a typed, provenance-carrying relationship between two assets.
type EdgeInput struct {
	TenantID   shared.ID
	From       shared.ID
	To         shared.ID
	Kind       asset.EdgeKind
	Provenance shared.ID
	Confidence asset.EdgeConfidence
}

// UpsertCloudAsset adapts the CSPM port to the asset service.
func (s *Service) UpsertCloudAsset(ctx context.Context, actor string, in ports.CloudAssetInput) (*asset.Asset, error) {
	return s.UpsertAsset(ctx, actor, UpsertAssetInput{TenantID: in.TenantID, Kind: in.Kind, Key: in.Key, Name: in.Name, Attributes: in.Attributes})
}

// UpsertCloudEdge adapts the CSPM port to the asset service.
func (s *Service) UpsertCloudEdge(ctx context.Context, actor string, in ports.CloudEdgeInput) error {
	return s.UpsertEdge(ctx, actor, EdgeInput{TenantID: in.TenantID, From: in.From, To: in.To, Kind: in.Kind, Provenance: in.Provenance, Confidence: in.Confidence})
}

// UpsertEdge validates and persists an edge. It is idempotent by natural key
// (tenant, from, to, kind, provenance).
func (s *Service) UpsertEdge(ctx context.Context, actor string, in EdgeInput) error {
	now := s.clock.Now()
	e, err := asset.NewEdge(in.TenantID, in.From, in.To, in.Kind, in.Provenance, in.Confidence)
	if err != nil {
		return err
	}
	if err := s.repo.UpsertEdge(ctx, e); err != nil {
		return fmt.Errorf("asset edge upsert: %w", err)
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor:  actor,
		Action: "asset.edge_upserted",
		Target: e.From.String(),
		Metadata: map[string]string{
			"tenant_id":  e.TenantID.String(),
			"to":         e.To.String(),
			"kind":       string(e.Kind),
			"provenance": e.Provenance.String(),
			"confidence": string(e.Confidence),
		},
		At: now,
	}); err != nil {
		return fmt.Errorf("asset edge upsert: audit: %w", err)
	}
	return nil
}

// ListAssets returns the tenant's assets, deterministically ordered.
func (s *Service) ListAssets(ctx context.Context, tenantID shared.ID) ([]*asset.Asset, error) {
	return s.repo.ListAssets(ctx, tenantID)
}

// ListEdges returns the tenant's edges, deterministically ordered.
func (s *Service) ListEdges(ctx context.Context, tenantID shared.ID) ([]*asset.Edge, error) {
	return s.repo.ListEdges(ctx, tenantID)
}

// WorkloadImage is a container image a workload runs, taken from the cluster-inventory graph.
type WorkloadImage struct {
	Ref    string // image reference as declared (may be a mutable tag)
	Digest string // resolved image digest; the KindImage asset's natural key
}

// WorkloadOrigin is one Kubernetes workload (Deployment/StatefulSet/DaemonSet/...) and the images it
// runs, derived from the cluster-inventory asset graph (KindWorkload --depends_on--> KindImage). It
// answers "which workload runs this image", so a CVE found on an image can be traced to its workload.
type WorkloadOrigin struct {
	Cluster        string
	Namespace      string
	Kind           string // controller kind
	Name           string
	ServiceAccount string
	Images         []WorkloadImage
}

// Workloads returns the tenant's Kubernetes workloads with the images they run, from the asset graph.
// It is read-only and returns an empty slice when no cluster inventory has been ingested.
func (s *Service) Workloads(ctx context.Context, tenantID shared.ID) ([]WorkloadOrigin, error) {
	assets, err := s.repo.ListAssets(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list assets: %w", err)
	}
	edges, err := s.repo.ListEdges(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list edges: %w", err)
	}
	byID := make(map[shared.ID]*asset.Asset, len(assets))
	for _, a := range assets {
		byID[a.ID] = a
	}
	// workload id -> the image assets it depends on
	imagesOf := make(map[shared.ID][]*asset.Asset)
	for _, e := range edges {
		if e.Kind != asset.EdgeDependsOn {
			continue
		}
		from, to := byID[e.From], byID[e.To]
		if from == nil || to == nil || from.Kind != asset.KindWorkload || to.Kind != asset.KindImage {
			continue
		}
		imagesOf[from.ID] = append(imagesOf[from.ID], to)
	}
	out := make([]WorkloadOrigin, 0)
	for _, a := range assets {
		if a.Kind != asset.KindWorkload {
			continue
		}
		wo := WorkloadOrigin{
			Cluster:        clusterFromWorkloadKey(a.Key),
			Namespace:      a.Attributes["namespace"],
			Kind:           a.Attributes["controller_kind"],
			Name:           a.Name,
			ServiceAccount: a.Attributes["service_account"],
		}
		for _, img := range imagesOf[a.ID] {
			wo.Images = append(wo.Images, WorkloadImage{Ref: img.Attributes["image"], Digest: img.Name})
		}
		sort.Slice(wo.Images, func(i, j int) bool { return wo.Images[i].Digest < wo.Images[j].Digest })
		out = append(out, wo)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Kind < out[j].Kind
	})
	return out, nil
}

// clusterFromWorkloadKey extracts the cluster identity, the first segment of a workload's natural key
// (cluster/namespace/controllerKind/name).
func clusterFromWorkloadKey(key string) string {
	if i := strings.IndexByte(key, '/'); i >= 0 {
		return key[:i]
	}
	return key
}
