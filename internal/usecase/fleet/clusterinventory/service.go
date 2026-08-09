// Package clusterinventory is the use-case layer for the Kubernetes cluster agent (#411, epic #405).
// It takes a vendor-neutral cluster Snapshot (produced by the infrastructure informer — a follow-up),
// maps it to the fleet asset model with the pure domain mapper, and persists the observed assets and
// typed edges through the asset use case, reusing its idempotent upsert-by-natural-key + audit path.
//
// Coverage honesty is preserved end to end: the mapper's coverage gaps (unscanned/unresolved image
// digests, workloads with no observed containers, out-of-scope and unobserved namespaces) are
// returned to the caller and audited, never dropped. Re-syncing an unchanged cluster is idempotent —
// producing no asset or edge churn — as long as the caller passes a STABLE per-cluster-source
// Provenance (see SyncInput.Provenance): assets upsert by a provenance-free natural key, and edges
// upsert by a natural key that INCLUDES provenance, so a stable provenance is what makes the edge set
// converge instead of growing one row per observation.
package clusterinventory

import (
	"context"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	dci "github.com/KKloudTarus/synapse-ce/internal/domain/clusterinventory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/assetuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// AssetWriter is the subset of the asset use case this service needs: idempotent upsert of an asset
// (resolving its stable id by natural key) and of a typed edge. assetuc.Service satisfies it; tests
// use a fake. It is a consumer-side interface defined at the point of use so this package depends on
// the asset service's behaviour, not its concrete type (it still references the assetuc input DTOs).
type AssetWriter interface {
	UpsertAsset(ctx context.Context, actor string, in assetuc.UpsertAssetInput) (*asset.Asset, error)
	UpsertEdge(ctx context.Context, actor string, in assetuc.EdgeInput) error
}

// The concrete asset use case satisfies the consumer-side interface.
var _ AssetWriter = (*assetuc.Service)(nil)

// Service maps and persists a cluster inventory.
type Service struct {
	assets  AssetWriter
	audit   ports.AuditLogger
	clock   ports.Clock
	scanned ports.ScannedImageStore // optional; when set, supplies the scanned-digest set for coverage
}

// NewService validates its dependencies and constructs the service.
func NewService(assets AssetWriter, audit ports.AuditLogger, clock ports.Clock) (*Service, error) {
	if assets == nil {
		return nil, fmt.Errorf("%w: cluster inventory requires an asset writer", shared.ErrValidation)
	}
	if audit == nil {
		return nil, fmt.Errorf("%w: cluster inventory requires an audit logger", shared.ErrValidation)
	}
	if clock == nil {
		return nil, fmt.Errorf("%w: cluster inventory requires a clock", shared.ErrValidation)
	}
	return &Service{assets: assets, audit: audit, clock: clock}, nil
}

// SetScannedImages wires the scanned-image digest source (#446). When set, a Sync whose SyncInput
// does not carry an explicit ScannedDigests set looks up the tenant's scanned digests here, so an
// unscanned running digest is an accurate coverage gap rather than every digest reported unscanned.
func (s *Service) SetScannedImages(store ports.ScannedImageStore) { s.scanned = store }

// SyncInput describes one observation of a cluster.
type SyncInput struct {
	TenantID shared.ID
	Snapshot dci.Snapshot
	// ScannedDigests is the set of image digests the engine has already scanned. A running digest
	// absent from it becomes a coverage gap (never omitted). When nil, the service looks it up from the
	// wired ScannedImageStore (SetScannedImages); a caller may still pass an explicit set to override.
	ScannedDigests map[string]bool
	// Provenance identifies the observation source that produced the assets/edges. It is required (an
	// unattributable edge cannot be trusted by attack-path traversal) and MUST be STABLE for a given
	// cluster source across syncs — e.g. derived from cluster identity, NOT a fresh per-sync id.
	// assetuc keys an edge by (tenant, from, to, kind, provenance), so a per-sync provenance would mint
	// a new edge row every observation (churn); a stable one lets the edge set converge.
	Provenance shared.ID
}

// SyncResult reports what a sync produced. Gaps are the coverage gaps surfaced to the caller so a
// partial inventory is visible, never silently treated as clean.
type SyncResult struct {
	Assets int
	Edges  int
	Gaps   []dci.CoverageGap
}

// Sync maps the snapshot to the asset model and persists it. It is idempotent: two syncs of an
// unchanged cluster produce the same assets/edges and no churn.
func (s *Service) Sync(ctx context.Context, actor string, in SyncInput) (*SyncResult, error) {
	if strings.TrimSpace(actor) == "" {
		return nil, fmt.Errorf("%w: cluster inventory actor is required", shared.ErrValidation)
	}
	if in.TenantID.IsZero() {
		return nil, fmt.Errorf("%w: cluster inventory tenant id is required", shared.ErrValidation)
	}
	if in.Provenance.IsZero() {
		return nil, fmt.Errorf("%w: cluster inventory provenance is required", shared.ErrValidation)
	}
	if err := in.Snapshot.Validate(); err != nil {
		return nil, fmt.Errorf("cluster inventory: invalid snapshot: %w", err)
	}

	// Resolve the scanned-digest set: an explicit set in the input wins; otherwise consult the store
	// (when wired). A lookup failure is a hard error rather than a silent fall-back to "nothing
	// scanned" — that would over-report unscanned gaps and mask the real coverage.
	scanned := in.ScannedDigests
	if scanned == nil && s.scanned != nil {
		var err error
		scanned, err = s.scanned.ScannedDigests(ctx, in.TenantID)
		if err != nil {
			return nil, fmt.Errorf("cluster inventory: scanned digests: %w", err)
		}
	}

	inv := dci.Map(in.Snapshot, scanned)

	// Upsert every observed asset first, recording the resolved id per natural-key ref so edges can be
	// wired. UpsertAsset resolves the stable id by (tenant, kind, key).
	refToID := make(map[dci.AssetRef]shared.ID, len(inv.Assets))
	for _, oa := range inv.Assets {
		a, err := s.assets.UpsertAsset(ctx, actor, assetuc.UpsertAssetInput{
			TenantID:   in.TenantID,
			Kind:       oa.Kind,
			Key:        oa.Key,
			Name:       oa.Name,
			Attributes: oa.Attributes,
		})
		if err != nil {
			return nil, fmt.Errorf("cluster inventory: upsert asset %s/%s: %w", oa.Kind, oa.Key, err)
		}
		refToID[oa.Ref()] = a.ID
	}

	edges := 0
	for _, e := range inv.Edges {
		from, okFrom := refToID[e.From]
		to, okTo := refToID[e.To]
		if !okFrom || !okTo {
			// The mapper only emits edges between observed assets, so an unresolved endpoint means that
			// invariant broke (a mapper bug/refactor). Fail loud rather than silently drop an attack-path
			// edge — a silently incomplete graph is exactly the failure this platform must not produce.
			return nil, fmt.Errorf("%w: cluster inventory: edge %s has an unresolved endpoint", shared.ErrValidation, e.Kind)
		}
		if err := s.assets.UpsertEdge(ctx, actor, assetuc.EdgeInput{
			TenantID:   in.TenantID,
			From:       from,
			To:         to,
			Kind:       e.Kind,
			Provenance: in.Provenance,
			Confidence: asset.EdgeObserved,
		}); err != nil {
			return nil, fmt.Errorf("cluster inventory: upsert edge %s: %w", e.Kind, err)
		}
		edges++
	}

	// Audit the coverage gaps so a partial inventory is durably attributable, not just returned.
	now := s.clock.Now()
	for _, g := range inv.Gaps {
		if err := s.audit.Record(ctx, ports.AuditEntry{
			Actor:  actor,
			Action: "cluster_inventory.coverage_gap",
			Target: g.Workload,
			Metadata: map[string]string{
				"tenant_id": in.TenantID.String(),
				"cluster":   inv.Cluster,
				"gap_kind":  string(g.Kind),
				"detail":    g.Detail,
			},
			At: now,
		}); err != nil {
			return nil, fmt.Errorf("cluster inventory: audit coverage gap: %w", err)
		}
	}

	return &SyncResult{Assets: len(inv.Assets), Edges: edges, Gaps: inv.Gaps}, nil
}
