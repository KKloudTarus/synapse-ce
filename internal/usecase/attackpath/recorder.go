package attackpath

import (
	"context"
	"errors"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	ap "github.com/KKloudTarus/synapse-ce/internal/domain/attackpath"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Recorder writes producer-owned finding attribution. It never guesses from finding prose.
type Recorder struct {
	assets      ports.AssetRepository
	store       ports.AttackPathStore
	engagements ports.EngagementRepository
}

func NewRecorder(assets ports.AssetRepository, store ports.AttackPathStore, engagements ports.EngagementRepository) (*Recorder, error) {
	if assets == nil || store == nil || engagements == nil {
		return nil, fmt.Errorf("%w: attack path recorder needs assets, store, and engagements", shared.ErrValidation)
	}
	return &Recorder{assets: assets, store: store, engagements: engagements}, nil
}

var _ ports.FindingAttributor = (*Recorder)(nil)

func (r *Recorder) tenantID(ctx context.Context, engagementID shared.ID) (shared.ID, error) {
	eng, err := r.engagements.GetByID(ctx, engagementID)
	if err != nil {
		return "", fmt.Errorf("load attribution engagement: %w", err)
	}
	return shared.TenantOrDefault(eng.TenantID), nil
}

// ValidateAsset proves that assetID belongs to the finding's engagement tenant.
func (r *Recorder) ValidateAsset(ctx context.Context, engagementID, assetID shared.ID) error {
	if engagementID.IsZero() || assetID.IsZero() {
		return fmt.Errorf("%w: attribution requires engagement and asset", shared.ErrValidation)
	}
	tenantID, err := r.tenantID(ctx, engagementID)
	if err != nil {
		return err
	}
	assets, err := r.assets.ListAssets(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("list binding assets: %w", err)
	}
	for _, a := range assets {
		if a.ID == assetID {
			return nil
		}
	}
	return fmt.Errorf("asset %s: %w", assetID, shared.ErrNotFound)
}

// Record replaces this producer's complete observation after its canonical findings are persisted.
func (r *Recorder) Record(ctx context.Context, engagementID, assetID, producer, provenance shared.ID, confidence asset.EdgeConfidence, findingIDs []shared.ID) error {
	targets := make([]ap.FindingTarget, 0, len(findingIDs))
	for _, findingID := range findingIDs {
		targets = append(targets, ap.FindingTarget{ID: findingID, Kind: ap.TargetCanonical})
	}
	return r.RecordTargets(ctx, engagementID, assetID, producer, provenance, confidence, targets)
}

// RecordTargets replaces this producer's complete observation after its typed targets are persisted.
func (r *Recorder) RecordTargets(ctx context.Context, engagementID, assetID, producer, provenance shared.ID, confidence asset.EdgeConfidence, targets []ap.FindingTarget) error {
	if producer.IsZero() || provenance.IsZero() || !confidence.Valid() {
		return fmt.Errorf("%w: attribution requires producer, provenance, and confidence", shared.ErrValidation)
	}
	if err := r.ValidateAsset(ctx, engagementID, assetID); err != nil {
		return err
	}
	tenantID, err := r.tenantID(ctx, engagementID)
	if err != nil {
		return err
	}
	bindings := make([]ap.Binding, 0, len(targets))
	for _, target := range targets {
		if target.ID.IsZero() || !target.Kind.Valid() {
			return fmt.Errorf("%w: attribution requires typed finding targets", shared.ErrValidation)
		}
		bindings = append(bindings, ap.Binding{TenantID: tenantID, EngagementID: engagementID, AssetID: assetID, FindingID: target.ID, TargetKind: target.Kind, Producer: producer, Provenance: provenance, Confidence: confidence})
	}
	return r.store.ReplaceBindings(ctx, tenantID, engagementID, producer, bindings)
}

// InheritedAssetID returns an asset only when every referenced finding has exactly one common binding.
func (r *Recorder) InheritedAssetID(ctx context.Context, engagementID shared.ID, findingIDs []shared.ID) (shared.ID, error) {
	if len(findingIDs) == 0 {
		return "", fmt.Errorf("%w: finding attribution needs referenced findings", shared.ErrValidation)
	}
	tenantID, err := r.tenantID(ctx, engagementID)
	if err != nil {
		return "", err
	}
	bindings, err := r.store.ListBindings(ctx, tenantID)
	if err != nil {
		return "", fmt.Errorf("list inherited bindings: %w", err)
	}
	common := map[shared.ID]bool{}
	for i, findingID := range findingIDs {
		assets := map[shared.ID]bool{}
		for _, b := range bindings {
			if b.EngagementID == engagementID && b.FindingID == findingID {
				assets[b.AssetID] = true
			}
		}
		if len(assets) != 1 {
			return "", fmt.Errorf("%w: finding %s has no unambiguous asset attribution", shared.ErrValidation, findingID)
		}
		if i == 0 {
			common = assets
			continue
		}
		for id := range common {
			if !assets[id] {
				delete(common, id)
			}
		}
	}
	if len(common) != 1 {
		return "", fmt.Errorf("%w: referenced findings do not share one attributed asset", shared.ErrValidation)
	}
	for id := range common {
		return id, nil
	}
	return "", errors.New("unreachable")
}

func (r *Recorder) AssetIDByKey(ctx context.Context, tenantID shared.ID, kind asset.Kind, key string) (shared.ID, error) {
	a, err := r.assets.GetAssetByKey(ctx, shared.TenantOrDefault(tenantID), kind, key)
	if errors.Is(err, shared.ErrNotFound) {
		return "", err
	}
	if err != nil {
		return "", fmt.Errorf("resolve binding asset: %w", err)
	}
	return a.ID, nil
}
