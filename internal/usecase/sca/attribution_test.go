package sca

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/attackpath"
	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type captureAttributor struct {
	assetID    shared.ID
	provenance shared.ID
	confidence asset.EdgeConfidence
	findingIDs []shared.ID
	err        error
}

func (*captureAttributor) ValidateAsset(context.Context, shared.ID, shared.ID) error { return nil }

func (a *captureAttributor) Record(_ context.Context, _ shared.ID, assetID, _, provenance shared.ID, confidence asset.EdgeConfidence, findingIDs []shared.ID) error {
	a.assetID, a.provenance, a.confidence = assetID, provenance, confidence
	a.findingIDs = append([]shared.ID(nil), findingIDs...)
	return a.err
}

func (a *captureAttributor) RecordTargets(_ context.Context, _ shared.ID, assetID, _, provenance shared.ID, confidence asset.EdgeConfidence, targets []attackpath.FindingTarget) error {
	a.assetID, a.provenance, a.confidence = assetID, provenance, confidence
	a.findingIDs = a.findingIDs[:0]
	for _, target := range targets {
		a.findingIDs = append(a.findingIDs, target.ID)
	}
	return a.err
}

func (*captureAttributor) InheritedAssetID(context.Context, shared.ID, []shared.ID) (shared.ID, error) {
	return "", shared.ErrNotFound
}

func attributionService(t *testing.T, assets ports.AssetRepository, attributor ports.FindingAttributor) *Service {
	t.Helper()
	svc := newSvc(&fakeEngRepo{eng: func() *engdom.Engagement {
		e, err := engdom.New("e1", "tenant-1", "test", "", time.Unix(0, 0).UTC())
		if err != nil {
			t.Fatal(err)
		}
		return e
	}()}, fakeClock{t: time.Unix(1, 0).UTC()}, &fakeAcquirer{dir: t.TempDir()}, &fakeAudit{}, &fakeDetector{})
	svc.ids = fakeIDs{}
	if err := svc.SetFindingAttribution(assets, attributor); err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestAttributeFindingsImageUsesResolvedManifestDigest(t *testing.T) {
	assets := memory.NewAssetStore()
	recorder := &captureAttributor{}
	svc := attributionService(t, assets, recorder)
	digest := "sha256:" + strings.Repeat("a", 64)
	result := &ScanResult{
		Image:       &sbom.ImageInfo{Reference: "registry.example/app:latest", Digest: digest},
		ReproDigest: "repro-image",
		Findings:    []finding.Finding{{ID: "finding-image", EngagementID: "e1"}},
	}

	if err := svc.attributeFindings(context.Background(), "e1", "registry.example/app:latest", result); err != nil {
		t.Fatal(err)
	}
	stored, err := assets.GetAssetByKey(context.Background(), "tenant-1", asset.KindImage, digest)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Name != "registry.example/app:latest" || recorder.assetID != stored.ID || recorder.provenance != "repro-image" || recorder.confidence != asset.EdgeObserved {
		t.Fatalf("image attribution asset=%+v recorder=%+v", stored, recorder)
	}
	if len(recorder.findingIDs) != 1 || recorder.findingIDs[0] != "finding-image" {
		t.Fatalf("image finding IDs = %v", recorder.findingIDs)
	}
}

func TestAttributeFindingsRepositoryUsesNormalizedTargetAndExistingAsset(t *testing.T) {
	assets := memory.NewAssetStore()
	recorder := &captureAttributor{}
	svc := attributionService(t, assets, recorder)
	target := normalizedSourceTarget(ports.AcquireRequest{Kind: ports.TargetLocal, Value: filepath.Join(t.TempDir(), "repo", "..", "repo")})
	existing, err := asset.New("repository-asset", "tenant-1", asset.KindRepository, target, "repository", nil, time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := assets.UpsertAsset(context.Background(), existing); err != nil {
		t.Fatal(err)
	}
	result := &ScanResult{ReproDigest: "repro-repository", Findings: []finding.Finding{{ID: "finding-repository", EngagementID: "e1"}}}

	if err := svc.attributeFindings(context.Background(), "e1", target, result); err != nil {
		t.Fatal(err)
	}
	if recorder.assetID != existing.ID || recorder.provenance != "repro-repository" || recorder.confidence != asset.EdgeObserved {
		t.Fatalf("repository attribution recorder=%+v", recorder)
	}
	if got, err := assets.GetAssetByKey(context.Background(), "tenant-1", asset.KindRepository, target); err != nil || got.ID != existing.ID {
		t.Fatalf("repository asset = %+v, %v", got, err)
	}
}

func TestAttributeFindingsRejectsInvalidImageDigestAndRecorderFailure(t *testing.T) {
	ctx := context.Background()
	assets := memory.NewAssetStore()
	recorder := &captureAttributor{}
	svc := attributionService(t, assets, recorder)
	bad := &ScanResult{Image: &sbom.ImageInfo{Reference: "registry.example/app:latest", Digest: "registry.example/app:latest"}, ReproDigest: "repro", Findings: []finding.Finding{{ID: "finding", EngagementID: "e1"}}}
	if err := svc.attributeFindings(ctx, "e1", "ignored", bad); !errors.Is(err, shared.ErrValidation) || recorder.assetID != "" {
		t.Fatalf("invalid digest error=%v recorder=%+v", err, recorder)
	}

	recorder.err = errors.New("attack path unavailable")
	result := &ScanResult{ReproDigest: "repro", Findings: []finding.Finding{{ID: "finding", EngagementID: "e1"}}}
	err := svc.attributeFindings(ctx, "e1", "https://example.test/repository", result)
	var partial *ports.PartialWriteError
	if !errors.As(err, &partial) || len(partial.IDs) != 1 || partial.IDs[0] != "finding" {
		t.Fatalf("recorder failure error=%v", err)
	}
	recorder.err = nil
	if err := svc.attributeFindings(ctx, "e1", "https://example.test/repository", result); err != nil || recorder.findingIDs[0] != "finding" {
		t.Fatalf("retry attribution error=%v recorder=%+v", err, recorder)
	}
}
