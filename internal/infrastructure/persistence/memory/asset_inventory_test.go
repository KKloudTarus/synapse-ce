package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestAssetInventoryTenantIsolationAndSharedLinks(t *testing.T) {
	repo := NewAssetInventoryRepository()
	now := time.Now().UTC()
	ctxA := shared.WithTenant(context.Background(), "tenant-a")
	ctxB := shared.WithTenant(context.Background(), "tenant-b")
	a, err := asset.New("asset-a", "tenant-a", "Payments API", asset.CategoryAPI, asset.Identity{Kind: "url", Value: "https://payments.example.test"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateAsset(ctxA, a); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetAsset(ctxB, a.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant asset error=%v", err)
	}
	for _, id := range []shared.ID{"service-a", "service-a-2"} {
		service := asset.BusinessService{ID: id, TenantID: "tenant-a", Name: id.String(), Criticality: asset.CriticalityHigh, Lifecycle: asset.LifecycleActive, Audit: shared.Audit{CreatedAt: now, UpdatedAt: now}}
		if err := repo.CreateBusinessService(ctxA, service); err != nil {
			t.Fatal(err)
		}
		if err := repo.LinkBusinessServiceAsset(ctxA, asset.BusinessServiceAssetLink{BusinessServiceID: id, AssetID: a.ID, Role: asset.AssetLinkUses, CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	links, err := repo.ListBusinessServiceAssets(ctxA, "service-a")
	if err != nil || len(links) != 1 || links[0].AssetID != a.ID {
		t.Fatalf("links=%+v err=%v", links, err)
	}
}

func TestAssetInventoryRejectsContainmentCycle(t *testing.T) {
	repo := NewAssetInventoryRepository()
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	now := time.Now().UTC()
	for _, id := range []shared.ID{"a", "b"} {
		a, _ := asset.New(id, "tenant-a", id.String(), asset.CategoryService, asset.Identity{Kind: "name", Value: id.String()}, now)
		if err := repo.CreateAsset(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	if err := repo.CreateRelationship(ctx, asset.Relationship{ID: "ab", TenantID: "tenant-a", FromAssetID: "a", ToAssetID: "b", Type: asset.RelationshipContains, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateRelationship(ctx, asset.Relationship{ID: "ba", TenantID: "tenant-a", FromAssetID: "b", ToAssetID: "a", Type: asset.RelationshipContains, CreatedAt: now}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("cycle error=%v", err)
	}
}

func TestDeleteAssetRemovesIncomingRelationships(t *testing.T) {
	repo := NewAssetInventoryRepository()
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	now := time.Now().UTC()
	for _, id := range []shared.ID{"a", "b"} {
		item, err := asset.New(id, "tenant-a", id.String(), asset.CategoryService, asset.Identity{Kind: "name", Value: id.String()}, now)
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.CreateAsset(ctx, item); err != nil {
			t.Fatal(err)
		}
	}
	if err := repo.CreateRelationship(ctx, asset.Relationship{ID: "ab", TenantID: "tenant-a", FromAssetID: "a", ToAssetID: "b", Type: asset.RelationshipDependsOn, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := repo.DeleteAsset(ctx, "b"); err != nil {
		t.Fatal(err)
	}
	relationships, err := repo.ListRelationships(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	if len(relationships) != 0 {
		t.Fatalf("relationships=%+v, want none", relationships)
	}
}
