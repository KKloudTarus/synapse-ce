package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestAssetStoreGetAssetByIDTenantIsolationAndCopy(t *testing.T) {
	ctx := context.Background()
	store := NewAssetStore()
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	a, err := asset.New("asset-a", "tenant-a", asset.KindHost, "machine-id/a", "host-a", map[string]string{"k": "v"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertAsset(ctx, a); err != nil {
		t.Fatal(err)
	}

	got, err := store.GetAssetByID(ctx, "tenant-a", "asset-a")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "asset-a" || got.TenantID != "tenant-a" || got.Kind != asset.KindHost {
		t.Fatalf("unexpected asset: %+v", got)
	}
	got.Attributes["k"] = "mutated"
	again, err := store.GetAssetByID(ctx, "tenant-a", "asset-a")
	if err != nil {
		t.Fatal(err)
	}
	if again.Attributes["k"] != "v" {
		t.Fatalf("caller mutated stored attributes: %+v", again.Attributes)
	}
	if _, err := store.GetAssetByID(ctx, "tenant-b", "asset-a"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant lookup=%v, want ErrNotFound", err)
	}
	for _, tc := range []struct {
		tenant shared.ID
		id     shared.ID
	}{
		{id: "asset-a"},
		{tenant: "tenant-a"},
	} {
		if _, err := store.GetAssetByID(ctx, tc.tenant, tc.id); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("invalid lookup tenant=%q id=%q error=%v, want ErrValidation", tc.tenant, tc.id, err)
		}
	}
}

func TestAssetStoreGetAssetByIDRejectsDuplicateCanonicalID(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

	t.Run("within tenant", func(t *testing.T) {
		store := NewAssetStore()
		for _, key := range []string{"machine-id/a", "machine-id/b"} {
			a, err := asset.New("asset-duplicate", "tenant-a", asset.KindHost, key, key, nil, now)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.UpsertAsset(ctx, a); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := store.GetAssetByID(ctx, "tenant-a", "asset-duplicate"); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("duplicate canonical id lookup=%v, want ErrValidation", err)
		}
	})

	t.Run("across tenants", func(t *testing.T) {
		store := NewAssetStore()
		for _, tc := range []struct {
			tenant shared.ID
			key    string
		}{
			{tenant: "tenant-a", key: "machine-id/a"},
			{tenant: "tenant-b", key: "machine-id/b"},
		} {
			a, err := asset.New("asset-global-duplicate", tc.tenant, asset.KindHost, tc.key, tc.key, nil, now)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.UpsertAsset(ctx, a); err != nil {
				t.Fatal(err)
			}
		}
		for _, tenant := range []shared.ID{"tenant-a", "tenant-b"} {
			if _, err := store.GetAssetByID(ctx, tenant, "asset-global-duplicate"); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("global duplicate lookup tenant=%s error=%v, want ErrValidation", tenant, err)
			}
		}
	})
}
