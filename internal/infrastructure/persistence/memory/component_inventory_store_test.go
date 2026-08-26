package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestComponentInventoryStoreUsesLatestSBOMAndCursor(t *testing.T) {
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	store := NewComponentInventoryStore(
		inventoryRecord("tenant-a", "eng-1", "sbom-old", "component-old", now, "old", "resolved"),
		inventoryRecord("tenant-a", "eng-1", "sbom-new", "component-b", now.Add(time.Hour), "b", "resolved"),
		inventoryRecord("tenant-a", "eng-1", "sbom-new", "component-a", now.Add(time.Hour), "a", "resolved"),
		inventoryRecord("tenant-a", "eng-1", "sbom-new", "component-unsupported", now.Add(time.Hour), "unsupported", "unsupported"),
		inventoryRecord("tenant-b", "eng-1", "sbom-other", "component-other", now.Add(2*time.Hour), "other", "resolved"),
	)
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	page, err := store.ListCurrentComponents(ctx, sbom.ComponentQuery{TenantID: "tenant-a", EngagementID: "eng-1", Ecosystem: "Go", Package: "example.com/pkg", Limit: 1})
	if err != nil {
		t.Fatalf("first page: %v", err)
	}
	if len(page.Items) != 1 || page.Items[0].ComponentID != "component-b" || page.Next == nil {
		t.Fatalf("first page = %+v", page)
	}
	next, err := store.ListCurrentComponents(ctx, sbom.ComponentQuery{TenantID: "tenant-a", EngagementID: "eng-1", Ecosystem: "Go", Package: "example.com/pkg", Cursor: *page.Next, Limit: 1})
	if err != nil {
		t.Fatalf("second page: %v", err)
	}
	if len(next.Items) != 1 || next.Items[0].ComponentID != "component-a" || next.Next != nil {
		t.Fatalf("second page = %+v", next)
	}
}

func TestComponentInventoryStoreRejectsCrossTenantQuery(t *testing.T) {
	store := NewComponentInventoryStore()
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	_, err := store.ListCurrentComponents(ctx, sbom.ComponentQuery{TenantID: "tenant-b", EngagementID: "eng-1", Ecosystem: "Go", Package: "example.com/pkg"})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("err=%v", err)
	}
}

func inventoryRecord(tenantID, engagementID, sbomID, componentID string, createdAt time.Time, packageName, status string) sbom.ComponentRecord {
	return sbom.ComponentRecord{TenantID: shared.ID(tenantID), EngagementID: shared.ID(engagementID), SBOMID: shared.ID(sbomID), ComponentID: shared.ID(componentID), Name: packageName, Version: "1.0.0", PURL: "pkg:golang/example.com/pkg@1.0.0", Ecosystem: "Go", Package: "example.com/pkg", IdentityHash: componentID, IdentityStatus: status, SBOMCreatedAt: createdAt}
}

func TestComponentInventoryStoreListByEngagement(t *testing.T) {
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	store := NewComponentInventoryStore(
		inventoryRecord("tenant-a", "eng-1", "sbom-old", "comp-stale", now, "stale", "resolved"),        // older SBOM
		inventoryRecord("tenant-a", "eng-1", "sbom-new", "comp-b", now.Add(time.Hour), "b", "resolved"), // latest SBOM
		inventoryRecord("tenant-a", "eng-1", "sbom-new", "comp-a", now.Add(time.Hour), "a", "resolved"), // latest SBOM
		inventoryRecord("tenant-a", "eng-2", "sbom-2", "comp-other-eng", now, "x", "resolved"),
		inventoryRecord("tenant-b", "eng-1", "sbom-3", "comp-other-tenant", now, "y", "resolved"),
	)
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	got, err := store.ListCurrentComponentsByEngagement(ctx, "tenant-a", "eng-1")
	if err != nil {
		t.Fatal(err)
	}
	// Only the LATEST SBOM's components (comp-stale from sbom-old excluded), deduped, ordered by ComponentID.
	if len(got) != 2 || got[0].ComponentID != "comp-a" || got[1].ComponentID != "comp-b" {
		t.Fatalf("list-by-engagement must return only the latest SBOM: %+v", got)
	}
	for _, r := range got {
		if r.EngagementID != "eng-1" || r.TenantID != "tenant-a" {
			t.Fatalf("leaked a foreign record: %+v", r)
		}
	}
	if _, err := store.ListCurrentComponentsByEngagement(ctx, "", "eng-1"); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("missing tenant must be rejected")
	}
	// ctx-tenant must match the requested tenant (defense-in-depth).
	if _, err := store.ListCurrentComponentsByEngagement(ctx, "tenant-b", "eng-1"); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("ctx/param tenant mismatch must be rejected")
	}
}
