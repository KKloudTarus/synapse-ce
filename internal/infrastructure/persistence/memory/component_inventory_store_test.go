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
