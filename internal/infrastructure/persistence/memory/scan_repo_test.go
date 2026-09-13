package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestScanRepositoryPersistsLatestComponentInventory(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	inventory := NewComponentInventoryStore()
	repo := NewScanRepository(inventory)
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	old := &sbom.SBOM{TargetRef: "repo", Components: []sbom.Component{{Name: "example.com/pkg", Version: "1.0.0", PURL: "pkg:golang/example.com/pkg@1.0.0"}}, Audit: shared.Audit{CreatedAt: now}}
	if _, err := repo.SaveScan(ctx, "eng-1", old, nil, ports.ScanSnapshot{}); err != nil {
		t.Fatal(err)
	}
	latest := &sbom.SBOM{TargetRef: "repo", Components: []sbom.Component{{Name: "example.com/pkg", Version: "2.0.0", PURL: "pkg:golang/example.com/pkg@2.0.0"}}, Audit: shared.Audit{CreatedAt: now.Add(time.Hour)}}
	skipped, err := repo.SaveScan(ctx, "eng-1", latest, []vulnerability.Vulnerability{{Component: "missing", Version: "1.0.0"}}, ports.ScanSnapshot{})
	if err != nil || skipped.SkippedVulnerabilities != 1 {
		t.Fatalf("save latest skipped=%d err=%v", skipped.SkippedVulnerabilities, err)
	}
	page, err := inventory.ListCurrentComponents(ctx, sbom.ComponentQuery{TenantID: "tenant-a", EngagementID: "eng-1", Ecosystem: "Go", Package: "example.com/pkg"})
	if err != nil || len(page.Items) != 1 || page.Items[0].Version != "2.0.0" {
		t.Fatalf("inventory=%+v err=%v", page, err)
	}
}

func TestScanRepositoryRequiresTenant(t *testing.T) {
	_, err := NewScanRepository().SaveScan(context.Background(), "eng-1", &sbom.SBOM{}, nil, ports.ScanSnapshot{})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("err=%v", err)
	}
}

func TestT04T05InventoryPublicationIsCompleteAndAdmissionOrdered(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	inventory := NewComponentInventoryStore()
	repo := NewScanRepository(inventory)
	engagementID := shared.ID("eng-1")
	scope := sbom.InventoryScope("repo")
	base := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)

	first, err := repo.AdmitInventory(ctx, engagementID, scope, base)
	if err != nil {
		t.Fatal(err)
	}
	newer, err := repo.AdmitInventory(ctx, engagementID, scope, base.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	newerSaved, err := repo.SaveScan(ctx, engagementID, inventoryDoc("repo", "2.0.0", base.Add(2*time.Second)), nil, authoritativeSnapshot(newer))
	if err != nil {
		t.Fatal(err)
	}
	if !newerSaved.Publication.Current || newerSaved.Publication.Superseded {
		t.Fatalf("newer publication=%+v", newerSaved.Publication)
	}
	olderSaved, err := repo.SaveScan(ctx, engagementID, inventoryDoc("repo", "1.0.0", base.Add(3*time.Second)), nil, authoritativeSnapshot(first))
	if err != nil {
		t.Fatal(err)
	}
	if olderSaved.Publication.Current || !olderSaved.Publication.Superseded {
		t.Fatalf("out-of-order publication=%+v", olderSaved.Publication)
	}
	current := inventory.current[inventoryScopeKey("tenant-a", engagementID, scope)]
	if current.Generation != newer.Generation || current.SBOMID != newerSaved.Publication.SBOMID {
		t.Fatalf("current pointer=%+v, want generation %d", current, newer.Generation)
	}

	degraded, err := repo.AdmitInventory(ctx, engagementID, scope, base.Add(4*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	degradedSaved, err := repo.SaveScan(ctx, engagementID, &sbom.SBOM{TargetRef: "repo", Audit: shared.Audit{CreatedAt: base.Add(5 * time.Second)}}, nil,
		ports.ScanSnapshot{InventoryAdmission: degraded, InventoryCompleteness: sbom.InventoryIncomplete, InventoryAuthorityReason: "generator_failed"})
	if err != nil {
		t.Fatal(err)
	}
	if degradedSaved.Publication.Current || degradedSaved.Publication.Superseded {
		t.Fatalf("degraded publication=%+v", degradedSaved.Publication)
	}
	if got := inventory.current[inventoryScopeKey("tenant-a", engagementID, scope)]; got.Generation != newer.Generation {
		t.Fatalf("degraded empty inventory replaced pointer: %+v", got)
	}

	empty, err := repo.AdmitInventory(ctx, engagementID, scope, base.Add(6*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	emptySaved, err := repo.SaveScan(ctx, engagementID, &sbom.SBOM{TargetRef: "repo", Audit: shared.Audit{CreatedAt: base.Add(7 * time.Second)}}, nil, authoritativeSnapshot(empty))
	if err != nil {
		t.Fatal(err)
	}
	if !emptySaved.Publication.Current || emptySaved.Publication.Coverage.Total != 0 {
		t.Fatalf("complete empty publication=%+v", emptySaved.Publication)
	}
}

func TestT07PinnedSnapshotTraversalRejectsCrossScopeAndGeneration(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	inventory := NewComponentInventoryStore()
	repo := NewScanRepository(inventory)
	now := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	scope := sbom.InventoryScope("repo")
	admission, err := repo.AdmitInventory(ctx, "eng-1", scope, now)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := repo.SaveScan(ctx, "eng-1", inventoryDoc("repo", "1.0.0", now), nil, authoritativeSnapshot(admission))
	if err != nil {
		t.Fatal(err)
	}
	page, err := inventory.ListSnapshotComponents(ctx, sbom.SnapshotQuery{TenantID: "tenant-a", EngagementID: "eng-1", SBOMID: saved.Publication.SBOMID,
		InventoryScope: scope, InventoryGeneration: admission.Generation, Limit: 1})
	if err != nil || len(page.Items) != 1 || page.Items[0].InventoryGeneration != admission.Generation {
		t.Fatalf("pinned page=%+v err=%v", page, err)
	}
	wrong, err := inventory.ListSnapshotComponents(ctx, sbom.SnapshotQuery{TenantID: "tenant-a", EngagementID: "eng-1", SBOMID: saved.Publication.SBOMID,
		InventoryScope: sbom.InventoryScope("other"), InventoryGeneration: admission.Generation, Limit: 1})
	if err != nil || len(wrong.Items) != 0 {
		t.Fatalf("cross-scope page=%+v err=%v", wrong, err)
	}
	if _, err := inventory.ListCurrentComponents(ctx, sbom.ComponentQuery{TenantID: "tenant-a", EngagementID: "eng-1", Ecosystem: "Go", Package: "example.com/pkg",
		SBOMID: saved.Publication.SBOMID, InventoryScope: scope}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("partial pin err=%v", err)
	}
}

func inventoryDoc(target, version string, createdAt time.Time) *sbom.SBOM {
	return &sbom.SBOM{TargetRef: target, Components: []sbom.Component{{Name: "example.com/pkg", Version: version, PURL: "pkg:golang/example.com/pkg@" + version}}, Audit: shared.Audit{CreatedAt: createdAt}}
}

func authoritativeSnapshot(admission sbom.InventoryAdmission) ports.ScanSnapshot {
	return ports.ScanSnapshot{InventoryAdmission: admission, InventoryCompleteness: sbom.InventoryComplete, InventoryAuthoritative: true, InventoryAuthorityReason: "test_complete"}
}
