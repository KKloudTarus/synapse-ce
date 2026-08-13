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
	old := &sbom.SBOM{Components: []sbom.Component{{Name: "example.com/pkg", Version: "1.0.0", PURL: "pkg:golang/example.com/pkg@1.0.0"}}, Audit: shared.Audit{CreatedAt: now}}
	if _, err := repo.SaveScan(ctx, "eng-1", old, nil, ports.ScanSnapshot{}); err != nil {
		t.Fatal(err)
	}
	latest := &sbom.SBOM{Components: []sbom.Component{{Name: "example.com/pkg", Version: "2.0.0", PURL: "pkg:golang/example.com/pkg@2.0.0"}}, Audit: shared.Audit{CreatedAt: now.Add(time.Hour)}}
	skipped, err := repo.SaveScan(ctx, "eng-1", latest, []vulnerability.Vulnerability{{Component: "missing", Version: "1.0.0"}}, ports.ScanSnapshot{})
	if err != nil || skipped != 1 {
		t.Fatalf("save latest skipped=%d err=%v", skipped, err)
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
