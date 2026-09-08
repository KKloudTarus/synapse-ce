package memory

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sourcepackage"
)

func TestEngagementSourceRepositoryTenantScopedVersionsAndReplay(t *testing.T) {
	ctx := context.Background()
	repo := NewEngagementSourceRepository()
	now := time.Now().UTC().Truncate(time.Microsecond)
	item := sourcepackage.Package{TenantID: "tenant-a", EngagementID: "eng-a", VersionID: shared.ID(strings.Repeat("a", 32)), Filename: "source.zip", Size: 10, SHA256: strings.Repeat("b", 64), CreatedBy: "alice", CreatedAt: now, AssociatedBy: "alice", AssociatedAt: now, Locator: "tenant-a/eng-a/version", ObjectKey: "tenant-a/eng-a/version/archive.zip"}
	if _, created, err := repo.Create(ctx, item); err != nil || !created {
		t.Fatalf("initial create = %v %v", created, err)
	}
	if _, created, err := repo.Create(ctx, item); err != nil || created {
		t.Fatalf("idempotent create = %v %v", created, err)
	}
	other := item
	other.TenantID, other.EngagementID = "tenant-b", "eng-b"
	other.Locator, other.ObjectKey = "tenant-b/eng-b/version", "tenant-b/eng-b/version/archive.zip"
	if _, created, err := repo.Create(ctx, other); err != nil || !created {
		t.Fatalf("same opaque version in another tenant = %v %v", created, err)
	}
	for _, expected := range []sourcepackage.Package{item, other} {
		if got, err := repo.GetByVersion(ctx, expected.TenantID, expected.EngagementID, expected.VersionID); err != nil || got != expected {
			t.Fatalf("tenant version overwritten: %+v %v", got, err)
		}
	}
	changed := item
	changed.CreatedBy = "forged"
	if _, _, err := repo.Create(ctx, changed); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("immutable replay mutation = %v", err)
	}
	if _, err := repo.GetByLocator(ctx, "tenant-b", item.Locator); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant locator = %v", err)
	}
}
