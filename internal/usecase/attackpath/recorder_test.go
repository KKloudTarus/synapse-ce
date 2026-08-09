package attackpath

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
)

func TestRecorderRequiresKnownAssetAndReplacesBindings(t *testing.T) {
	ctx := context.Background()
	assets := memory.NewAssetStore()
	store := memory.NewAttackPathStore()
	engagements := memory.NewEngagementRepository()
	eng, _ := engagement.New("eng", "tenant", "eng", "client", time.Unix(0, 0))
	if err := engagements.Create(ctx, eng); err != nil {
		t.Fatal(err)
	}
	recorder, err := NewRecorder(assets, store, engagements)
	if err != nil {
		t.Fatal(err)
	}
	if err := recorder.Record(ctx, "eng", "missing", "scan", "scan", asset.EdgeObserved, []shared.ID{"finding"}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing asset error = %v, want not found", err)
	}
	if err := assets.UpsertAsset(ctx, &asset.Asset{ID: "asset", TenantID: "tenant", Kind: asset.KindImage, Key: "sha256:1", Name: "image"}); err != nil {
		t.Fatal(err)
	}
	if err := recorder.Record(ctx, "eng", "asset", "scan", "scan", asset.EdgeObserved, []shared.ID{"finding"}); err != nil {
		t.Fatal(err)
	}
	if err := recorder.Record(ctx, "eng", "asset", "scan", "scan", asset.EdgeObserved, []shared.ID{"replacement"}); err != nil {
		t.Fatal(err)
	}
	got, err := store.ListBindings(ctx, "tenant")
	if err != nil || len(got) != 1 || got[0].FindingID != "replacement" {
		t.Fatalf("bindings = %#v, %v", got, err)
	}
}
