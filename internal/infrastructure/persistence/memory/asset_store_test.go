package memory

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	dhi "github.com/KKloudTarus/synapse-ce/internal/domain/hostinventory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func hostFor(t *testing.T, tenant shared.ID, id, key, agent string) *asset.Asset {
	t.Helper()
	attrs := map[string]string{}
	if agent != "" {
		attrs["reporting_agent_id"] = agent
	}
	a, err := asset.New(shared.ID(id), tenant, asset.KindHost, key, key, attrs, time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// TestAssetStoreRefusesHostsPastTheAgentCap mirrors the fleet_assets trigger (migration 0132): a new
// host row for an agent that already reports MaxHostsPerAgent hosts is refused as forbidden; an owned
// host still re-syncs; another agent, another tenant, and a host without a reporting agent are not
// counted against it.
func TestAssetStoreRefusesHostsPastTheAgentCap(t *testing.T) {
	ctx := context.Background()
	store := NewAssetStore()
	for i := 0; i < dhi.MaxHostsPerAgent; i++ {
		if err := store.UpsertAsset(ctx, hostFor(t, "tenant-a", fmt.Sprintf("h-%d", i), fmt.Sprintf("machine-id/%d", i), "agent-1")); err != nil {
			t.Fatalf("host %d: %v", i, err)
		}
	}
	if err := store.UpsertAsset(ctx, hostFor(t, "tenant-a", "h-extra", "machine-id/extra", "agent-1")); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("host past the cap accepted: %v", err)
	}
	if err := store.UpsertAsset(ctx, hostFor(t, "tenant-a", "h-0", "machine-id/0", "agent-1")); err != nil {
		t.Fatalf("re-sync of an owned host refused: %v", err)
	}
	if err := store.UpsertAsset(ctx, hostFor(t, "tenant-a", "h-b", "machine-id/b", "agent-2")); err != nil {
		t.Fatalf("second agent refused: %v", err)
	}
	if err := store.UpsertAsset(ctx, hostFor(t, "tenant-b", "h-t2", "machine-id/0", "agent-1")); err != nil {
		t.Fatalf("same agent id in another tenant refused: %v", err)
	}
	if err := store.UpsertAsset(ctx, hostFor(t, "tenant-a", "h-anon", "hostname/anon", "")); err != nil {
		t.Fatalf("host without a reporting agent refused: %v", err)
	}
}

// TestAssetStoreHostCapHoldsUnderConcurrentFirstObservations is the race the use-case count cannot
// close: N syncs for new keys arrive at cap-1 at once. Exactly one row is admitted.
func TestAssetStoreHostCapHoldsUnderConcurrentFirstObservations(t *testing.T) {
	ctx := context.Background()
	store := NewAssetStore()
	for i := 0; i < dhi.MaxHostsPerAgent-1; i++ {
		if err := store.UpsertAsset(ctx, hostFor(t, "tenant-a", fmt.Sprintf("h-%d", i), fmt.Sprintf("machine-id/%d", i), "agent-1")); err != nil {
			t.Fatalf("host %d: %v", i, err)
		}
	}
	var wg sync.WaitGroup
	var accepted atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := store.UpsertAsset(ctx, hostFor(t, "tenant-a", fmt.Sprintf("race-%d", i), fmt.Sprintf("machine-id/race-%d", i), "agent-1")); err == nil {
				accepted.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("%d racing hosts admitted, want exactly 1", accepted.Load())
	}
	all, err := store.ListAssets(ctx, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != dhi.MaxHostsPerAgent {
		t.Fatalf("%d hosts stored, want %d", len(all), dhi.MaxHostsPerAgent)
	}
}
