package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	dhi "github.com/KKloudTarus/synapse-ce/internal/domain/hostinventory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TestMigration0132CapMatchesDomainConstant pins the number in the trigger to
// hostinventory.MaxHostsPerAgent without a database: the two are edited together or the build fails.
func TestMigration0132CapMatchesDomainConstant(t *testing.T) {
	sql, err := os.ReadFile("../../../../migrations/0132_fleet_assets_host_cap.sql")
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("IF owned >= %d THEN", dhi.MaxHostsPerAgent); !strings.Contains(string(sql), want) {
		t.Fatalf("migration 0132 does not enforce %d hosts per agent (want %q)", dhi.MaxHostsPerAgent, want)
	}
}

// TestMigration0132HostCapTrigger asserts the trigger exists and drives the backstop the host
// inventory use case relies on: the host past the cap for one agent is refused as ErrForbidden, an
// owned host still re-syncs, another agent and a host without a reporting agent are unaffected, and
// concurrent first observations at cap-1 admit exactly one row.
func TestMigration0132HostCapTrigger(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	var tgname string
	if err := pool.QueryRow(ctx, `SELECT tgname FROM pg_trigger WHERE tgname='fleet_assets_guard_host_cap' AND NOT tgisinternal`).Scan(&tgname); err != nil {
		t.Fatalf("fleet_assets_guard_host_cap trigger missing: %v", err)
	}

	suffix := randHex(t)
	tenant := shared.ID("t-0132-" + suffix)
	agentA, agentB := "agent-a-"+suffix, "agent-b-"+suffix
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, $1) ON CONFLICT DO NOTHING`, tenant.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	for _, agent := range []string{agentA, agentB} {
		if _, err := pool.Exec(ctx, `INSERT INTO fleet_agents(id,tenant_id,name,token_hash,state) VALUES($1,$2,$1,$3,'active')`, agent, tenant.String(), "hash-"+agent); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM telemetry_asset_bindings WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(ctx, `DELETE FROM fleet_assets WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(ctx, `DELETE FROM fleet_agents WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenant.String())
	})

	assets := NewAssetRepository(pool)
	now := time.Now().UTC().Truncate(time.Microsecond)
	host := func(key, agent string) *asset.Asset {
		attrs := map[string]string{"os": "linux"}
		if agent != "" {
			attrs["reporting_agent_id"] = agent
		}
		a, err := asset.New(shared.ID("h-"+randHex(t)), tenant, asset.KindHost, key, key, attrs, now)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}

	for i := 0; i < dhi.MaxHostsPerAgent; i++ {
		if err := assets.UpsertAsset(ctx, host(fmt.Sprintf("machine-id/%d", i), agentA)); err != nil {
			t.Fatalf("host %d: %v", i, err)
		}
	}
	if err := assets.UpsertAsset(ctx, host("machine-id/extra", agentA)); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("host past the cap accepted: %v", err)
	}
	if err := assets.UpsertAsset(ctx, host("machine-id/0", agentA)); err != nil {
		t.Fatalf("re-sync of an owned host refused: %v", err)
	}
	if err := assets.UpsertAsset(ctx, host("machine-id/b", agentB)); err != nil {
		t.Fatalf("second agent refused: %v", err)
	}
	if err := assets.UpsertAsset(ctx, host("hostname/anon", "")); err != nil {
		t.Fatalf("host without a reporting agent refused: %v", err)
	}

	// Agent B sits at cap-1; eight first observations race for the last slot.
	for i := 1; i < dhi.MaxHostsPerAgent-1; i++ {
		if err := assets.UpsertAsset(ctx, host(fmt.Sprintf("machine-id/b%d", i), agentB)); err != nil {
			t.Fatalf("agent B host %d: %v", i, err)
		}
	}
	var wg sync.WaitGroup
	var accepted, refused atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			err := assets.UpsertAsset(ctx, host(fmt.Sprintf("machine-id/race-%d", i), agentB))
			switch {
			case err == nil:
				accepted.Add(1)
			case errors.Is(err, shared.ErrForbidden):
				refused.Add(1)
			default:
				t.Errorf("racing upsert %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	if accepted.Load() != 1 || refused.Load() != 7 {
		t.Fatalf("accepted=%d refused=%d, want exactly one admitted", accepted.Load(), refused.Load())
	}
	var owned int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM fleet_assets WHERE tenant_id=$1 AND kind='host' AND attributes->>'reporting_agent_id'=$2`, tenant.String(), agentB).Scan(&owned); err != nil {
		t.Fatal(err)
	}
	if owned != dhi.MaxHostsPerAgent {
		t.Fatalf("agent B owns %d hosts, want %d", owned, dhi.MaxHostsPerAgent)
	}
}
