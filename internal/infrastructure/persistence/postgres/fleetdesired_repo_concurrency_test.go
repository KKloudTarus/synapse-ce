package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetdesired"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestFleetDesiredRepositoryConcurrentCASAllowsExactlyOneWinner(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	const tenant = "fd-concurrent-cas"
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1,$1) ON CONFLICT (id) DO NOTHING`, tenant); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_ = WithTenant(bg, pool, tenant, func(tx pgx.Tx) error {
			if _, err := tx.Exec(bg, `DELETE FROM fleet_desired_state WHERE tenant_id=$1`, tenant); err != nil {
				return err
			}
			_, err := tx.Exec(bg, `DELETE FROM fleet_assets WHERE tenant_id=$1 AND id LIKE 'fd-concurrent-%'`, tenant)
			return err
		})
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id=$1`, tenant)
	})

	now := time.Date(2026, 8, 19, 6, 0, 0, 0, time.UTC)
	assets := NewAssetRepository(pool)
	for _, id := range []shared.ID{"fd-concurrent-create", "fd-concurrent-update", "fd-concurrent-clear"} {
		a, err := asset.New(id, tenant, asset.KindHost, "key/"+id.String(), id.String(), nil, now)
		if err != nil {
			t.Fatal(err)
		}
		if err := assets.UpsertAsset(ctx, a); err != nil {
			t.Fatal(err)
		}
	}

	repo := NewFleetDesiredRepository(pool)
	runPutRace := func(t *testing.T, left, right *fleetdesired.State) {
		t.Helper()
		start := make(chan struct{})
		results := make(chan error, 2)
		for _, candidate := range []*fleetdesired.State{left, right} {
			candidate := candidate
			go func() {
				<-start
				results <- repo.Put(context.Background(), candidate)
			}()
		}
		close(start)
		errA, errB := <-results, <-results
		wins := 0
		conflicts := 0
		for _, err := range []error{errA, errB} {
			switch {
			case err == nil:
				wins++
			case errors.Is(err, shared.ErrConflict):
				conflicts++
			default:
				t.Fatalf("concurrent CAS returned unexpected error: %v", err)
			}
		}
		if wins != 1 || conflicts != 1 {
			t.Fatalf("concurrent CAS wins=%d conflicts=%d, want exactly one of each; errors=(%v, %v)", wins, conflicts, errA, errB)
		}
	}

	t.Run("create", func(t *testing.T) {
		runPutRace(t,
			&fleetdesired.State{
				TenantID: tenant, AssetID: "fd-concurrent-create", PolicyID: "policy-create-a",
				Capabilities: []string{"process"}, UpdatedBy: "operator-a", Version: 1,
				Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
			},
			&fleetdesired.State{
				TenantID: tenant, AssetID: "fd-concurrent-create", PolicyID: "policy-create-b",
				Capabilities: []string{"network"}, UpdatedBy: "operator-b", Version: 1,
				Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
			},
		)
		got, err := repo.Get(ctx, tenant, "fd-concurrent-create")
		if err != nil {
			t.Fatal(err)
		}
		if got.Version != 1 || (got.PolicyID != "policy-create-a" && got.PolicyID != "policy-create-b") {
			t.Fatalf("unexpected concurrent-create winner: %+v", got)
		}
	})

	t.Run("update", func(t *testing.T) {
		base := &fleetdesired.State{
			TenantID: tenant, AssetID: "fd-concurrent-update", PolicyID: "policy-update",
			Capabilities: []string{"process"}, UpdatedBy: "operator", Version: 1,
			Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
		}
		if err := repo.Put(ctx, base); err != nil {
			t.Fatal(err)
		}
		at := now.Add(time.Minute)
		runPutRace(t,
			&fleetdesired.State{
				TenantID: tenant, AssetID: "fd-concurrent-update", PolicyID: "policy-update",
				Capabilities: []string{"file"}, UpdatedBy: "operator-a", Version: 2,
				Audit: shared.Audit{CreatedAt: now, UpdatedAt: at},
			},
			&fleetdesired.State{
				TenantID: tenant, AssetID: "fd-concurrent-update", PolicyID: "policy-update",
				Capabilities: []string{"network"}, UpdatedBy: "operator-b", Version: 2,
				Audit: shared.Audit{CreatedAt: now, UpdatedAt: at},
			},
		)
		got, err := repo.Get(ctx, tenant, "fd-concurrent-update")
		if err != nil {
			t.Fatal(err)
		}
		if got.Version != 2 || got.PolicyID != "policy-update" || len(got.Capabilities) != 1 ||
			(got.Capabilities[0] != "file" && got.Capabilities[0] != "network") {
			t.Fatalf("unexpected concurrent-update winner: %+v", got)
		}
	})

	t.Run("update versus clear", func(t *testing.T) {
		base := &fleetdesired.State{
			TenantID: tenant, AssetID: "fd-concurrent-clear", PolicyID: "policy-clear-race",
			Capabilities: []string{"process"}, UpdatedBy: "operator", Version: 1,
			Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
		}
		if err := repo.Put(ctx, base); err != nil {
			t.Fatal(err)
		}
		update := &fleetdesired.State{
			TenantID: tenant, AssetID: "fd-concurrent-clear", PolicyID: "policy-clear-race",
			Capabilities: []string{"network"}, UpdatedBy: "operator-update", Version: 2,
			Audit: shared.Audit{CreatedAt: now, UpdatedAt: now.Add(time.Minute)},
		}
		type result struct {
			op  string
			err error
		}
		start := make(chan struct{})
		results := make(chan result, 2)
		go func() {
			<-start
			results <- result{op: "update", err: repo.Put(context.Background(), update)}
		}()
		go func() {
			<-start
			results <- result{op: "clear", err: repo.Delete(context.Background(), tenant, "fd-concurrent-clear", "policy-clear-race", 1)}
		}()
		close(start)
		first, second := <-results, <-results
		outcomes := map[string]error{first.op: first.err, second.op: second.err}
		wins := 0
		conflicts := 0
		for _, result := range []result{first, second} {
			switch {
			case result.err == nil:
				wins++
			case errors.Is(result.err, shared.ErrConflict):
				conflicts++
			default:
				t.Fatalf("%s returned unexpected error: %v", result.op, result.err)
			}
		}
		if wins != 1 || conflicts != 1 {
			t.Fatalf("update/clear race wins=%d conflicts=%d, want one each: %+v", wins, conflicts, outcomes)
		}
		got, err := repo.Get(ctx, tenant, "fd-concurrent-clear")
		if outcomes["update"] == nil {
			if err != nil || got.Version != 2 || got.Capabilities[0] != "network" {
				t.Fatalf("winning update not preserved: got=%+v err=%v outcomes=%+v", got, err, outcomes)
			}
			return
		}
		if !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("winning clear left policy behind: got=%+v err=%v outcomes=%+v", got, err, outcomes)
		}
	})
}
