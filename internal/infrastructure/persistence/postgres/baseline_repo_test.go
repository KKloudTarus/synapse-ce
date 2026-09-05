package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/baseline"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func baselineSums(count int64) []baseline.FeatureSummary {
	out := make([]baseline.FeatureSummary, baseline.NumFeatures)
	for f := 0; f < baseline.NumFeatures; f++ {
		out[f] = baseline.FeatureSummary{Feature: baseline.Feature(f), Count: count, Sum: 2 * count, SumSq: 4 * count, Min: 2, Max: 2}
	}
	return out
}

func TestBaselineRepository(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	id := randHex(t)
	tenant := shared.ID("bl-" + id)
	other := shared.ID("bl-other-" + id)
	for _, tn := range []shared.ID{tenant, other} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tn.String()); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
	}
	t.Cleanup(func() {
		bg := context.Background()
		for _, tn := range []shared.ID{tenant, other} {
			_, _ = pool.Exec(bg, `DELETE FROM baselines WHERE tenant_id=$1`, tn.String())
			_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id=$1`, tn.String())
		}
	})

	repo := NewBaselineRepository(pool)
	tctx := shared.WithTenant(ctx, tenant)
	octx := shared.WithTenant(ctx, other)
	key := baseline.Key{Tenant: tenant, Group: "web-tier"}

	// Not found before save.
	if _, err := repo.Load(tctx, key); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	// Save + load round-trip.
	rec := ports.BaselineRecord{Key: key, State: baseline.StateActive, Summaries: baselineSums(12), DriftRun: 2, Drifted: false, UpdatedAt: time.Unix(1_800_000_000, 0).UTC()}
	if err := repo.Save(tctx, rec); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := repo.Load(tctx, key)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.State != baseline.StateActive || got.DriftRun != 2 || len(got.Summaries) != baseline.NumFeatures || got.Summaries[0].Count != 12 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	// The reloaded summaries rehydrate a valid domain baseline.
	if _, err := baseline.NewBaselineFrom(got.Key, got.State, got.Summaries); err != nil {
		t.Fatalf("reloaded record must rehydrate: %v", err)
	}
	// Upsert updates in place.
	rec.State = baseline.StateDrifted
	rec.Drifted = true
	rec.DriftRun = 3
	if err := repo.Save(tctx, rec); err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.Load(tctx, key); got.State != baseline.StateDrifted || !got.Drifted || got.DriftRun != 3 {
		t.Fatalf("upsert did not update, got state=%s drifted=%v run=%d", got.State, got.Drifted, got.DriftRun)
	}
	// Tenant isolation: other tenant cannot see it.
	if _, err := repo.Load(octx, baseline.Key{Tenant: other, Group: "web-tier"}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant load must be ErrNotFound, got %v", err)
	}
	// Cross-tenant key rejected before touching the DB.
	if err := repo.Save(tctx, ports.BaselineRecord{Key: baseline.Key{Tenant: other, Group: "x"}, State: baseline.StateLearning, Summaries: baselineSums(0), UpdatedAt: time.Unix(1, 0).UTC()}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("cross-tenant key must be rejected, got %v", err)
	}
}
