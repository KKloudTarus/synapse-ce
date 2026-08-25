package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/baseline"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func sums(count int64) []baseline.FeatureSummary {
	out := make([]baseline.FeatureSummary, baseline.NumFeatures)
	for f := 0; f < baseline.NumFeatures; f++ {
		out[f] = baseline.FeatureSummary{Feature: baseline.Feature(f), Count: count, Sum: 2 * count, SumSq: 4 * count, Min: 2, Max: 2}
	}
	return out
}

func rec(tenant shared.ID, group string) ports.BaselineRecord {
	return ports.BaselineRecord{
		Key:       baseline.Key{Tenant: tenant, Group: group},
		State:     baseline.StateActive,
		Summaries: sums(10),
		DriftRun:  1,
		Drifted:   false,
		UpdatedAt: time.Unix(1_700_000_000, 0).UTC(),
	}
}

func TestBaselineStoreRoundTripAndTenantIsolation(t *testing.T) {
	s := NewBaselineStore()
	ctxA := shared.WithTenant(context.Background(), "ta")
	ctxB := shared.WithTenant(context.Background(), "tb")

	if err := s.Save(ctxA, rec("ta", "web")); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := s.Load(ctxA, baseline.Key{Tenant: "ta", Group: "web"})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.State != baseline.StateActive || got.Summaries[0].Count != 10 || got.DriftRun != 1 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	// Idempotent re-save (upsert) with a new state.
	up := rec("ta", "web")
	up.State = baseline.StateStale
	if err := s.Save(ctxA, up); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Load(ctxA, baseline.Key{Tenant: "ta", Group: "web"}); got.State != baseline.StateStale {
		t.Fatalf("upsert did not update state, got %s", got.State)
	}
	// Tenant B cannot see tenant A's baseline.
	if _, err := s.Load(ctxB, baseline.Key{Tenant: "tb", Group: "web"}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("tenant B must not see A's baseline, got %v", err)
	}
	// A key whose tenant disagrees with the context tenant is rejected (no cross-tenant write/read).
	if err := s.Save(ctxA, rec("tb", "web")); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("cross-tenant key on save must be rejected, got %v", err)
	}
	if _, err := s.Load(ctxA, baseline.Key{Tenant: "tb", Group: "web"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("cross-tenant key on load must be rejected, got %v", err)
	}
	// No tenant in context is rejected.
	if err := s.Save(context.Background(), rec("ta", "web")); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing tenant must be rejected, got %v", err)
	}
}

func TestBaselineStoreRejectsCorruptSummaries(t *testing.T) {
	s := NewBaselineStore()
	ctx := shared.WithTenant(context.Background(), "ta")
	bad := rec("ta", "web")
	bad.Summaries = bad.Summaries[:2] // wrong length
	if err := s.Save(ctx, bad); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("wrong-length summaries must be rejected, got %v", err)
	}
}
