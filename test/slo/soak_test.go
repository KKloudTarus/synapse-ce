package slo

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/correlation"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/correlationuc"
)

// soakIterations is the sustained-operation length. Bounded so the gate runs in CI, but long enough to
// surface a leak or unbounded-growth regression — the third A7 (#628) leg beside E2E + failure.
const soakIterations = 2000

// TestSOAK_CorrelationSustainedStability runs the correlation pipeline repeatedly against a stable
// detection set and asserts it stays CORRECT and does not LEAK (heap bounded across the run). A7 soak leg:
// sustained operation must not degrade, error, or grow without bound.
func TestSOAK_CorrelationSustainedStability(t *testing.T) {
	if testing.Short() {
		t.Skip("soak skipped under -short")
	}
	base := time.Unix(1_700_000_000, 0).UTC()
	dets := makeDetections(base)
	cfg := correlation.Config{Window: time.Hour, MaxPerIncident: 100000, PageSize: 1000}

	var m0 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)

	svc, err := correlationuc.NewService(fixedDetections{recs: dets}, memory.NewDetectionProvenanceStore(), memory.NewEndpointTimelineStore(), memory.NewCorrelationStateStore(), &countingIncidents{seen: map[shared.ID]bool{}}, nil, cfg, noopAudit{}, func() time.Time { return base })
	if err != nil {
		t.Fatal(err)
	}
	ctx := shared.WithTenant(context.Background(), "tenant-soak")
	if res := driveCorrelationSnapshot(t, svc, ctx); len(res.Created) != sloSessions {
		t.Fatalf("initial correctness drifted — expected %d incidents, got %d", sloSessions, len(res.Created))
	}
	for i := 0; i < soakIterations; i++ {
		res, err := svc.CorrelateEngagement(ctx, "soak", "eng-1")
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		if len(res.Created) != 0 || res.HasMore || res.Phase != "" {
			t.Fatalf("iteration %d: completed snapshot was reprocessed: %+v", i, res)
		}
	}

	var m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)
	const slack = 64 << 20 // generous slack for GC timing; a real leak over 2000 iterations blows past it
	if m1.HeapAlloc > m0.HeapAlloc+slack {
		t.Fatalf("SOAK: heap grew from %d to %d over %d iterations (>%d slack) — possible leak", m0.HeapAlloc, m1.HeapAlloc, soakIterations, slack)
	}
	t.Logf("OK: %d sustained correlation iterations, correct + heap stable (%d → %d bytes)", soakIterations, m0.HeapAlloc, m1.HeapAlloc)
}
