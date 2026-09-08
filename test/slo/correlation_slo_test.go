// Package slo holds EDR data-plane SLO / scale release gates (#594 #636). They are REAL gates: each
// asserts a latency budget AND a correctness invariant (deterministic + idempotent), so a regression that
// makes the deterministic pipeline slow, non-deterministic, or lossy fails the gate — never a stub that
// always passes. Run with `make edr-slo` (or `go test ./test/slo/...`).
package slo

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/correlation"
	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/correlationuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	sloDetections      = 20000           // detections correlated in one pass
	sloSessions        = 400             // distinct (asset,host) sessions they fall into
	sloCorrelateBudget = 3 * time.Second // wall-clock budget for correlating the whole set
)

// makeSignals builds sloDetections signals spread across sloSessions (asset,host) keys, each session's
// signals within the correlation window so every session becomes exactly one incident.
func makeSignals(base time.Time) []correlation.Signal {
	out := make([]correlation.Signal, 0, sloDetections)
	for i := 0; i < sloDetections; i++ {
		sess := i % sloSessions
		out = append(out, correlation.Signal{
			ID:         shared.ID(fmt.Sprintf("d-%d", i)),
			AssetID:    shared.ID(fmt.Sprintf("asset-%d", sess)),
			EntityID:   shared.ID(fmt.Sprintf("host-%d", sess)),
			OccurredAt: base.Add(time.Duration(i) * time.Millisecond),
			Severity:   shared.SeverityHigh,
			RuleID:     "r1",
			Title:      "process: r1",
		})
	}
	return out
}

// TestSLO_CorrelatorScaleAndDeterminism: the domain correlator folds 20k detections into one incident per
// session within the latency budget, and the result is DETERMINISTIC (a re-run yields the identical
// incident set) — the correctness half that makes this a real gate, not a timer.
func TestSLO_CorrelatorScaleAndDeterminism(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	signals := makeSignals(base)
	cfg := correlation.Config{Window: time.Hour, MaxPerIncident: 100000, PageSize: 1000}

	start := time.Now()
	events, err := correlation.Correlate(cfg, signals)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("correlate: %v", err)
	}
	if elapsed > sloCorrelateBudget {
		t.Fatalf("SLO VIOLATION: correlating %d detections took %s (budget %s)", sloDetections, elapsed, sloCorrelateBudget)
	}
	incidents := distinctIncidents(events)
	if incidents != sloSessions {
		t.Fatalf("correctness: expected %d incidents (one per session), got %d", sloSessions, incidents)
	}
	// Determinism: a second run over the same input yields the identical incident set.
	events2, _ := correlation.Correlate(cfg, signals)
	if distinctIncidents(events2) != incidents || !sameIncidentIDs(events, events2) {
		t.Fatal("correctness: correlator is non-deterministic across runs")
	}
	t.Logf("OK: correlated %d detections → %d incidents in %s (budget %s)", sloDetections, incidents, elapsed, sloCorrelateBudget)
}

// TestSLO_CorrelationPipelineIdempotent: the correlationuc orchestration records one incident per session
// and a re-run over the SAME detections records ZERO new incidents (idempotency — no duplicate-incident
// pollution under repeated/scheduled correlation), within budget.
func TestSLO_CorrelationPipelineIdempotent(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	dets := makeDetections(base)
	incs := &countingIncidents{seen: map[shared.ID]bool{}}
	svc, err := correlationuc.NewService(fixedDetections{recs: dets}, memory.NewDetectionProvenanceStore(), memory.NewEndpointTimelineStore(), memory.NewCorrelationStateStore(), incs, nil, correlation.Config{Window: time.Hour, MaxPerIncident: 100000, PageSize: 1000}, noopAudit{}, func() time.Time { return base })
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	ctx := shared.WithTenant(context.Background(), "tenant-slo")
	res := driveCorrelationSnapshot(t, svc, ctx)
	elapsed := time.Since(start)
	if elapsed > sloCorrelateBudget {
		t.Fatalf("SLO VIOLATION: pipeline correlation took %s (budget %s)", elapsed, sloCorrelateBudget)
	}
	if len(res.Created) != sloSessions {
		t.Fatalf("correctness: expected %d incidents, got %d", sloSessions, len(res.Created))
	}
	res2, err := svc.CorrelateEngagement(ctx, "slo", "eng-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.Created) != 0 {
		t.Fatalf("correctness: a re-run must be idempotent (0 new incidents), got %d — duplicate-incident risk", len(res2.Created))
	}
	t.Logf("OK: pipeline correlated %d detections → %d incidents in %s; re-run idempotent", sloDetections, len(res.Created), elapsed)
}

func makeDetections(base time.Time) []detection.Record {
	out := make([]detection.Record, 0, sloDetections)
	for i := 0; i < sloDetections; i++ {
		sess := i % sloSessions
		out = append(out, detection.Record{
			ID:      shared.ID(fmt.Sprintf("d-%d", i)),
			AssetID: shared.ID(fmt.Sprintf("asset-%d", sess)),
			Detection: detection.Detection{
				RuleID: "r1", RuleVersion: 1, Class: detection.ClassProcess, Severity: shared.SeverityHigh,
				HostID: shared.ID(fmt.Sprintf("host-%d", sess)), Observed: base.Add(time.Duration(i) * time.Millisecond),
			},
		})
	}
	return out
}

func driveCorrelationSnapshot(t *testing.T, svc *correlationuc.Service, ctx context.Context) correlationuc.Result {
	t.Helper()
	var total correlationuc.Result
	for range 1024 {
		step, err := svc.CorrelateEngagement(ctx, "slo", "eng-1")
		if err != nil {
			t.Fatal(err)
		}
		total.Created = append(total.Created, step.Created...)
		total.Updated = append(total.Updated, step.Updated...)
		if !step.HasMore && step.Phase == "" {
			return total
		}
	}
	t.Fatal("correlation snapshot did not complete")
	return total
}

func distinctIncidents(events []incident.IncidentEvent) int {
	seen := map[shared.ID]bool{}
	for _, e := range events {
		seen[e.IncidentID] = true
	}
	return len(seen)
}

func sameIncidentIDs(a, b []incident.IncidentEvent) bool {
	sa, sb := map[shared.ID]bool{}, map[shared.ID]bool{}
	for _, e := range a {
		sa[e.IncidentID] = true
	}
	for _, e := range b {
		sb[e.IncidentID] = true
	}
	if len(sa) != len(sb) {
		return false
	}
	for k := range sa {
		if !sb[k] {
			return false
		}
	}
	return true
}

type fixedDetections struct{ recs []detection.Record }

func (f fixedDetections) CorrelationHighWater(_ context.Context, _ shared.ID, completed correlation.SourcePosition, _ time.Time) (correlation.SourcePosition, bool, error) {
	var high correlation.SourcePosition
	for _, r := range f.recs {
		p := correlation.SourcePosition{RecordedAt: r.RecordedAt, ID: r.ID}
		if p.RecordedAt.IsZero() {
			p.RecordedAt = r.Detection.Observed
		}
		if !completed.RecordedAt.IsZero() && (p.RecordedAt.Before(completed.RecordedAt) || (p.RecordedAt.Equal(completed.RecordedAt) && p.ID <= completed.ID)) {
			continue
		}
		if high.RecordedAt.IsZero() || p.RecordedAt.After(high.RecordedAt) || (p.RecordedAt.Equal(high.RecordedAt) && p.ID > high.ID) {
			high = p
		}
	}
	return high, !high.RecordedAt.IsZero(), nil
}
func (f fixedDetections) ListCorrelationSourcePage(_ context.Context, _ shared.ID, after, through correlation.SourcePosition, _ time.Time, limit int) ([]detection.Record, bool, error) {
	// makeDetections supplies recorded-order input, so keyset seek avoids repeatedly sorting/scanning 20k rows.
	at := func(i int) time.Time {
		if f.recs[i].RecordedAt.IsZero() {
			return f.recs[i].Detection.Observed
		}
		return f.recs[i].RecordedAt
	}
	start := sort.Search(len(f.recs), func(i int) bool {
		return after.RecordedAt.IsZero() || at(i).After(after.RecordedAt) || (at(i).Equal(after.RecordedAt) && f.recs[i].ID > after.ID)
	})
	end := sort.Search(len(f.recs), func(i int) bool {
		return at(i).After(through.RecordedAt) || (at(i).Equal(through.RecordedAt) && f.recs[i].ID > through.ID)
	})
	if end < start {
		end = start
	}
	more := end-start > limit
	if more {
		end = start + limit
	}
	out := append([]detection.Record(nil), f.recs[start:end]...)
	for i := range out {
		if out[i].RecordedAt.IsZero() {
			out[i].RecordedAt = out[i].Detection.Observed
		}
	}
	return out, more, nil
}

type countingIncidents struct{ seen map[shared.ID]bool }

func (c *countingIncidents) RecordCorrelation(_ context.Context, events []incident.IncidentEvent) ([]incident.Incident, []incident.Incident, error) {
	var created []incident.Incident
	for _, e := range events {
		if c.seen[e.IncidentID] {
			continue
		}
		c.seen[e.IncidentID] = true
		created = append(created, incident.Incident{ID: e.IncidentID, State: incident.StateOpen})
	}
	return created, nil, nil
}

type noopAudit struct{}

func (noopAudit) Record(context.Context, ports.AuditEntry) error { return nil }

// failingIncidents fails RecordCorrelation, standing in for a store outage mid-pipeline (chaos).
type failingIncidents struct{}

func (failingIncidents) RecordCorrelation(context.Context, []incident.IncidentEvent) ([]incident.Incident, []incident.Incident, error) {
	return nil, nil, fmt.Errorf("injected store outage")
}

// TestSLO_ChaosStoreOutageFailsClosed: a correlation whose incident store fails mid-pipeline must fail
// CLOSED — surface the error, never a partial/silent success — so a fault never silently drops incidents
// (coverage honesty under chaos).
func TestSLO_ChaosStoreOutageFailsClosed(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	svc, err := correlationuc.NewService(fixedDetections{recs: makeDetections(base)}, memory.NewDetectionProvenanceStore(), memory.NewEndpointTimelineStore(), memory.NewCorrelationStateStore(), failingIncidents{}, nil, correlation.Config{Window: time.Hour, MaxPerIncident: 100000, PageSize: 1000}, noopAudit{}, func() time.Time { return base })
	if err != nil {
		t.Fatal(err)
	}
	ctx := shared.WithTenant(context.Background(), "tenant-slo")
	for range 64 {
		res, err := svc.CorrelateEngagement(ctx, "slo", "eng-1")
		if err != nil {
			if len(res.Created) != 0 {
				t.Fatalf("chaos: no incident may be reported created on a failed pipeline, got %d", len(res.Created))
			}
			t.Log("OK: store outage failed closed (error surfaced, no partial incidents)")
			return
		}
	}
	t.Fatal("chaos: a store outage must surface during bounded consume steps")
	t.Log("OK: store outage failed closed (error surfaced, no partial incidents)")
}
