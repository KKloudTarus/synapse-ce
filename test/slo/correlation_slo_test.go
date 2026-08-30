// Package slo holds EDR data-plane SLO / scale release gates (#594 #636). They are REAL gates: each
// asserts a latency budget AND a correctness invariant (deterministic + idempotent), so a regression that
// makes the deterministic pipeline slow, non-deterministic, or lossy fails the gate — never a stub that
// always passes. Run with `make edr-slo` (or `go test ./test/slo/...`).
package slo

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/correlation"
	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
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
	cfg := correlation.Config{Window: time.Hour, MaxPerIncident: 100000}

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
	svc, err := correlationuc.NewService(fixedDetections{recs: dets}, incs, nil, correlation.Config{Window: time.Hour, MaxPerIncident: 100000}, noopAudit{}, func() time.Time { return base })
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	res, err := svc.CorrelateEngagement(context.Background(), "slo", "eng-1")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed > sloCorrelateBudget {
		t.Fatalf("SLO VIOLATION: pipeline correlation took %s (budget %s)", elapsed, sloCorrelateBudget)
	}
	if len(res.Created) != sloSessions {
		t.Fatalf("correctness: expected %d incidents, got %d", sloSessions, len(res.Created))
	}
	res2, err := svc.CorrelateEngagement(context.Background(), "slo", "eng-1")
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

func (f fixedDetections) ListDetections(context.Context, shared.ID) ([]detection.Record, error) {
	return f.recs, nil
}

type countingIncidents struct{ seen map[shared.ID]bool }

func (c *countingIncidents) RecordCorrelation(_ context.Context, events []incident.IncidentEvent) ([]incident.Incident, error) {
	var created []incident.Incident
	for _, e := range events {
		if c.seen[e.IncidentID] {
			continue
		}
		c.seen[e.IncidentID] = true
		created = append(created, incident.Incident{ID: e.IncidentID, State: incident.StateOpen})
	}
	return created, nil
}

type noopAudit struct{}

func (noopAudit) Record(context.Context, ports.AuditEntry) error { return nil }

// failingIncidents fails RecordCorrelation, standing in for a store outage mid-pipeline (chaos).
type failingIncidents struct{}

func (failingIncidents) RecordCorrelation(context.Context, []incident.IncidentEvent) ([]incident.Incident, error) {
	return nil, fmt.Errorf("injected store outage")
}

// TestSLO_ChaosStoreOutageFailsClosed: a correlation whose incident store fails mid-pipeline must fail
// CLOSED — surface the error, never a partial/silent success — so a fault never silently drops incidents
// (coverage honesty under chaos).
func TestSLO_ChaosStoreOutageFailsClosed(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	svc, err := correlationuc.NewService(fixedDetections{recs: makeDetections(base)}, failingIncidents{}, nil, correlation.Config{Window: time.Hour, MaxPerIncident: 100000}, noopAudit{}, func() time.Time { return base })
	if err != nil {
		t.Fatal(err)
	}
	res, err := svc.CorrelateEngagement(context.Background(), "slo", "eng-1")
	if err == nil {
		t.Fatal("chaos: a store outage must surface as an error, not a silent success")
	}
	if len(res.Created) != 0 {
		t.Fatalf("chaos: no incident may be reported created on a failed pipeline, got %d", len(res.Created))
	}
	t.Log("OK: store outage failed closed (error surfaced, no partial incidents)")
}
