package telemetry

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeAudit struct {
	mu      sync.Mutex
	actions []string
}

func (a *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.actions = append(a.actions, e.Action)
	return nil
}
func (a *fakeAudit) has(action string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, x := range a.actions {
		if x == action {
			return true
		}
	}
	return false
}

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

func procEventAt(comm string, at time.Time) detection.Event {
	return detection.Event{Class: detection.ClassProcess, At: at, Host: "host-1",
		Process: &detection.ProcessEvent{PID: 1, Comm: comm, Path: "/usr/bin/" + comm}}
}

func newSvc(t *testing.T, budget int, hot, warm time.Duration) (*Service, *memory.TelemetryStore, *fakeAudit) {
	t.Helper()
	store := memory.NewTelemetryStore(hot, warm)
	audit := &fakeAudit{}
	svc, err := NewService(store, audit, fixedClock{t: time.Unix(1_000_000, 0)}, budget)
	if err != nil {
		t.Fatal(err)
	}
	return svc, store, audit
}

func tctx() context.Context { return shared.WithTenant(context.Background(), "t1") }

func batch(seq uint64, sampleRate int, evs ...detection.Event) ports.TelemetryBatch {
	return ports.TelemetryBatch{TenantID: "t1", HostID: "host-1", AssetID: "asset-1", AgentID: "agent:1",
		Class: detection.ClassProcess, Sequence: seq, SampleRate: sampleRate, Events: evs}
}

func TestIngestBudgetOverflowReportsGap(t *testing.T) {
	svc, _, audit := newSvc(t, 2, 7*24*time.Hour, 30*24*time.Hour)
	b := batch(1, 1, procEventAt("ps", time.Unix(1_000_000, 0)), procEventAt("top", time.Unix(1_000_000, 0)), procEventAt("ls", time.Unix(1_000_000, 0)))
	rep, err := svc.Ingest(tctx(), b)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Accepted != 2 || rep.Dropped != 1 {
		t.Fatalf("overflow must shed the excess and report it, got %+v", rep)
	}
	if !audit.has("telemetry.overflow") {
		t.Error("store-rate overflow must be reported as a telemetry gap, never silent")
	}
}

func TestIngestSequenceGapIsVisible(t *testing.T) {
	svc, _, audit := newSvc(t, 100, 7*24*time.Hour, 30*24*time.Hour)
	if _, err := svc.Ingest(tctx(), batch(1, 1, procEventAt("ps", time.Unix(1_000_000, 0)))); err != nil {
		t.Fatal(err)
	}
	// Jump to seq 4 → seqs 2,3 lost upstream.
	rep, err := svc.Ingest(tctx(), batch(4, 1, procEventAt("top", time.Unix(1_000_000, 0))))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Gap == nil || rep.Gap.Missing != 2 {
		t.Fatalf("an upstream loss must surface as a sequence gap, got %+v", rep.Gap)
	}
	if !audit.has("telemetry.sequence_gap") {
		t.Error("a sequence gap must be reported")
	}
	// A hunt over the window sees the lossy sequence.
	res, _ := svc.Hunt(tctx(), ports.HuntQuery{HostID: "host-1", Class: detection.ClassProcess})
	if res.Complete {
		t.Error("a window with a sequence gap must not report as complete")
	}
	if len(res.SequenceGaps) == 0 {
		t.Error("the hunt must expose the sequence gap")
	}
}

func TestSampledWindowNeverComplete(t *testing.T) {
	svc, _, _ := newSvc(t, 100, 7*24*time.Hour, 30*24*time.Hour)
	// A batch sampled 1-in-10.
	if _, err := svc.Ingest(tctx(), batch(1, 10, procEventAt("ps", time.Unix(1_000_000, 0)))); err != nil {
		t.Fatal(err)
	}
	res, _ := svc.Hunt(tctx(), ports.HuntQuery{HostID: "host-1", Class: detection.ClassProcess})
	if !res.Sampled || res.MaxSampleRate != 10 {
		t.Fatalf("a sampled window must report its rate, got sampled=%v rate=%d", res.Sampled, res.MaxSampleRate)
	}
	if res.Complete {
		t.Error("a sampled window must never be presented as complete")
	}
}

func TestRetentionTiersAndAuditedExpiry(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	svc, store, audit := newSvc(t, 1000, time.Hour, 2*time.Hour)
	svc.clock = fixedClock{t: now}
	// hot (recent), warm (between hot and warm cut), expired (past warm).
	hotEv := procEventAt("ps", now.Add(-10*time.Minute))
	warmEvs := []detection.Event{procEventAt("a", now.Add(-90*time.Minute)), procEventAt("b", now.Add(-90*time.Minute))}
	oldEv := procEventAt("old", now.Add(-3*time.Hour))
	_, _ = svc.Ingest(tctx(), batch(1, 1, hotEv))
	_, _ = svc.Ingest(tctx(), ports.TelemetryBatch{TenantID: "t1", HostID: "host-1", AssetID: "asset-1", AgentID: "agent:1", Class: detection.ClassProcess, Sequence: 2, SampleRate: 1, Events: warmEvs})
	_, _ = svc.Ingest(tctx(), batch(3, 1, oldEv))

	rep, err := svc.Sweep(tctx())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Expired < 1 {
		t.Errorf("past-warm rows must be expired, got %+v", rep)
	}
	if rep.WarmDownsampled < 1 {
		t.Errorf("the warm window must be down-sampled (reduced resolution), got %+v", rep)
	}
	if !audit.has("telemetry.retention_sweep") {
		t.Error("expiry must be audited, never silent")
	}
	// The old event is gone; the hot event remains.
	res, _ := store.Query(tctx(), ports.HuntQuery{HostID: "host-1"})
	for _, ev := range res.Events {
		if ev.Process != nil && ev.Process.Comm == "old" {
			t.Error("an expired event must not survive the sweep")
		}
	}
}

// TestRetroHuntPatterns exercises the three acceptance patterns.
func TestRetroHuntPatterns(t *testing.T) {
	svc, _, _ := newSvc(t, 1000, 7*24*time.Hour, 30*24*time.Hour)
	base := time.Unix(1_000_000, 0)
	// Seed: a `ps` (matches det.process_enumeration) + a `bash` (matches nothing).
	_, _ = svc.Ingest(tctx(), batch(1, 1, procEventAt("ps", base), procEventAt("bash", base.Add(time.Second))))

	// (1) retro-run a rule over the hot window.
	fired, res, err := svc.RetroRunRule(tctx(), ports.HuntQuery{HostID: "host-1", Class: detection.ClassProcess})
	if err != nil {
		t.Fatal(err)
	}
	if len(fired) != 1 || fired[0].RuleID != "det.process_enumeration" {
		t.Fatalf("retro-run must fire det.process_enumeration on the ps event, got %+v", fired)
	}
	if !res.Complete {
		t.Error("a full, gapless window must report complete")
	}
	// (2) reconstruct context around a detection: events for the host+window.
	ctxRes, _ := svc.Hunt(tctx(), ports.HuntQuery{Kind: ports.HuntContext, HostID: "host-1", Since: base.Add(-time.Minute), Until: base.Add(time.Minute)})
	if len(ctxRes.Events) < 2 {
		t.Errorf("context hunt must return the surrounding events, got %d", len(ctxRes.Events))
	}
	// (3) pivot from an asset to its raw events.
	pivot, _ := svc.Hunt(tctx(), ports.HuntQuery{Kind: ports.HuntAssetPivot, AssetID: "asset-1"})
	if len(pivot.Events) < 2 {
		t.Errorf("asset pivot must return the asset's raw events, got %d", len(pivot.Events))
	}
}

func TestFootprintIsObservable(t *testing.T) {
	svc, _, _ := newSvc(t, 1000, 7*24*time.Hour, 30*24*time.Hour)
	_, _ = svc.Ingest(tctx(), batch(1, 1, procEventAt("ps", time.Unix(1_000_000, 0)), procEventAt("top", time.Unix(1_000_000, 0))))
	fp, err := svc.Footprint(tctx())
	if err != nil {
		t.Fatal(err)
	}
	if fp.Rows != 2 || fp.Bytes <= 0 {
		t.Fatalf("footprint must report rows and bytes, got %+v", fp)
	}
}

// TestRetroHuntLatencyOnSeededVolume seeds a volume and REPORTS the measured retro-hunt latency (#424
// acceptance: the three patterns within a stated bound on a stated volume).
func TestRetroHuntLatencyOnSeededVolume(t *testing.T) {
	svc, _, _ := newSvc(t, 100000, 7*24*time.Hour, 30*24*time.Hour)
	base := time.Unix(1_000_000, 0)
	const batches, per = 200, 100 // 20k seeded events
	for i := 0; i < batches; i++ {
		evs := make([]detection.Event, per)
		for j := 0; j < per; j++ {
			comm := "bash"
			if j == 0 {
				comm = "ps" // one matching event per batch
			}
			evs[j] = procEventAt(comm, base.Add(time.Duration(i)*time.Second))
		}
		if _, err := svc.Ingest(tctx(), ports.TelemetryBatch{TenantID: "t1", HostID: "host-1", AssetID: "asset-1", AgentID: "agent:1", Class: detection.ClassProcess, Sequence: uint64(i + 1), SampleRate: 1, Events: evs}); err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now()
	fired, res, err := svc.RetroRunRule(tctx(), ports.HuntQuery{HostID: "host-1", Class: detection.ClassProcess})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("retro-run over %d seeded events: %d detections, %d rows scanned, latency %s", batches*per, len(fired), res.RowsScanned, elapsed)
	if len(fired) != batches {
		t.Fatalf("expected one detection per batch, got %d", len(fired))
	}
	if elapsed > 5*time.Second {
		t.Errorf("retro-hunt latency %s exceeds the 5s bound on %d events (memory tier)", elapsed, batches*per)
	}
}
