package telemetry

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetryschema"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeAudit struct {
	mu         sync.Mutex
	actions    []string
	failAction string // if set, Record returns an error for this action (and does not record it)
}

func (a *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failAction != "" && e.Action == a.failAction {
		return errors.New("audit sink unavailable")
	}
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
		SchemaVersion: telemetryschema.Current, Class: detection.ClassProcess, Sequence: seq, SampleRate: sampleRate, Events: evs}
}

func TestIngestBudgetOverflowIsTruncatedNotSampled(t *testing.T) {
	// D2: a sheddable-class overflow keeps the prefix but is recorded as a first-class Truncated loss —
	// NOT relabelled as an elevated sample rate. A hunt sees the window incomplete via the loss, while the
	// stored sample rate stays truthful (1 = full fidelity for the events that WERE kept).
	svc, _, audit := newSvc(t, 2, 7*24*time.Hour, 30*24*time.Hour)
	at := time.Unix(1_000_000, 0)
	b := batch(1, 1, procEventAt("ps", at), procEventAt("top", at), procEventAt("ls", at))
	rep, err := svc.Ingest(tctx(), b)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Accepted != 2 || rep.Dropped != 1 {
		t.Fatalf("overflow must keep the budget prefix and report the drop, got %+v", rep)
	}
	if rep.Disposition != telemetry.Truncated {
		t.Fatalf("overflow of a sheddable class must be Truncated, got %q", rep.Disposition)
	}
	if !audit.has("telemetry.overflow") {
		t.Error("store-rate overflow must be reported, never silent")
	}
	res, _ := svc.Hunt(tctx(), ports.HuntQuery{HostID: "host-1", Class: detection.ClassProcess})
	// The D2 fix: the truncation surfaces as a first-class loss, NOT as a fake elevated sample rate.
	if res.Sampled || res.MaxSampleRate != 1 {
		t.Errorf("truncation must NOT masquerade as sampling, got sampled=%v rate=%d", res.Sampled, res.MaxSampleRate)
	}
	if res.Complete {
		t.Error("a truncated window must never be presented as complete")
	}
	if len(res.Losses) != 1 || res.Losses[0].Disposition != telemetry.Truncated || res.Losses[0].DroppedCount != 1 {
		t.Fatalf("the hunt must expose the truncation as a first-class loss, got %+v", res.Losses)
	}
}

func TestIngestNeverShedClassRefusesOverflow(t *testing.T) {
	// A never-shed class (privilege) that exceeds the budget is refused WHOLE (back-pressure) and recorded
	// as Dropped — never truncated into a lossy prefix that hides a security-critical event.
	svc, _, audit := newSvc(t, 2, 7*24*time.Hour, 30*24*time.Hour)
	at := time.Unix(1_000_000, 0)
	priv := func(comm string) detection.Event {
		return detection.Event{Class: detection.ClassPrivilege, At: at, Host: "host-1",
			Process: &detection.ProcessEvent{PID: 1, Comm: comm, Path: "/usr/bin/" + comm}}
	}
	b := ports.TelemetryBatch{TenantID: "t1", HostID: "host-1", AssetID: "asset-1", AgentID: "agent:1",
		SchemaVersion: telemetryschema.Current, Class: detection.ClassPrivilege, Sequence: 1, SampleRate: 1,
		Events: []detection.Event{priv("su"), priv("sudo"), priv("setuid")}}
	rep, err := svc.Ingest(tctx(), b)
	if !errors.Is(err, shared.ErrSaturated) {
		t.Fatalf("a never-shed overflow must be refused with ErrSaturated, got %v", err)
	}
	if rep.Disposition != telemetry.Dropped || rep.Accepted != 0 || rep.Dropped != 3 {
		t.Fatalf("a refused never-shed batch must be Dropped with 0 accepted and the WHOLE batch dropped, got %+v", rep)
	}
	if !audit.has("telemetry.drop") {
		t.Error("a refused never-shed drop (the most severe loss) must be audited")
	}
	// Nothing was stored (refused whole), but the loss is queryable so the drop is never silent.
	res, _ := svc.Hunt(tctx(), ports.HuntQuery{HostID: "host-1", Class: detection.ClassPrivilege})
	if len(res.Events) != 0 {
		t.Errorf("no event of a refused never-shed batch may be stored, got %d", len(res.Events))
	}
	if len(res.Losses) != 1 || res.Losses[0].Disposition != telemetry.Dropped {
		t.Fatalf("the drop must be a queryable first-class loss, got %+v", res.Losses)
	}
	// The loss must ALSO surface on an asset-pivot hunt (HuntAssetPivot) — otherwise a dropped window
	// reads complete on exactly that acceptance pattern.
	if ap, _ := svc.Hunt(tctx(), ports.HuntQuery{AssetID: "asset-1", Class: detection.ClassPrivilege}); len(ap.Losses) != 1 || ap.Complete {
		t.Fatalf("an asset-pivot hunt must surface the drop and never be complete, got losses=%+v complete=%v", ap.Losses, ap.Complete)
	}
}

func TestIngestFailsWhenGapAuditFails(t *testing.T) {
	// The recordGap audit is a HARD requirement now (D2 companion bug): if the overflow coverage event
	// cannot be audited, the whole ingest fails rather than admitting an unrecorded loss.
	svc, _, audit := newSvc(t, 2, 7*24*time.Hour, 30*24*time.Hour)
	audit.failAction = "telemetry.overflow"
	at := time.Unix(1_000_000, 0)
	b := batch(1, 1, procEventAt("ps", at), procEventAt("top", at), procEventAt("ls", at))
	if _, err := svc.Ingest(tctx(), b); !errors.Is(err, shared.ErrSaturated) {
		t.Fatalf("an unauditable overflow must fail the ingest, got %v", err)
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
	_, _ = svc.Ingest(tctx(), ports.TelemetryBatch{TenantID: "t1", HostID: "host-1", AssetID: "asset-1", AgentID: "agent:1", SchemaVersion: telemetryschema.Current, Class: detection.ClassProcess, Sequence: 2, SampleRate: 1, Events: warmEvs})
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
		if _, err := svc.Ingest(tctx(), ports.TelemetryBatch{TenantID: "t1", HostID: "host-1", AssetID: "asset-1", AgentID: "agent:1", SchemaVersion: telemetryschema.Current, Class: detection.ClassProcess, Sequence: uint64(i + 1), SampleRate: 1, Events: evs}); err != nil {
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

func TestIngestValidatesSchemaVersion(t *testing.T) {
	svc, _, _ := newSvc(t, 100, 7*24*time.Hour, 30*24*time.Hour)
	ev := procEventAt("ps", time.Unix(1_000_000, 0))

	// Accepted: the schema version this build emits. Acceptance keys on the batch's declared schema
	// version, never on any agent-binary version (there is no agent-version field on the batch) — proving
	// the schema/agent decoupling structurally.
	if _, err := svc.Ingest(tctx(), batch(1, 1, ev)); err != nil {
		t.Fatalf("Current schema version (%d) must be accepted: %v", telemetryschema.Current, err)
	}

	// Rejected fail-closed with ErrValidation: an unset (0) version and a version newer than this reader
	// supports — never parsed under a guessed shape.
	for _, v := range []int{0, telemetryschema.MaxSupported + 1} {
		b := batch(2, 1, ev)
		b.SchemaVersion = v
		if _, err := svc.Ingest(tctx(), b); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("schema version %d must be rejected with ErrValidation, got %v", v, err)
		}
	}
}
