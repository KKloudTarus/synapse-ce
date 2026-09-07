package detect

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ---- fakes ------------------------------------------------------------------------------------------

type fakeSensor struct {
	events   chan detection.Event
	coverage []detection.ClassCoverage
	dropped  map[detection.Class]uint64
	started  bool
	startErr error
}

func newFakeSensor() *fakeSensor {
	return &fakeSensor{events: make(chan detection.Event, 64), dropped: map[detection.Class]uint64{}}
}
func (f *fakeSensor) Start(context.Context) error         { f.started = true; return f.startErr }
func (f *fakeSensor) Events() <-chan detection.Event      { return f.events }
func (f *fakeSensor) Coverage() []detection.ClassCoverage { return f.coverage }
func (f *fakeSensor) Dropped() map[detection.Class]uint64 { return f.dropped }
func (f *fakeSensor) Close() error                        { return nil }

type fakeSink struct {
	mu   sync.Mutex
	got  []detection.Detection
	fail bool
}

func (s *fakeSink) Emit(_ context.Context, d detection.Detection) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errors.New("sink down")
	}
	s.got = append(s.got, d)
	return nil
}
func (s *fakeSink) detections() []detection.Detection {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]detection.Detection(nil), s.got...)
}

type fixedSampler struct{ pct float64 }

func (s fixedSampler) CPUPercent() float64 { return s.pct }

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

func procEvent(comm string, args ...string) detection.Event {
	return detection.Event{Class: detection.ClassProcess, At: time.Unix(1, 0), Host: "h",
		Process: &detection.ProcessEvent{PID: 1, Comm: comm, Path: "/usr/bin/" + comm, Args: args}}
}

func newEngine(t *testing.T, sensor *fakeSensor, sink *fakeSink, opts Options) *Engine {
	t.Helper()
	if opts.Clock == nil {
		opts.Clock = fixedClock{t: time.Unix(1000, 0)}
	}
	e, err := NewEngine(sensor, sink, "host-1", "agent:1", opts)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// ---- tests ------------------------------------------------------------------------------------------

func TestNewEngineValidation(t *testing.T) {
	s, k := newFakeSensor(), &fakeSink{}
	cases := map[string]func() (*Engine, error){
		"nil sensor": func() (*Engine, error) { return NewEngine(nil, k, "h", "a", Options{}) },
		"nil sink":   func() (*Engine, error) { return NewEngine(s, nil, "h", "a", Options{}) },
		"no host":    func() (*Engine, error) { return NewEngine(s, k, "", "a", Options{}) },
		"no agent":   func() (*Engine, error) { return NewEngine(s, k, "h", "", Options{}) },
		"bad class": func() (*Engine, error) {
			return NewEngine(s, k, "h", "a", Options{Classes: []detection.Class{"telepathy"}})
		},
	}
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := call(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want validation error, got %v", err)
			}
		})
	}
}

// TestEngineEmitsDetectionOnMatch: a captured `ps` exec becomes a det.process_enumeration detection with
// the triggering event as evidence and full attribution.
func TestEngineEmitsDetectionOnMatch(t *testing.T) {
	sensor, sink := newFakeSensor(), &fakeSink{}
	e := newEngine(t, sensor, sink, Options{})
	e.process(context.Background(), procEvent("ps", "-ef"))

	got := sink.detections()
	if len(got) != 1 {
		t.Fatalf("want one detection, got %d", len(got))
	}
	d := got[0]
	if d.RuleID != "det.process_enumeration" || d.HostID != "host-1" || d.AgentID != "agent:1" {
		t.Fatalf("detection attribution wrong: %+v", d)
	}
	if len(d.Evidence) != 1 || d.Evidence[0].Process.Comm != "ps" {
		t.Fatalf("detection must carry the triggering event as evidence: %+v", d.Evidence)
	}
}

// TestEngineIgnoresNonMatchingAndDisabled: a non-matching command produces nothing, and an event of a
// disabled class is never evaluated.
func TestEngineIgnoresNonMatchingAndDisabled(t *testing.T) {
	sensor, sink := newFakeSensor(), &fakeSink{}
	e := newEngine(t, sensor, sink, Options{Classes: []detection.Class{detection.ClassProcess}})

	e.process(context.Background(), procEvent("bash")) // no process rule matches bash
	// A file event while only the process class is enabled must be ignored.
	e.process(context.Background(), detection.Event{Class: detection.ClassFile, At: time.Unix(1, 0), Host: "h",
		File: &detection.FileEvent{Path: "/etc/shadow", Op: "read"}})

	if got := sink.detections(); len(got) != 0 {
		t.Fatalf("no detection expected, got %d: %+v", len(got), got)
	}
}

// TestEngineContextWindowIsBounded: a detection carries recent same-class events as bounded context,
// ending with the trigger.
func TestEngineContextWindowIsBounded(t *testing.T) {
	sensor, sink := newFakeSensor(), &fakeSink{}
	e := newEngine(t, sensor, sink, Options{Classes: []detection.Class{detection.ClassProcess}, ContextWindow: 4})

	// Feed several non-matching execs to fill context, then a matching `ps`.
	for _, c := range []string{"bash", "sh", "env", "cat", "ls"} {
		e.process(context.Background(), procEvent(c))
	}
	e.process(context.Background(), procEvent("ps"))

	got := sink.detections()
	if len(got) != 1 {
		t.Fatalf("want one detection, got %d", len(got))
	}
	ev := got[0].Evidence
	if len(ev) != 4 {
		t.Fatalf("context window must be bounded to 4, got %d", len(ev))
	}
	if ev[len(ev)-1].Process.Comm != "ps" {
		t.Fatalf("window must end with the trigger, got %q", ev[len(ev)-1].Process.Comm)
	}
}

// TestEngineShedsClassesInDefinedOrderUnderLoad: sustained over-ceiling load sheds classes in the
// defined order (file, network, process, privilege), records each, and stops the shed class being
// evaluated. Shedding is reported, not silent.
func TestEngineShedsClassesInDefinedOrderUnderLoad(t *testing.T) {
	sensor, sink := newFakeSensor(), &fakeSink{}
	e := newEngine(t, sensor, sink, Options{CPUCeilingPct: 50, Sampler: fixedSampler{pct: 90}})

	// Four over-ceiling samples shed the four classes in order.
	for i := 0; i < 5; i++ {
		e.process(context.Background(), procEvent("bash"))
	}
	log := e.ShedLog()
	want := []detection.Class{detection.ClassFile, detection.ClassNetwork, detection.ClassProcess, detection.ClassPrivilege}
	if len(log) != len(want) {
		t.Fatalf("want %d shed events, got %d: %+v", len(want), len(log), log)
	}
	for i, c := range want {
		if log[i].Class != c {
			t.Fatalf("shed order wrong at %d: got %s want %s", i, log[i].Class, c)
		}
		if log[i].CPUAtShed != 90 || log[i].CeilingPct != 50 {
			t.Errorf("shed event must record the measured cpu and ceiling: %+v", log[i])
		}
	}

	// A now-shed process class must not produce detections.
	sinkBefore := len(sink.detections())
	e.process(context.Background(), procEvent("ps"))
	if len(sink.detections()) != sinkBefore {
		t.Error("a shed class must not be evaluated into detections")
	}
}

func TestEngineDoesNotShedWhenUnderCeiling(t *testing.T) {
	sensor, sink := newFakeSensor(), &fakeSink{}
	e := newEngine(t, sensor, sink, Options{CPUCeilingPct: 50, Sampler: fixedSampler{pct: 10}})
	for i := 0; i < 10; i++ {
		e.process(context.Background(), procEvent("ps"))
	}
	if len(e.ShedLog()) != 0 {
		t.Fatalf("no shedding expected under the ceiling, got %+v", e.ShedLog())
	}
	if len(sink.detections()) != 10 {
		t.Fatalf("every ps should have produced a detection, got %d", len(sink.detections()))
	}
}

// TestEngineCoverageFoldsGapsShedAndDrops is the coverage-honesty end state: the engine's coverage
// reflects the sensor's gaps, its own shedding, and back-pressure drops — a class not fully observed is
// never reported as clean.
func TestEngineCoverageFoldsSensorGapsShedAndDrops(t *testing.T) {
	sensor, sink := newFakeSensor(), &fakeSink{}
	sensor.coverage = []detection.ClassCoverage{
		{Class: detection.ClassProcess, HostID: "host-1", State: detection.StateActive},
		{Class: detection.ClassFile, HostID: "host-1", State: detection.StateFailed, Reason: "load failed"},
		{Class: detection.ClassNetwork, HostID: "host-1", State: detection.StateActive},
		{Class: detection.ClassPrivilege, HostID: "host-1", State: detection.StateActive},
	}
	sensor.dropped = map[detection.Class]uint64{detection.ClassNetwork: 7}
	e := newEngine(t, sensor, sink, Options{CPUCeilingPct: 50, Sampler: fixedSampler{pct: 90}})

	// Shed the first class (file) — but file is already failed at the sensor; shed the process class too
	// by forcing two breaches.
	e.process(context.Background(), procEvent("bash")) // sheds file
	e.process(context.Background(), procEvent("bash")) // sheds network

	cov := e.Coverage()
	byClass := map[detection.Class]detection.ClassCoverage{}
	for _, c := range cov {
		byClass[c.Class] = c
	}
	// process: active (not shed, not dropped) — the only cleanly observed class.
	if byClass[detection.ClassProcess].State != detection.StateActive {
		t.Errorf("process should remain active: %+v", byClass[detection.ClassProcess])
	}
	// file: sensor-failed gap (shed overlays but the sensor state was already a gap; either way not clean).
	if !byClass[detection.ClassFile].IsObservationGap() {
		t.Errorf("file must be a gap: %+v", byClass[detection.ClassFile])
	}
	// network: shed by the engine → degraded gap (shed takes precedence over the drop annotation).
	nw := byClass[detection.ClassNetwork]
	if nw.State != detection.StateDegraded || !nw.IsObservationGap() {
		t.Errorf("network was shed and must be a degraded gap: %+v", nw)
	}
	// Every class present; none silently clean.
	if len(cov) != len(detection.Classes()) {
		t.Fatalf("coverage must report every class, got %d", len(cov))
	}
}

// TestEngineCountsEmitFailures: a confirmed detection the sink cannot record is not silently lost — it
// is counted and folds the class into a degraded coverage state.
func TestEngineCountsEmitFailures(t *testing.T) {
	sensor := newFakeSensor()
	sensor.coverage = []detection.ClassCoverage{{Class: detection.ClassProcess, HostID: "host-1", State: detection.StateActive}}
	sink := &fakeSink{fail: true}
	e := newEngine(t, sensor, sink, Options{Classes: []detection.Class{detection.ClassProcess}})

	e.process(context.Background(), procEvent("ps")) // matches, but the sink fails

	if len(sink.detections()) != 0 {
		t.Fatal("the sink rejected the emit; nothing should be recorded")
	}
	cov := e.Coverage()
	var proc detection.ClassCoverage
	for _, c := range cov {
		if c.Class == detection.ClassProcess {
			proc = c
		}
	}
	if proc.State != detection.StateDegraded || proc.IsObservationGap() != true {
		t.Fatalf("a class whose detections cannot be recorded must be degraded, got %+v", proc)
	}
}

// TestEngineRunIsSingleCall: Run refuses a second invocation rather than double-processing.
func TestEngineRunIsSingleCall(t *testing.T) {
	sensor, sink := newFakeSensor(), &fakeSink{}
	e := newEngine(t, sensor, sink, Options{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	if err := e.Run(context.Background()); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a second Run must be refused with a validation error, got %v", err)
	}
}

// TestEngineRunLoopProcessesThenStops drives the full Run loop with the fake sensor and a cancel.
func TestEngineRunLoopProcessesThenStops(t *testing.T) {
	sensor, sink := newFakeSensor(), &fakeSink{}
	e := newEngine(t, sensor, sink, Options{})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()

	sensor.events <- procEvent("ps", "-ef")
	// Give the loop a moment, then close the stream to end Run.
	deadline := time.After(2 * time.Second)
	for len(sink.detections()) == 0 {
		select {
		case <-deadline:
			t.Fatal("Run did not process the event")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	close(sensor.events)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after the stream closed")
	}
	_ = cancel
	if !sensor.started {
		t.Error("Run must start the sensor")
	}
}

func dnsEvent(at time.Time, remote string) detection.Event {
	return detection.Event{Class: detection.ClassNetwork, At: at, Host: "host-1",
		Network: &detection.NetworkEvent{Proto: "udp", RemoteAddr: remote, RemotePort: 53, Direction: "egress", PID: 9, Comm: "beacon"}}
}

// The DNS rule is windowed: single packets emit nothing, a burst to one destination emits one detection
// whose evidence is the burst (capped at MaxEvidence), and the count restarts after it fires.
func TestEngineWindowedRuleFiresOnBurstOnly(t *testing.T) {
	sensor := newFakeSensor()
	sink := &fakeSink{}
	eng := newEngine(t, sensor, sink, Options{Classes: []detection.Class{detection.ClassNetwork}})
	rule, ok := detection.Lookup("det.suspicious_dns_beacon")
	if !ok || !rule.Windowed() {
		t.Fatalf("dns rule = %+v", rule)
	}
	t0 := time.Unix(1_000, 0)
	// Spread across two destinations, each below the count: nothing.
	for i := 0; i < rule.Window.Count-1; i++ {
		eng.process(context.Background(), dnsEvent(t0.Add(time.Duration(i)*100*time.Millisecond), "10.0.0.53"))
		eng.process(context.Background(), dnsEvent(t0.Add(time.Duration(i)*100*time.Millisecond), "10.0.0.54"))
	}
	if got := sink.detections(); len(got) != 0 {
		t.Fatalf("emitted %d detections below the burst threshold", len(got))
	}
	eng.process(context.Background(), dnsEvent(t0.Add(time.Duration(rule.Window.Count)*100*time.Millisecond), "10.0.0.53"))
	got := sink.detections()
	if len(got) != 1 || got[0].RuleID != rule.ID || got[0].RuleVersion != 2 {
		t.Fatalf("detections = %+v", got)
	}
	if len(got[0].Evidence) != detection.MaxEvidence || !got[0].Truncated {
		t.Fatalf("burst evidence = %d truncated=%v", len(got[0].Evidence), got[0].Truncated)
	}
	for _, e := range got[0].Evidence {
		if e.Network.RemoteAddr != "10.0.0.53" {
			t.Fatalf("evidence from another destination: %+v", e)
		}
	}
	// The other destination is still one short; one more packet to it fires its own detection.
	eng.process(context.Background(), dnsEvent(t0.Add(time.Duration(rule.Window.Count+1)*100*time.Millisecond), "10.0.0.54"))
	if got := sink.detections(); len(got) != 2 {
		t.Fatalf("second destination did not fire independently: %d", len(got))
	}
}

// TestEngineEmitsSequenceDetection: a downloader then a remote-shell tool on one host becomes a single
// det.tool_staging_sequence detection carrying the ordered pair as evidence, proving the engine routes a
// sequence match through the burst-detection path.
func TestEngineEmitsSequenceDetection(t *testing.T) {
	sensor, sink := newFakeSensor(), &fakeSink{}
	e := newEngine(t, sensor, sink, Options{Classes: []detection.Class{detection.ClassProcess}})

	e.process(context.Background(), procEvent("curl")) // staging: no detection yet
	if got := sink.detections(); len(got) != 0 {
		t.Fatalf("the staging step alone must not detect, got %d", len(got))
	}
	e.process(context.Background(), procEvent("ncat")) // use: completes the sequence

	var seq *detection.Detection
	for i, d := range sink.detections() {
		if d.RuleID == "det.tool_staging_sequence" {
			seq = &sink.detections()[i]
		}
	}
	if seq == nil {
		t.Fatalf("the tool-staging sequence was not detected: %+v", sink.detections())
	}
	if len(seq.Evidence) != 2 || seq.Evidence[0].Process.Comm != "curl" || seq.Evidence[1].Process.Comm != "ncat" {
		t.Fatalf("sequence evidence is not the ordered pair: %+v", seq.Evidence)
	}
}
