// Package detect is the agent-side detection engine (issue #422, phase 3). It runs ON THE AGENT: it
// consumes the per-class event stream from a DetectionSensor, evaluates the clean-room rule catalogue
// against each event, and emits a detection — with a bounded context window — for every match.
//
// It is deterministic-first and observe-only: the engine matches typed rules and emits detections; it
// never executes anything (golden rule 1). It enforces a CPU ceiling by SHEDDING whole event classes in
// a defined order and reporting that it did, and it reports per-class coverage that folds in the
// sensor's gaps, its own shedding, and back-pressure drops — so a class the agent is not fully observing
// is never presented as clean.
package detect

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// LoadSampler reports the CPU cost currently attributable to detection, as a percentage of one core. The
// engine samples it to decide whether to shed load. A real implementation reads getrusage; tests inject
// a deterministic one.
type LoadSampler interface {
	CPUPercent() float64
}

// nopSampler always reports zero load — the default when the caller wires no sampler. With it the engine
// never sheds, which is the safe default (shed only on a measured, wired signal).
type nopSampler struct{}

func (nopSampler) CPUPercent() float64 { return 0 }

// shedOrder is the DEFINED order in which classes are shed under CPU pressure: highest-volume / lowest
// marginal value first, most security-critical last. File opens are the loudest and cheapest to lose;
// privilege changes are the rarest and most important, so they are shed only as a last resort.
var shedOrder = []detection.Class{
	detection.ClassFile,
	detection.ClassNetwork,
	detection.ClassProcess,
	detection.ClassPrivilege,
}

// ShedEvent records that a class was shed to stay under the CPU ceiling, so the action is auditable and
// visible rather than a silent drop in coverage.
type ShedEvent struct {
	Class      detection.Class
	At         time.Time
	CPUAtShed  float64
	CeilingPct float64
}

// Options configures an engine.
type Options struct {
	Classes        []detection.Class // classes to evaluate; defaults to all
	CPUCeilingPct  float64           // shed when the sampler exceeds this; 0 disables shedding
	Sampler        LoadSampler       // load source; nil → never sheds
	SampleInterval time.Duration     // minimum spacing between load samples; 0 → sample every event
	ContextWindow  int               // events of context kept per class; defaults to DefaultContextWindow
	Clock          ports.Clock
}

// DefaultContextWindow is how many recent same-class events accompany a detection as bounded context.
const DefaultContextWindow = 16

// Engine ties a sensor to the rule catalogue.
type Engine struct {
	sensor   ports.DetectionSensor
	sink     ports.DetectionSink
	host     shared.ID
	agentID  shared.ID
	rules    map[detection.Class][]detection.Rule
	enabled  map[detection.Class]bool
	ceiling  float64
	sampler  LoadSampler
	interval time.Duration
	window   int
	clock    ports.Clock

	mu         sync.Mutex
	started    bool
	shed       map[detection.Class]bool
	shedLog    []ShedEvent
	ctxBuf     map[detection.Class][]detection.Event
	emitFail   map[detection.Class]uint64
	lastSample time.Time
}

// NewEngine validates dependencies and loads the rule catalogue for the enabled classes.
func NewEngine(sensor ports.DetectionSensor, sink ports.DetectionSink, host, agentID shared.ID, opts Options) (*Engine, error) {
	if sensor == nil || sink == nil {
		return nil, fmt.Errorf("%w: detection engine needs a sensor and a sink", shared.ErrValidation)
	}
	if host == "" || agentID == "" {
		return nil, fmt.Errorf("%w: detection engine needs a host and agent identity", shared.ErrValidation)
	}
	classes := opts.Classes
	if len(classes) == 0 {
		classes = detection.Classes()
	}
	enabled := make(map[detection.Class]bool, len(classes))
	rules := make(map[detection.Class][]detection.Rule, len(classes))
	for _, c := range classes {
		if !c.Valid() {
			return nil, fmt.Errorf("%w: unknown detection class %q", shared.ErrValidation, c)
		}
		enabled[c] = true
		rs, err := detection.CatalogueByClass(c)
		if err != nil {
			return nil, fmt.Errorf("load rules for %s: %w", c, err)
		}
		rules[c] = rs
	}
	sampler := opts.Sampler
	if sampler == nil {
		sampler = nopSampler{}
	}
	clock := opts.Clock
	if clock == nil {
		clock = systemClock{}
	}
	window := opts.ContextWindow
	if window <= 0 {
		window = DefaultContextWindow
	}
	return &Engine{
		sensor: sensor, sink: sink, host: host, agentID: agentID,
		rules: rules, enabled: enabled, ceiling: opts.CPUCeilingPct, sampler: sampler,
		interval: opts.SampleInterval, window: window, clock: clock,
		shed: map[detection.Class]bool{}, ctxBuf: map[detection.Class][]detection.Event{},
		emitFail: map[detection.Class]uint64{},
	}, nil
}

// Run starts the sensor and processes events until the context is cancelled or the sensor's event stream
// closes. It always closes the sensor on return. It is a single blocking call; do not call it twice.
func (e *Engine) Run(ctx context.Context) (err error) {
	e.mu.Lock()
	if e.started {
		e.mu.Unlock()
		return fmt.Errorf("%w: detection engine already run", shared.ErrValidation)
	}
	e.started = true
	e.mu.Unlock()

	if serr := e.sensor.Start(ctx); serr != nil {
		return fmt.Errorf("start sensor: %w", serr)
	}
	// Surface a failed detach rather than swallowing it — but only when Run has no more pressing error
	// to report (a cancel or a start failure takes precedence).
	defer func() {
		if cerr := e.sensor.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("close sensor: %w", cerr)
		}
	}()

	events := e.sensor.Events()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, ok := <-events:
			if !ok {
				return nil // sensor closed its stream
			}
			e.process(ctx, ev)
		}
	}
}

// process handles one event: sample load (maybe shed), then — unless the class is shed or disabled —
// buffer it as context and evaluate every rule for its class, emitting a detection per match.
func (e *Engine) process(ctx context.Context, ev detection.Event) {
	if !e.enabled[ev.Class] {
		return
	}
	e.maybeShed(ev.Class)

	e.mu.Lock()
	if e.shed[ev.Class] {
		e.mu.Unlock()
		return // this class is shed to stay under the ceiling; its events are not evaluated
	}
	window := e.pushContextLocked(ev)
	rules := e.rules[ev.Class]
	e.mu.Unlock()

	for _, r := range rules {
		if !r.Match(ev) {
			continue
		}
		d, err := detection.NewDetection(r, e.host, e.agentID, window, e.clock.Now().UTC())
		if err != nil {
			// A malformed event cannot produce a detection. Skip rather than emit a bad one, but COUNT
			// it — a matched rule that produced nothing is a coverage signal, not a silent miss.
			e.recordEmitFailure(ev.Class)
			continue
		}
		if err := e.sink.Emit(ctx, d); err != nil {
			// The detection was confirmed but could not be recorded. That is not silent: it is counted and
			// folds into Coverage as a degraded class, so an operator sees the class's record is incomplete.
			e.recordEmitFailure(ev.Class)
		}
	}
}

// recordEmitFailure counts a matched rule whose detection could not be built or emitted, per class.
func (e *Engine) recordEmitFailure(c detection.Class) {
	e.mu.Lock()
	e.emitFail[c]++
	e.mu.Unlock()
}

// pushContextLocked appends the event to its class's bounded ring and returns the current window (a copy)
// to accompany a detection. The window is the recent same-class events ending with the trigger — bounded
// so a detection stays small (the domain further caps it at detection.MaxEvidence).
func (e *Engine) pushContextLocked(ev detection.Event) []detection.Event {
	buf := append(e.ctxBuf[ev.Class], ev)
	if len(buf) > e.window {
		buf = buf[len(buf)-e.window:]
	}
	e.ctxBuf[ev.Class] = buf
	out := make([]detection.Event, len(buf))
	copy(out, buf)
	return out
}

// maybeShed samples the load (respecting the minimum sample interval) and, if it exceeds the ceiling,
// sheds the next class in the defined order that is enabled and not already shed. It records the action.
func (e *Engine) maybeShed(_ detection.Class) {
	if e.ceiling <= 0 {
		return // shedding disabled
	}
	now := e.clock.Now()
	e.mu.Lock()
	if e.interval > 0 && !e.lastSample.IsZero() && now.Sub(e.lastSample) < e.interval {
		e.mu.Unlock()
		return
	}
	e.lastSample = now
	e.mu.Unlock()

	cpu := e.sampler.CPUPercent()
	if cpu <= e.ceiling {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, c := range shedOrder {
		if e.enabled[c] && !e.shed[c] {
			e.shed[c] = true
			e.shedLog = append(e.shedLog, ShedEvent{Class: c, At: now.UTC(), CPUAtShed: cpu, CeilingPct: e.ceiling})
			return // shed exactly one class per breach; re-check on the next sample
		}
	}
}

// ShedLog returns the classes shed under load pressure, in order — the report that shedding occurred.
func (e *Engine) ShedLog() []ShedEvent {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]ShedEvent, len(e.shedLog))
	copy(out, e.shedLog)
	return out
}

// Coverage returns the honest per-class observation status: the sensor's coverage, with a class the
// engine has shed downgraded to a degraded gap, and a class the sensor is dropping under back-pressure
// likewise downgraded. A class the engine does not evaluate is never reported as cleanly observed.
func (e *Engine) Coverage() []detection.ClassCoverage {
	sensorCov := e.sensor.Coverage()
	dropped := e.sensor.Dropped()

	e.mu.Lock()
	shed := make(map[detection.Class]bool, len(e.shed))
	for c, v := range e.shed {
		shed[c] = v
	}
	emitFail := make(map[detection.Class]uint64, len(e.emitFail))
	for c, v := range e.emitFail {
		emitFail[c] = v
	}
	e.mu.Unlock()

	out := make([]detection.ClassCoverage, 0, len(sensorCov))
	for _, cc := range sensorCov {
		switch {
		case shed[cc.Class]:
			cc.State = detection.StateDegraded
			cc.Reason = "shed by the engine to stay under the CPU ceiling"
		case dropped[cc.Class] > 0 && cc.State == detection.StateActive:
			cc.State = detection.StateDegraded
			cc.Reason = fmt.Sprintf("dropping events under back-pressure (%d dropped)", dropped[cc.Class])
		case emitFail[cc.Class] > 0 && cc.State == detection.StateActive:
			cc.State = detection.StateDegraded
			cc.Reason = fmt.Sprintf("%d detection(s) matched but could not be recorded", emitFail[cc.Class])
		}
		out = append(out, cc)
	}
	return out
}

// systemClock is the default wall clock.
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }
