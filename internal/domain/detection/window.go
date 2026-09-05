package detection

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Window turns a rule from "every matching event is a detection" into "this many matching events within
// this span, for the same group, is a detection". It is what separates one DNS packet from a burst of
// them to one destination. The predicates still decide which events count; the window decides when the
// count is a finding.
type Window struct {
	// Count is the number of matching events that must fall inside the span (>= 2; a count of one is a
	// plain rule).
	Count int
	// Within is the sliding span measured on event timestamps.
	Within time.Duration
	// GroupBy partitions the count by the values of these fields, so ten queries to ten resolvers do not
	// add up to a burst against one. Empty groups by host only. Fields must belong to the rule's class.
	GroupBy []Field
}

// MaxWindowGroups bounds the distinct groups an Evaluator tracks per rule; beyond it the stalest group is
// dropped. A sensor on a busy host must not let an attacker grow the evaluator without bound by varying
// the grouped field. Memory per rule is bounded by MaxWindowGroups groups, each holding at most
// MaxWindowCount timestamps and MaxEvidence events.
const MaxWindowGroups = 1024

// MaxWindowCount caps a window's count; a detection keeps the last MaxEvidence events of a larger burst
// and marks the evidence truncated.
const MaxWindowCount = 10000

func (w Window) validate(class Class) error {
	if w.Count < 2 {
		return fmt.Errorf("%w: window count must be at least 2 (a count of 1 is a plain rule)", shared.ErrValidation)
	}
	if w.Count > MaxWindowCount {
		return fmt.Errorf("%w: window count %d exceeds the %d cap", shared.ErrValidation, w.Count, MaxWindowCount)
	}
	if w.Within <= 0 {
		return fmt.Errorf("%w: window span must be positive", shared.ErrValidation)
	}
	for _, f := range w.GroupBy {
		fc, ok := fieldClass(f)
		if !ok {
			return fmt.Errorf("%w: window groups by unknown field %q", shared.ErrValidation, f)
		}
		if fc != class {
			return fmt.Errorf("%w: window field %q belongs to class %s, not %s", shared.ErrValidation, f, fc, class)
		}
	}
	return nil
}

func (w *Window) clone() *Window {
	if w == nil {
		return nil
	}
	c := *w
	if w.GroupBy != nil {
		c.GroupBy = append([]Field(nil), w.GroupBy...)
	}
	return &c
}

// Fired is one rule that produced a detection for the evaluated event. For a windowed rule Evidence is
// the burst that crossed the threshold, oldest first; for a plain rule it is nil and the caller supplies
// whatever context it keeps.
type Fired struct {
	Rule     Rule
	Evidence []Event
	// Observed is the number of matching events in the burst that fired (>= len(Evidence)); zero for a
	// plain rule. Pass it to NewBurstDetection so a burst longer than the kept evidence is marked truncated.
	Observed int
}

// Evaluator applies a rule set to a stream of events, keeping the per-group state windowed rules need.
// Plain rules pass straight through Rule.Match. It is not safe for concurrent use; the caller serialises
// events, which a sensor stream already does.
type Evaluator struct {
	rules   []Rule
	buckets map[string]*bucket // rule id -> group key -> burst, flattened as rule\x00group
	perRule map[string]int
}

type bucket struct {
	times  []time.Time // matching event times inside the span, in arrival order, at most Count
	events []Event     // the most recent matching events inside the span, at most MaxEvidence
	newest time.Time
}

// NewEvaluator validates the rules and prepares state for the windowed ones.
func NewEvaluator(rules []Rule) (*Evaluator, error) {
	out := &Evaluator{rules: make([]Rule, 0, len(rules)), buckets: map[string]*bucket{}, perRule: map[string]int{}}
	for _, r := range rules {
		if err := r.Validate(); err != nil {
			return nil, err
		}
		out.rules = append(out.rules, r.clone())
	}
	return out, nil
}

// Evaluate feeds one event and returns the rules that fire on it, in rule order.
func (ev *Evaluator) Evaluate(e Event) []Fired {
	var fired []Fired
	for _, r := range ev.rules {
		if !r.Match(e) {
			continue
		}
		if r.Window == nil {
			fired = append(fired, Fired{Rule: r})
			continue
		}
		if burst, observed, ok := ev.observe(r, e); ok {
			fired = append(fired, Fired{Rule: r, Evidence: burst, Observed: observed})
		}
	}
	return fired
}

// observe records a matching event in its group's bucket and reports the burst once the count is reached
// inside the span. Firing resets the group, so a sustained storm yields one detection per Count events
// rather than one per event past the threshold.
func (ev *Evaluator) observe(r Rule, e Event) ([]Event, int, bool) {
	key := r.ID + "\x00" + groupKey(e, r.Window.GroupBy)
	b, ok := ev.buckets[key]
	if !ok {
		ev.evictIfFull(r.ID)
		b = &bucket{}
		ev.buckets[key] = b
		ev.perRule[r.ID]++
	}
	cutoff := e.At.Add(-r.Window.Within)
	times := b.times[:0]
	for _, t := range b.times {
		if !t.Before(cutoff) {
			times = append(times, t)
		}
	}
	b.times = append(times, e.At)
	events := b.events[:0]
	for _, old := range b.events {
		if !old.At.Before(cutoff) {
			events = append(events, old)
		}
	}
	b.events = append(events, e.clone())
	if len(b.events) > MaxEvidence {
		b.events = b.events[len(b.events)-MaxEvidence:]
	}
	if e.At.After(b.newest) {
		b.newest = e.At
	}
	if len(b.times) < r.Window.Count {
		return nil, 0, false
	}
	observed := len(b.times)
	burst := make([]Event, len(b.events))
	copy(burst, b.events)
	sort.SliceStable(burst, func(i, j int) bool { return burst[i].At.Before(burst[j].At) })
	b.times, b.events = nil, nil
	return burst, observed, true
}

// evictIfFull drops the stalest group of a rule when the rule is at its group cap.
func (ev *Evaluator) evictIfFull(ruleID string) {
	if ev.perRule[ruleID] < MaxWindowGroups {
		return
	}
	prefix := ruleID + "\x00"
	var staleKey string
	var stale time.Time
	for k, b := range ev.buckets {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		if staleKey == "" || b.newest.Before(stale) {
			staleKey, stale = k, b.newest
		}
	}
	if staleKey != "" {
		delete(ev.buckets, staleKey)
		ev.perRule[ruleID]--
	}
}

// groupKey renders the grouped field values of an event. A field the event lacks contributes an empty
// segment, so events missing the field still group together rather than each forming its own group.
func groupKey(e Event, fields []Field) string {
	if len(fields) == 0 {
		return string(e.Host)
	}
	parts := make([]string, 0, len(fields)+1)
	parts = append(parts, string(e.Host))
	for _, f := range fields {
		if fieldIsNumeric(f) {
			if v, ok := e.intField(f); ok {
				parts = append(parts, strconv.Itoa(v))
				continue
			}
			parts = append(parts, "")
			continue
		}
		vals, ok := e.stringFields(f)
		if !ok || len(vals) == 0 {
			parts = append(parts, "")
			continue
		}
		parts = append(parts, strings.Join(vals, ","))
	}
	return strings.Join(parts, "\x1f")
}
