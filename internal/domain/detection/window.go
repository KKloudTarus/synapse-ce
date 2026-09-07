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
	// Within is the sliding span measured on event timestamps, exclusive: events exactly Within apart
	// are not in one burst.
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
	buckets map[string]map[string]*bucket      // rule id -> group key -> burst
	seqs    map[string]map[string]*seqProgress // rule id -> group key -> ordered partial match
}

type bucket struct {
	times  []time.Time // matching event times inside the span, in arrival order, at most Count
	events []Event     // the most recent matching events inside the span, at most MaxEvidence
	newest time.Time
}

// seqProgress is one group's partial match of a sequence rule: how many steps are satisfied, the events
// that satisfied them, and the instant the whole sequence must finish by (first-match time + Within).
type seqProgress struct {
	step     int
	events   []Event
	deadline time.Time
}

// NewEvaluator validates the rules and prepares state for the windowed and sequence ones.
func NewEvaluator(rules []Rule) (*Evaluator, error) {
	out := &Evaluator{rules: make([]Rule, 0, len(rules)), buckets: map[string]map[string]*bucket{}, seqs: map[string]map[string]*seqProgress{}}
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
		if r.Sequence != nil {
			if burst, ok := ev.observeSequence(r, e); ok {
				fired = append(fired, Fired{Rule: r, Evidence: burst, Observed: len(burst)})
			}
			continue
		}
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

// observeSequence advances a sequence rule's partial match for the event's group and reports the ordered
// evidence once the last step is satisfied within the span. A group holds a partial match only while one
// is live: a lapsed or completed match is deleted, and an event that neither advances a live match nor
// starts one leaves no group. So an unrelated event never occupies a slot, and it cannot evict another
// group's live partial match. An event that matches the first step while a later step was pending
// restarts the sequence from that event, so a repeated staging is not missed.
func (ev *Evaluator) observeSequence(r Rule, e Event) ([]Event, bool) {
	if e.Class != r.Class {
		return nil, false // an event of another class cannot advance a same-class sequence
	}
	groups := ev.seqs[r.ID]
	if groups == nil {
		groups = map[string]*seqProgress{}
		ev.seqs[r.ID] = groups
	}
	key := groupKey(e, r.Sequence.GroupBy)
	if p := groups[key]; p != nil {
		// The next step advances the match, but only inside the anchor's span and not before the last
		// matched event: a skewed timestamp (kernel vs wall-clock) must neither extend the span nor
		// reorder the evidence. A late or out-of-order event simply does not advance.
		last := p.events[len(p.events)-1].At
		if e.At.Before(p.deadline) && !e.At.Before(last) && r.Sequence.Steps[p.step].Match(e) {
			p.events = append(p.events, e.clone())
			p.step++
			if p.step < len(r.Sequence.Steps) {
				return nil, false
			}
			burst := make([]Event, len(p.events))
			copy(burst, p.events)
			if len(burst) > MaxEvidence {
				burst = burst[len(burst)-MaxEvidence:]
			}
			delete(groups, key) // completed: free the group so an identical later sequence fires again
			return burst, true
		}
		// A fresh first step re-anchors the (possibly stalled) match to this newer staging, so a repeated
		// downloader whose use lands after the first anchor's span is not missed.
		if r.Sequence.Steps[0].Match(e) {
			p.step, p.events, p.deadline = 1, []Event{e.clone()}, e.At.Add(r.Sequence.Within)
		}
		// Otherwise the live match is left untouched: an unrelated event, even one with a skewed forward
		// timestamp, never drops it. An expired match is reclaimed lazily by evictSeqIfFull, which frees
		// expired groups first, so memory stays bounded without trusting a stray timestamp.
		return nil, false
	}

	// No live match for this group: only a first-step event starts one, so unrelated events never
	// allocate a slot. A sequence has at least two steps, so a first-step match never completes here.
	if !r.Sequence.Steps[0].Match(e) {
		return nil, false
	}
	evictSeqIfFull(groups)
	groups[key] = &seqProgress{step: 1, events: []Event{e.clone()}, deadline: e.At.Add(r.Sequence.Within)}
	return nil, false
}

// evictSeqIfFull makes room for a new group when a sequence rule is at its group cap, which is only
// reached by that many concurrent LIVE partial matches (unrelated events hold no group). It drops exactly
// the earliest-deadline (stalest) match, with the lowest group key breaking a tie so eviction is
// deterministic and never depends on map iteration order. It does NOT compare deadlines to any incoming
// event's timestamp: a skewed step-0 timestamp must not be able to reclassify other groups as expired and
// evict live partial matches en masse. The earliest-deadline group is the stalest whether it has expired
// or not, so a single deterministic drop is both correct and skew-proof.
func evictSeqIfFull(groups map[string]*seqProgress) {
	if len(groups) < MaxWindowGroups {
		return
	}
	var victim string
	var earliest time.Time
	found := false
	for k, p := range groups {
		if !found || p.deadline.Before(earliest) || (p.deadline.Equal(earliest) && k < victim) {
			victim, earliest, found = k, p.deadline, true
		}
	}
	if found {
		delete(groups, victim)
	}
}

// observe records a matching event in its group's bucket and reports the burst once the count is reached
// inside the span. Firing resets the group, so a sustained storm yields one detection per Count events
// rather than one per event past the threshold.
func (ev *Evaluator) observe(r Rule, e Event) ([]Event, int, bool) {
	groups := ev.buckets[r.ID]
	if groups == nil {
		groups = map[string]*bucket{}
		ev.buckets[r.ID] = groups
	}
	key := groupKey(e, r.Window.GroupBy)
	b, ok := groups[key]
	if !ok {
		evictIfFull(groups, e.At.Add(-r.Window.Within))
		b = &bucket{}
		groups[key] = b
	}
	// The span is measured from the newest event the group has seen, not from this arrival: events
	// reach the evaluator in arrival order, and a late event stamped long before the others (a drained
	// kernel timestamp behind a wall-clock fallback) must neither extend the span nor count in it.
	if e.At.After(b.newest) {
		b.newest = e.At
	}
	cutoff := b.newest.Add(-r.Window.Within)
	if !e.At.After(cutoff) {
		return nil, 0, false // older than the span: cannot be part of this burst
	}
	times := b.times[:0]
	for _, t := range b.times {
		if t.After(cutoff) {
			times = append(times, t)
		}
	}
	b.times = append(times, e.At)
	events := b.events[:0]
	for _, old := range b.events {
		if old.At.After(cutoff) {
			events = append(events, old)
		}
	}
	b.events = append(events, e.clone())
	if len(b.events) > MaxEvidence {
		b.events = b.events[len(b.events)-MaxEvidence:]
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

// evictIfFull makes room for a new group when a rule is at its group cap. Groups whose newest event is
// already outside the span can no longer complete a burst, so they go first; only when none has
// expired is the stalest live group dropped. The scan covers one rule's groups, never every rule's.
func evictIfFull(groups map[string]*bucket, cutoff time.Time) {
	if len(groups) < MaxWindowGroups {
		return
	}
	var staleKey string
	var stale time.Time
	for k, b := range groups {
		if !b.newest.After(cutoff) {
			delete(groups, k)
			continue
		}
		if staleKey == "" || b.newest.Before(stale) {
			staleKey, stale = k, b.newest
		}
	}
	if len(groups) >= MaxWindowGroups && staleKey != "" {
		delete(groups, staleKey)
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
