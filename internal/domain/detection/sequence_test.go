package detection

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func seqEvent(at time.Time, host shared.ID, comm string) Event {
	return Event{Class: ClassProcess, At: at, Host: host, Process: &ProcessEvent{PID: 7, Comm: comm, Path: "/usr/bin/" + comm}}
}

func stepMatcher(values ...string) Matcher {
	return Matcher{Class: ClassProcess, All: []Predicate{{Field: FieldProcComm, Op: OpIn, Values: values}}}
}

func sequenceRule(within time.Duration) Rule {
	return Rule{
		ID: "det.test_sequence", Version: 1, Class: ClassProcess, Title: "seq", Severity: shared.SeverityHigh,
		Sequence: &Sequence{Within: within, Steps: []Matcher{stepMatcher("curl", "wget"), stepMatcher("nc", "ncat")}},
	}
}

func TestSequenceValidation(t *testing.T) {
	if err := sequenceRule(time.Minute).Validate(); err != nil {
		t.Fatalf("valid sequence rule rejected: %v", err)
	}
	base := func() Rule { return sequenceRule(time.Minute) }
	cases := map[string]func(r *Rule){
		"one step": func(r *Rule) { r.Sequence.Steps = r.Sequence.Steps[:1] },
		"no span":  func(r *Rule) { r.Sequence.Within = 0 },
		"cross-class step": func(r *Rule) {
			r.Sequence.Steps[1] = Matcher{Class: ClassNetwork, All: []Predicate{{Field: FieldNetRemotePort, Op: OpEquals, Value: "53"}}}
		},
		"empty step matcher":  func(r *Rule) { r.Sequence.Steps[0] = Matcher{Class: ClassProcess} },
		"bad groupby field":   func(r *Rule) { r.Sequence.GroupBy = []Field{"nope"} },
		"cross-class groupby": func(r *Rule) { r.Sequence.GroupBy = []Field{FieldNetRemoteAddr} },
		"also windowed":       func(r *Rule) { r.Window = &Window{Count: 2, Within: time.Minute} },
		"non-empty top match": func(r *Rule) {
			r.Matcher = Matcher{Class: ClassProcess, All: []Predicate{{Field: FieldProcComm, Op: OpEquals, Value: "x"}}}
		},
	}
	for name, mut := range cases {
		r := base()
		mut(&r)
		if err := r.Validate(); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: err = %v, want ErrValidation", name, err)
		}
	}
	// Over the step cap.
	over := base()
	steps := make([]Matcher, MaxSequenceSteps+1)
	for i := range steps {
		steps[i] = stepMatcher("curl")
	}
	over.Sequence.Steps = steps
	if err := over.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("over step cap: err = %v, want ErrValidation", err)
	}
}

func TestEvaluatorSequenceFiresInOrderWithinSpan(t *testing.T) {
	ev, err := NewEvaluator([]Rule{sequenceRule(2 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Unix(1_000, 0)

	// Step 1 alone does not fire.
	if fired := ev.Evaluate(seqEvent(t0, "h", "curl")); len(fired) != 0 {
		t.Fatalf("fired on the first step alone: %+v", fired)
	}
	// An unrelated event in between does not break the sequence.
	if fired := ev.Evaluate(seqEvent(t0.Add(time.Second), "h", "ps")); len(fired) != 0 {
		t.Fatalf("unrelated event fired: %+v", fired)
	}
	// The second step completes the sequence.
	fired := ev.Evaluate(seqEvent(t0.Add(30*time.Second), "h", "nc"))
	if len(fired) != 1 {
		t.Fatalf("second step should complete the sequence, got %d", len(fired))
	}
	if len(fired[0].Evidence) != 2 || fired[0].Evidence[0].Process.Comm != "curl" || fired[0].Evidence[1].Process.Comm != "nc" {
		t.Fatalf("evidence is not the ordered pair: %+v", fired[0].Evidence)
	}
}

func TestEvaluatorSequenceIgnoresWrongOrder(t *testing.T) {
	ev, _ := NewEvaluator([]Rule{sequenceRule(2 * time.Minute)})
	t0 := time.Unix(2_000, 0)
	// Second step first, then first step: no completed sequence.
	if fired := ev.Evaluate(seqEvent(t0, "h", "nc")); len(fired) != 0 {
		t.Fatalf("second step alone fired: %+v", fired)
	}
	if fired := ev.Evaluate(seqEvent(t0.Add(time.Second), "h", "curl")); len(fired) != 0 {
		t.Fatalf("out-of-order events fired: %+v", fired)
	}
}

func TestEvaluatorSequenceResetsWhenLapsed(t *testing.T) {
	ev, _ := NewEvaluator([]Rule{sequenceRule(time.Minute)})
	t0 := time.Unix(3_000, 0)
	ev.Evaluate(seqEvent(t0, "h", "curl"))
	// The second step arrives after the span: the partial match has lapsed, so nothing fires.
	if fired := ev.Evaluate(seqEvent(t0.Add(90*time.Second), "h", "nc")); len(fired) != 0 {
		t.Fatalf("a lapsed sequence fired: %+v", fired)
	}
}

func TestEvaluatorSequenceGroupsByHost(t *testing.T) {
	ev, _ := NewEvaluator([]Rule{sequenceRule(2 * time.Minute)})
	t0 := time.Unix(4_000, 0)
	// host a stages, host b uses: two different hosts must not stitch into one sequence.
	ev.Evaluate(seqEvent(t0, "host-a", "curl"))
	if fired := ev.Evaluate(seqEvent(t0.Add(time.Second), "host-b", "nc")); len(fired) != 0 {
		t.Fatalf("events on different hosts completed a sequence: %+v", fired)
	}
	// host a completing its own sequence still fires.
	if fired := ev.Evaluate(seqEvent(t0.Add(2*time.Second), "host-a", "nc")); len(fired) != 1 {
		t.Fatalf("same-host sequence should fire, got %d", len(fired))
	}
}

// TestCataloguedSequenceFires proves the shipped tool-staging sequence rule reconciles through a fresh
// evaluator built from the catalogue: a downloader then a remote-shell tool on one host completes it.
func TestCataloguedSequenceFires(t *testing.T) {
	rules, err := CatalogueByClass(ClassProcess)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := NewEvaluator(rules)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Unix(5_000, 0)
	ev.Evaluate(seqEvent(t0, "h", "wget"))
	fired := ev.Evaluate(seqEvent(t0.Add(10*time.Second), "h", "ncat"))
	var got bool
	for _, f := range fired {
		if f.Rule.ID == "det.tool_staging_sequence" {
			got = true
		}
	}
	if !got {
		t.Fatalf("the catalogued tool-staging sequence did not fire; got %+v", fired)
	}
}

// TestEvaluatorSequenceRestartsOnRepeatedFirstStep proves a repeated staging is not missed: A, A, B where
// the second A and the B are within the span must fire, even though the first A's window would lapse.
func TestEvaluatorSequenceRestartsOnRepeatedFirstStep(t *testing.T) {
	ev, _ := NewEvaluator([]Rule{sequenceRule(2 * time.Minute)})
	t0 := time.Unix(6_000, 0)
	if fired := ev.Evaluate(seqEvent(t0, "h", "curl")); len(fired) != 0 {
		t.Fatalf("first staging fired alone: %+v", fired)
	}
	// A second staging 119s later supersedes the first (which is about to lapse).
	if fired := ev.Evaluate(seqEvent(t0.Add(119*time.Second), "h", "curl")); len(fired) != 0 {
		t.Fatalf("second staging fired alone: %+v", fired)
	}
	// The remote shell 61s after the second staging is inside its span, so the sequence fires.
	fired := ev.Evaluate(seqEvent(t0.Add(180*time.Second), "h", "nc"))
	if len(fired) != 1 {
		t.Fatalf("the restarted sequence should fire, got %d", len(fired))
	}
	if fired[0].Evidence[0].Process.Comm != "curl" || !fired[0].Evidence[0].At.Equal(t0.Add(119*time.Second)) {
		t.Fatalf("evidence should start from the SECOND staging, got %+v", fired[0].Evidence[0])
	}
}

// TestEvaluatorSequenceFiresAgainAfterCompletion proves a completed sequence frees its group, so an
// identical later sequence on the same host fires again rather than being swallowed.
func TestEvaluatorSequenceFiresAgainAfterCompletion(t *testing.T) {
	ev, _ := NewEvaluator([]Rule{sequenceRule(2 * time.Minute)})
	t0 := time.Unix(7_000, 0)
	ev.Evaluate(seqEvent(t0, "h", "curl"))
	if fired := ev.Evaluate(seqEvent(t0.Add(time.Second), "h", "nc")); len(fired) != 1 {
		t.Fatalf("first sequence should fire, got %d", len(fired))
	}
	ev.Evaluate(seqEvent(t0.Add(10*time.Second), "h", "curl"))
	if fired := ev.Evaluate(seqEvent(t0.Add(11*time.Second), "h", "nc")); len(fired) != 1 {
		t.Fatalf("a second identical sequence should fire again, got %d", len(fired))
	}
}

// TestSequenceRuleReturnsAreImmutable proves a returned sequence rule cannot be reached through to mutate
// the package catalogue: the deep copy must cover the step matchers' Values, which the plain-rule
// immutability test never touches (a sequence rule's top-level Matcher.All is nil).
func TestSequenceRuleReturnsAreImmutable(t *testing.T) {
	r, ok := Lookup("det.tool_staging_sequence")
	if !ok || r.Sequence == nil || len(r.Sequence.Steps) == 0 || len(r.Sequence.Steps[0].All) == 0 {
		t.Fatal("expected the catalogued tool-staging sequence with step predicates")
	}
	r.Sequence.Steps[0].All[0].Values[0] = "TAMPERED"
	r.Sequence.Steps[0].All[0].Value = "TAMPERED"

	fresh, ok := Lookup("det.tool_staging_sequence")
	if !ok {
		t.Fatal("re-lookup failed")
	}
	for _, v := range fresh.Sequence.Steps[0].All[0].Values {
		if v == "TAMPERED" {
			t.Fatal("mutating a returned sequence rule's step Values leaked into the catalogue")
		}
	}
	if fresh.Sequence.Steps[0].All[0].Value == "TAMPERED" {
		t.Fatal("mutating a returned sequence rule's step Value leaked into the catalogue")
	}
}

// TestEvaluatorSequenceGroupsAreBounded proves an attacker cannot grow the evaluator without bound by
// varying the grouped field: a sequence rule grouped by a high-cardinality field, fed a unique first-step
// value per event, never holds more than MaxWindowGroups partial matches, and only step-0 events allocate
// a group at all (an unrelated event allocates nothing).
func TestEvaluatorSequenceGroupsAreBounded(t *testing.T) {
	r := Rule{
		ID: "det.test_seq_grouped", Version: 1, Class: ClassProcess, Title: "seq", Severity: shared.SeverityHigh,
		Sequence: &Sequence{Within: time.Hour, GroupBy: []Field{FieldProcPath}, Steps: []Matcher{stepMatcher("curl"), stepMatcher("nc")}},
	}
	ev, err := NewEvaluator([]Rule{r})
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Unix(8_000, 0)
	// Unrelated events allocate no group.
	for i := 0; i < 100; i++ {
		ev.Evaluate(Event{Class: ClassProcess, At: t0, Host: "h", Process: &ProcessEvent{Comm: "bash", Path: "/bin/bash" + string(rune(i))}})
	}
	if n := len(ev.seqs[r.ID]); n != 0 {
		t.Fatalf("unrelated events allocated %d groups, want 0", n)
	}
	// A step-0 event per unique path, well past the cap.
	for i := 0; i < MaxWindowGroups+500; i++ {
		ev.Evaluate(Event{Class: ClassProcess, At: t0.Add(time.Duration(i) * time.Millisecond), Host: "h", Process: &ProcessEvent{Comm: "curl", Path: "/p/" + string(rune(i))}})
	}
	if n := len(ev.seqs[r.ID]); n > MaxWindowGroups {
		t.Fatalf("group count %d exceeds the %d cap", n, MaxWindowGroups)
	}
}
