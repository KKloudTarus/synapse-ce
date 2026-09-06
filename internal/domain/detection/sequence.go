package detection

import (
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// MaxSequenceSteps bounds a sequence rule's length. Per-group state holds at most this many events, so a
// rule cannot make the evaluator allocate an unbounded partial match.
const MaxSequenceSteps = 8

// Sequence turns a rule from "one matching event is a detection" into "these matchers, satisfied by
// events of the rule's class IN THIS ORDER, for the same group, all within this span, is a detection".
// It expresses an ordered behaviour that no single event and no rate shows: stage a tool, then use it;
// probe identity, then attempt escalation. The steps match over the rule's own class; a cross-class
// sequence is out of scope for the per-class engine, which sees one class at a time.
type Sequence struct {
	// Steps are the ordered matchers. An event advances the sequence only when it matches the next
	// unsatisfied step. At least two steps: a one-step sequence is a plain rule.
	Steps []Matcher
	// Within is the span from the FIRST matched step's event to the last, exclusive. A partial match that
	// lapses is reset, so a slow, unrelated recurrence is never stitched into a sequence.
	Within time.Duration
	// GroupBy partitions progress by these fields so two hosts' (or two entities') unrelated events do
	// not interleave into one sequence. Empty groups by host only. Fields must belong to the rule's class.
	GroupBy []Field
}

func (s Sequence) validate(class Class) error {
	if len(s.Steps) < 2 {
		return fmt.Errorf("%w: sequence needs at least 2 steps (a one-step sequence is a plain rule)", shared.ErrValidation)
	}
	if len(s.Steps) > MaxSequenceSteps {
		return fmt.Errorf("%w: sequence has %d steps, over the %d cap", shared.ErrValidation, len(s.Steps), MaxSequenceSteps)
	}
	if s.Within <= 0 {
		return fmt.Errorf("%w: sequence span must be positive", shared.ErrValidation)
	}
	for i, step := range s.Steps {
		if step.Class != class {
			return fmt.Errorf("%w: sequence step %d matches class %s, not the rule's class %s", shared.ErrValidation, i, step.Class, class)
		}
		if err := step.validate(); err != nil {
			return fmt.Errorf("sequence step %d: %w", i, err)
		}
	}
	for _, f := range s.GroupBy {
		fc, ok := fieldClass(f)
		if !ok {
			return fmt.Errorf("%w: sequence groups by unknown field %q", shared.ErrValidation, f)
		}
		if fc != class {
			return fmt.Errorf("%w: sequence field %q belongs to class %s, not %s", shared.ErrValidation, f, fc, class)
		}
	}
	return nil
}

func (s *Sequence) clone() *Sequence {
	if s == nil {
		return nil
	}
	c := *s
	if s.Steps != nil {
		steps := make([]Matcher, len(s.Steps))
		for i, m := range s.Steps {
			steps[i] = m.clone()
		}
		c.Steps = steps
	}
	if s.GroupBy != nil {
		c.GroupBy = append([]Field(nil), s.GroupBy...)
	}
	return &c
}
