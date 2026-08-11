package detection

import (
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Rule is a typed, versioned, clean-room detection definition. It matches over one event class and, on a
// match, the engine emits a Detection carrying the matched evidence. Rules are catalogued exactly like
// the SAST catalogue, with a drift test that fails the build if the shipped catalogue does not validate.
//
// ID is stable and public-facing: it is the detection id the emulation catalogue (#421) names as the
// expected observable, so the purple ledger (#426) can reconcile executed techniques against detections
// by this id. Changing an ID breaks that linkage, so IDs are append-only in practice.
type Rule struct {
	ID       string // stable, catalogued; matches an emulation ExpectedObservable.DetectionID
	Version  int
	Class    Class
	Title    string
	Severity shared.Severity
	Matcher  Matcher
}

// Validate enforces the invariants a catalogued rule must hold. A rule that fails these cannot produce a
// trustworthy detection and must not ship.
func (r Rule) Validate() error {
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("%w: rule has no id", shared.ErrValidation)
	}
	if r.Version < 1 {
		return fmt.Errorf("%w: rule %s must be versioned (>=1)", shared.ErrValidation, r.ID)
	}
	if !r.Class.Valid() {
		return fmt.Errorf("%w: rule %s has an unknown class %q", shared.ErrValidation, r.ID, r.Class)
	}
	if strings.TrimSpace(r.Title) == "" {
		return fmt.Errorf("%w: rule %s has no title", shared.ErrValidation, r.ID)
	}
	// A detection with severity "unknown" cannot be prioritised, so a rule must carry a concrete one.
	if !r.Severity.Valid() || r.Severity == shared.SeverityUnknown {
		return fmt.Errorf("%w: rule %s has an invalid severity %q", shared.ErrValidation, r.ID, r.Severity)
	}
	if r.Matcher.Class != r.Class {
		return fmt.Errorf("%w: rule %s class %s does not match its matcher's class %s",
			shared.ErrValidation, r.ID, r.Class, r.Matcher.Class)
	}
	if err := r.Matcher.validate(); err != nil {
		return fmt.Errorf("rule %s: %w", r.ID, err)
	}
	return nil
}

// Match reports whether an event satisfies this rule. It observes and matches only — it never executes
// anything (golden rule 1); the Matcher is typed data, not a shell expression.
func (r Rule) Match(e Event) bool {
	return r.Matcher.Match(e)
}

// clone returns a deep copy of the rule: the Matcher's predicate slice and each predicate's Values slice
// are copied, not aliased. The catalogue accessors return clones so a caller cannot reach through a
// returned rule and mutate the package-level rule set — a runtime-mutable detection catalogue would be a
// security defect, not just a style one.
func (r Rule) clone() Rule {
	c := r
	if r.Matcher.All != nil {
		preds := make([]Predicate, len(r.Matcher.All))
		for i, p := range r.Matcher.All {
			pc := p
			if p.Values != nil {
				pc.Values = append([]string(nil), p.Values...)
			}
			preds[i] = pc
		}
		c.Matcher.All = preds
	}
	return c
}
