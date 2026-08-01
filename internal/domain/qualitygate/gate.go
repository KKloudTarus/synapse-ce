// Package qualitygate is the deterministic pass/fail gate over a codebase's measured metrics – the
// "Clean as You Code" quality gate. It is pure domain: types + evaluation, no I/O, no LLM. A Gate is a
// list of conditions on named metrics (e.g. new_critical <= 0); Evaluate returns pass/fail plus the exact
// conditions that failed, so a CI step can print an actionable reason.
package qualitygate

import (
	"fmt"
	"regexp"
	"strings"
)

// Op is a comparison operator for a condition.
type Op string

const (
	OpLE Op = "<=" // metric must be at most threshold (the common "no more than" gate)
	OpGE Op = ">=" // metric must be at least threshold (e.g. coverage)
	OpEQ Op = "==" // metric must equal threshold
	OpLT Op = "<"
	OpGT Op = ">"
)

// Condition asserts one metric relates to a threshold. Metric names are documented in metrics.go.
type Condition struct {
	Metric    string  `yaml:"metric" json:"metric"`
	Op        Op      `yaml:"op" json:"op"`
	Threshold float64 `yaml:"threshold" json:"threshold"`
}

// Gate is a named set of conditions; all must hold for the gate to pass.
type Gate struct {
	Key        string      `yaml:"key,omitempty" json:"key,omitempty"`
	Name       string      `yaml:"name,omitempty" json:"name,omitempty"`
	Conditions []Condition `yaml:"conditions" json:"conditions"`
	BuiltIn    bool        `yaml:"-" json:"built_in,omitempty"`
}

// Snapshot is the measured metric values. A metric absent from the snapshot reads as 0.
type Snapshot map[string]float64

// validOps is the set of operators a condition may use.
var validOps = map[Op]bool{OpLE: true, OpGE: true, OpEQ: true, OpLT: true, OpGT: true}
var keyPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// Normalize validates and normalizes a managed custom gate.
func (g Gate) Normalize() (Gate, error) {
	g.Key, g.Name = strings.TrimSpace(g.Key), strings.TrimSpace(g.Name)
	if !keyPattern.MatchString(g.Key) {
		return Gate{}, fmt.Errorf("quality gate key must be a lowercase hyphenated slug")
	}
	if g.Name == "" {
		return Gate{}, fmt.Errorf("quality gate name is required")
	}
	g.BuiltIn = false
	if err := g.Validate(); err != nil {
		return Gate{}, err
	}
	return g, nil
}

// Clone returns an independent copy of a gate.
func (g Gate) Clone() Gate {
	g.Conditions = append([]Condition(nil), g.Conditions...)
	return g
}

// BuiltIns returns the managed built-in gate definitions.
func BuiltIns() []Gate { return []Gate{Default()} }

// Resolve returns a built-in gate by key.
func Resolve(key string) (Gate, bool) {
	key = strings.TrimSpace(key)
	for _, gate := range BuiltIns() {
		if gate.Key == key {
			return gate, true
		}
	}
	return Gate{}, false
}

// DefaultKey is the key assigned to projects that use the built-in gate.
const DefaultKey = "synapse-way"

// Effective returns the built-in default for an empty key, or a named built-in gate.
func Effective(key string) (Gate, bool) {
	if strings.TrimSpace(key) == "" {
		return Default(), true
	}
	return Resolve(key)
}

// Validate rejects a gate that is empty or references an unknown metric/operator, so a typo'd or
// truncated config fails loud at load time rather than silently passing (a security gate must fail
// closed). It is called by the config loader.
func (g Gate) Validate() error {
	if len(g.Conditions) == 0 {
		return fmt.Errorf("quality gate has no conditions")
	}
	for _, c := range g.Conditions {
		if !ValidMetric(c.Metric) {
			return fmt.Errorf("unknown gate metric %q", c.Metric)
		}
		if !validOps[c.Op] {
			return fmt.Errorf("unknown gate operator %q for metric %q", c.Op, c.Metric)
		}
	}
	return nil
}

// ConditionResult is one evaluated condition.
type ConditionResult struct {
	Condition Condition
	Actual    float64
	Passed    bool
}

// Result is the gate outcome. Incomplete reports that analysis reached a limit, so
// Passed is false even when every evaluated condition held.
type Result struct {
	Passed     bool
	Incomplete bool
	Results    []ConditionResult
}

// Failures returns the conditions that did not hold.
func (r Result) Failures() []ConditionResult {
	var out []ConditionResult
	for _, c := range r.Results {
		if !c.Passed {
			out = append(out, c)
		}
	}
	return out
}

// Evaluate checks every condition against the snapshot. An unknown operator fails its condition closed
// (a malformed gate never silently passes).
func Evaluate(g Gate, s Snapshot) Result {
	res := Result{Passed: true}
	for _, c := range g.Conditions {
		actual := s[c.Metric]
		ok := compare(actual, c.Op, c.Threshold)
		if !ok {
			res.Passed = false
		}
		res.Results = append(res.Results, ConditionResult{Condition: c, Actual: actual, Passed: ok})
	}
	return res
}

func compare(actual float64, op Op, threshold float64) bool {
	switch op {
	case OpLE:
		return actual <= threshold
	case OpGE:
		return actual >= threshold
	case OpEQ:
		return actual == threshold
	case OpLT:
		return actual < threshold
	case OpGT:
		return actual > threshold
	default:
		return false // unknown operator: fail closed
	}
}

// String renders a condition as "metric op threshold" for messages.
func (c Condition) String() string {
	return fmt.Sprintf("%s %s %g", c.Metric, c.Op, c.Threshold)
}
