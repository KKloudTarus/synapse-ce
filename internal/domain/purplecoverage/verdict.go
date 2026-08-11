// Package purplecoverage is the pure domain that closes the purple loop (issue #426): it joins the
// detection each emulated technique EXPECTED (#421) with the detections that ACTUALLY fired (#422/#423)
// and resolves a coverage verdict. Coverage is measured, not claimed — the intersection is coverage, the
// difference is the gap, and the honest distinctions (unknown vs gap, bonus vs hidden) are enforced here.
//
// No I/O, no clock. The join and persistence live in internal/usecase/purplecoverage.
package purplecoverage

import (
	"fmt"
	"sort"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Verdict is the coverage outcome for one technique. The set is closed and resolved TOP-DOWN in this
// order (issue #426): out_of_reach, unknown, covered, gap — so an emulation that never executed can
// never be counted as a gap.
type Verdict string

const (
	VerdictOutOfReach Verdict = "out_of_reach" // the platform cannot emulate this technique at all
	VerdictUnknown    Verdict = "unknown"      // emulatable, but this run could not execute it (e.g. out of scope)
	VerdictCovered    Verdict = "covered"      // executed AND the expected detection fired
	VerdictGap        Verdict = "gap"          // executed, but the expected detection did NOT fire
)

// Valid reports whether v is a known verdict.
func (v Verdict) Valid() bool {
	switch v {
	case VerdictOutOfReach, VerdictUnknown, VerdictCovered, VerdictGap:
		return true
	default:
		return false
	}
}

// Uncovered reports whether a verdict counts against coverage in a way a defender must act on: only a gap
// is an actionable coverage hole. unknown and out_of_reach are honest non-measurements, not holes.
func (v Verdict) Uncovered() bool { return v == VerdictGap }

// Input is one technique's expected-vs-actual for a run. Emulatable=false means the platform cannot
// emulate it (out_of_reach); Executed=false means it was emulatable but did not run this time (unknown).
// Actual is the set of detection ids observed in the same window on the same asset.
type Input struct {
	TechniqueID string
	TaxonomyRef string
	Expected    string // the detection id the technique should produce
	Emulatable  bool
	Executed    bool
	Actual      []string
}

// Resolve applies the top-down verdict order. Crucially, a non-executed technique is unknown, NEVER a
// gap: you cannot measure detection of something that did not run, and collapsing the two would over- or
// under-state coverage — both dishonest.
func Resolve(in Input) Verdict {
	switch {
	case !in.Emulatable:
		return VerdictOutOfReach
	case !in.Executed:
		return VerdictUnknown
	case containsDetection(in.Actual, in.Expected):
		return VerdictCovered
	default:
		return VerdictGap
	}
}

// Coverage is one technique's resolved coverage for a run — the stored record, so coverage over time is a
// trend and a regression is visible. It carries the public taxonomy reference so coverage is reported in
// terms a customer and an auditor already understand.
type Coverage struct {
	TenantID     shared.ID
	EngagementID shared.ID
	RunID        shared.ID
	AssetID      shared.ID
	TechniqueID  string
	TaxonomyRef  string
	Expected     string
	Actual       []string
	Verdict      Verdict
	ComputedAt   time.Time
}

// Validate enforces the invariants a stored coverage record must hold: a taxonomy reference (coverage is
// expressed against the public taxonomy), a technique, and a valid verdict.
func (c Coverage) Validate() error {
	if c.TenantID == "" || c.RunID == "" || c.EngagementID == "" {
		return fmt.Errorf("%w: coverage is missing tenant/run/engagement scope", shared.ErrValidation)
	}
	if c.TechniqueID == "" {
		return fmt.Errorf("%w: coverage has no technique id", shared.ErrValidation)
	}
	if c.TaxonomyRef == "" {
		return fmt.Errorf("%w: coverage for %s has no taxonomy reference — coverage must be expressed against the public taxonomy", shared.ErrValidation, c.TechniqueID)
	}
	if !c.Verdict.Valid() {
		return fmt.Errorf("%w: coverage for %s has an invalid verdict %q", shared.ErrValidation, c.TechniqueID, c.Verdict)
	}
	return nil
}

// BonusDetections returns the actual detection ids that matched NO technique's expected detection — a
// bonus detection or noise. They are reported SEPARATELY (never hidden, never counted as coverage), so a
// hunt sees them for what they are.
func BonusDetections(inputs []Input, allActual []string) []string {
	expected := make(map[string]struct{}, len(inputs))
	for _, in := range inputs {
		if in.Expected != "" {
			expected[in.Expected] = struct{}{}
		}
	}
	seen := map[string]struct{}{}
	var bonus []string
	for _, a := range allActual {
		if _, isExpected := expected[a]; isExpected {
			continue
		}
		if _, dup := seen[a]; dup {
			continue
		}
		seen[a] = struct{}{}
		bonus = append(bonus, a)
	}
	sort.Strings(bonus)
	return bonus
}

// Regression is a technique that went from covered to uncovered between two runs — a detection
// regression, surfaced in the same spirit as the code regression suite.
type Regression struct {
	TechniqueID string
	TaxonomyRef string
	From        Verdict
	To          Verdict
}

// Regressions compares an earlier run's coverage with a later run's and returns the covered->uncovered
// transitions. A covered technique that becomes a gap (or unknown/out_of_reach) is a regression; the
// reverse (a gap that becomes covered) is progress, not a regression.
func Regressions(prev, curr []Coverage) []Regression {
	was := make(map[string]Verdict, len(prev))
	tax := make(map[string]string, len(prev))
	for _, c := range prev {
		was[c.TechniqueID] = c.Verdict
		tax[c.TechniqueID] = c.TaxonomyRef
	}
	var out []Regression
	for _, c := range curr {
		if was[c.TechniqueID] == VerdictCovered && c.Verdict != VerdictCovered {
			ref := c.TaxonomyRef
			if ref == "" {
				ref = tax[c.TechniqueID]
			}
			out = append(out, Regression{TechniqueID: c.TechniqueID, TaxonomyRef: ref, From: VerdictCovered, To: c.Verdict})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TechniqueID < out[j].TechniqueID })
	return out
}

// WorkItem is the actionable item an uncovered technique produces: write or fix the missing detection.
// It references the technique and the missing detection so a human can pick it up (the platform never
// auto-writes the rule — that is deliberately out of scope).
type WorkItem struct {
	TechniqueID      string
	TaxonomyRef      string
	MissingDetection string
}

// WorkItems returns one work item per GAP (executed-but-undetected) technique. unknown/out_of_reach do
// NOT produce work items: there is no detection to write for something that did not run or cannot run.
func WorkItems(cov []Coverage) []WorkItem {
	var out []WorkItem
	for _, c := range cov {
		if c.Verdict == VerdictGap {
			out = append(out, WorkItem{TechniqueID: c.TechniqueID, TaxonomyRef: c.TaxonomyRef, MissingDetection: c.Expected})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TechniqueID < out[j].TechniqueID })
	return out
}

func containsDetection(actual []string, expected string) bool {
	if expected == "" {
		return false
	}
	for _, a := range actual {
		if a == expected {
			return true
		}
	}
	return false
}
