package compliance

import (
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// A Spec is a versioned compliance benchmark: a set of controls, each PASS or FAIL depending on whether any
// scan finding matches it. It re-projects the deterministic findings onto an auditor-citable pass/fail
// report (Trivy's compliance-spec idea), purely by a deterministic id/attribute join – NO LLM, so the
// result is a lookup a human can audit, and it drops straight into the LLM-free report path.
type Spec struct {
	ID       string
	Title    string
	Version  string
	Controls []SpecControl
}

// SpecControl is one benchmark control. It FAILS when any finding matches ANY of its join keys: a mapped
// CWE, a finding Kind, or a severity at/above MinSeverity. A control with no findings against it PASSES.
type SpecControl struct {
	ID          string   // control id as cited, e.g. "SAB-INJ-1"
	Title       string   // human control title
	CWEs        []string // FAIL if a finding's CWE is one of these (normalized, "CWE-" tolerated)
	Kinds       []string // FAIL if a finding's Kind is one of these (e.g. "secret", "misconfig")
	MinSeverity string   // FAIL if any finding is at/above this severity label; "" disables the severity join
}

// ControlResult is a control's evaluated status plus the finding titles that failed it (evidence).
type ControlResult struct {
	Control  SpecControl
	Passed   bool
	Evidence []string // titles of the findings that failed the control (empty when passed)
}

// Report is the evaluated benchmark: per-control results plus pass/fail tallies. MinSeverity + IgnoreUnfixed
// record the SCOPE of the finding set it was computed over, so a PASS is never misread as "no weakness of
// this class at ANY severity" – findings below the floor (and, when IgnoreUnfixed, unfixed vulns) were not
// in the evaluated set.
type Report struct {
	SpecID        string
	Title         string
	Version       string
	MinSeverity   string // the severity floor the evaluated findings were promoted at ("info" = none dropped)
	IgnoreUnfixed bool   // whether unfixed vulns were excluded from the evaluated set
	Results       []ControlResult
	Passed        int
	Failed        int
}

// Evaluate joins the findings against the spec and returns the per-control report. Deterministic and
// order-independent: controls keep their spec order; evidence is sorted. A control matches a finding when
// the finding's CWE is in Controls.CWEs, its Kind is in Controls.Kinds, or its severity is at/above
// MinSeverity – the same match a human would make by reading the control's join keys.
func Evaluate(spec Spec, findings []finding.Finding) Report {
	rep := Report{SpecID: spec.ID, Title: spec.Title, Version: spec.Version}
	for _, c := range spec.Controls {
		var evidence []string
		for _, f := range findings {
			if controlMatchesFinding(c, f) {
				evidence = append(evidence, f.Title)
			}
		}
		sort.Strings(evidence)
		res := ControlResult{Control: c, Passed: len(evidence) == 0, Evidence: evidence}
		rep.Results = append(rep.Results, res)
		if res.Passed {
			rep.Passed++
		} else {
			rep.Failed++
		}
	}
	return rep
}

func controlMatchesFinding(c SpecControl, f finding.Finding) bool {
	if fc := normalizeCWE(f.CWE); fc != "" {
		for _, cwe := range c.CWEs {
			if normalizeCWE(cwe) == fc {
				return true
			}
		}
	}
	for _, k := range c.Kinds {
		if strings.EqualFold(string(f.Kind), k) {
			return true
		}
	}
	// A control MinSeverity that isn't a known label ranks 0 and would match EVERY finding (over-match); guard
	// on a positive threshold so an unrecognized value fail-closes (disables the severity join), matching the
	// CWE join's fail-to-nothing philosophy for when non-hardcoded specs arrive.
	if minRank := shared.SeverityRank(shared.Severity(c.MinSeverity)); minRank > 0 && shared.SeverityRank(f.Severity) >= minRank {
		return true
	}
	return false
}
