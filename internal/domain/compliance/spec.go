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
	// Frameworks is the per-framework CIS/OWASP/PCI/ISO coverage rollup over the same findings (D6.6): for each
	// framework a finding maps to, the controls Synapse assesses and whether each FAILED or is NOT_ASSESSED.
	// It never asserts PASS (see ComplianceStatus). Empty when no finding maps to any mapped control.
	Frameworks []FrameworkCoverage `json:"frameworks,omitempty"`
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

// ComplianceStatus is a control's assessed state in a rollup. Synapse asserts FAILED (a finding mapped to the
// control) or NOT_ASSESSED (the control is mapped but no finding matched it). It deliberately does NOT assert
// PASS: a clean finding set is not proof a control's requirement is met, only that Synapse's checks for it did
// not fire. Asserting PASS would need per-control coverage proof (that the relevant check actually ran over
// the relevant resource), which the scan does not carry. NOT_APPLICABLE is reserved for a future scan-scope
// signal (e.g. a Kubernetes framework against a scan with no Kubernetes manifests).
type ComplianceStatus string

const (
	ControlFailed      ComplianceStatus = "failed"
	ControlNotAssessed ComplianceStatus = "not_assessed"
)

// ControlStatus is one control's assessed state within a framework rollup.
type ControlStatus struct {
	Control  Control          `json:"control"`
	Status   ComplianceStatus `json:"status"`
	Findings int              `json:"findings"` // findings mapped to this control (>0 iff failed)
}

// FrameworkCoverage is a per-framework compliance rollup over a finding set. For every control Synapse can
// assess in the framework (its curated mapping), it reports FAILED or NOT_ASSESSED. Assessable is the
// denominator — the number of controls Synapse maps in this framework, NOT the framework's full control
// catalogue — so "Failed of Assessable" is never misread as full-framework compliance. Findings counts the
// findings that mapped to the framework (each finding once). A NOT_ASSESSED control is explicitly NOT a pass.
type FrameworkCoverage struct {
	Framework  string          `json:"framework"`
	Assessable int             `json:"assessable_controls"`
	Failed     int             `json:"failed_controls"`
	Findings   int             `json:"findings"`
	Controls   []ControlStatus `json:"controls"`
}

// controlsByFramework returns every control Synapse maps (from the CWE and rule tables), grouped by framework
// and de-duplicated by control ID. It is the denominator source for the rollup: the controls Synapse is able
// to assess, never the framework's complete catalogue.
func controlsByFramework() map[string][]Control {
	byFW := map[string]map[string]Control{}
	add := func(cs []Control) {
		for _, c := range cs {
			if byFW[c.Framework] == nil {
				byFW[c.Framework] = map[string]Control{}
			}
			// Deterministic dedup: a control ID should carry one canonical title across the CWE and rule
			// tables, but if two entries ever disagree, pick the lexicographically smaller title so the
			// emitted metadata does not depend on Go's map iteration order.
			if existing, ok := byFW[c.Framework][c.ID]; !ok || c.Title < existing.Title {
				byFW[c.Framework][c.ID] = c
			}
		}
	}
	for _, cs := range cweControls {
		add(cs)
	}
	for _, cs := range ruleControls {
		add(cs)
	}
	out := make(map[string][]Control, len(byFW))
	for fw, m := range byFW {
		cs := make([]Control, 0, len(m))
		for _, c := range m {
			cs = append(cs, c)
		}
		sortControls(cs)
		out[fw] = cs
	}
	return out
}

// Rollup aggregates findings into a per-framework compliance rollup using the same curated finding->controls
// mapping (CWE + rule key) as ControlsForFinding, so every FAILED is a deterministic lookup, never an
// inference. A framework is reported only when at least one finding maps to it; within that framework EVERY
// control Synapse maps is listed with its status — FAILED (a finding mapped) or NOT_ASSESSED (no finding, and
// NOT a pass assertion) — alongside the assessable-controls denominator, so a partial result reads honestly
// and a NOT_ASSESSED control is never mistaken for a clean pass. Deterministic order.
func Rollup(findings []finding.Finding) []FrameworkCoverage {
	assessable := controlsByFramework()
	failed := map[string]map[string]int{} // framework -> control ID -> findings mapped
	frameworkFindings := map[string]int{}
	for _, f := range findings {
		controls := ControlsForFinding(f.CWE, f.RuleKey)
		if len(controls) == 0 {
			continue
		}
		countedFW := map[string]bool{}
		countedControl := map[string]bool{} // guard: count each (framework,control) at most once PER finding
		for _, c := range controls {
			if failed[c.Framework] == nil {
				failed[c.Framework] = map[string]int{}
			}
			if key := c.Framework + "\x00" + c.ID; !countedControl[key] {
				countedControl[key] = true
				failed[c.Framework][c.ID]++
			}
			if !countedFW[c.Framework] {
				countedFW[c.Framework] = true
				frameworkFindings[c.Framework]++
			}
		}
	}
	out := make([]FrameworkCoverage, 0, len(failed))
	for fw := range failed {
		controls := assessable[fw]
		fc := FrameworkCoverage{Framework: fw, Assessable: len(controls), Findings: frameworkFindings[fw]}
		for _, c := range controls {
			n := failed[fw][c.ID]
			st := ControlNotAssessed
			if n > 0 {
				st = ControlFailed
				fc.Failed++
			}
			fc.Controls = append(fc.Controls, ControlStatus{Control: c, Status: st, Findings: n})
		}
		out = append(out, fc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Framework < out[j].Framework })
	return out
}
