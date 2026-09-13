// Package reachbench scores a reachability engine against a labeled reachable/unreachable corpus and
// enforces a recall ratchet. It is the accuracy benchmark for reachability (EPIC #1042, 5.1), distinct from
// internal/usecase/accuracyeval, which measures DETECTION accuracy (does a finding fire), not REACHABILITY
// (is the vulnerable code reached).
//
// The gating metric is RECALL over the "reachable" positive class: of the cases whose ground truth is
// reachable, how many did the engine call reachable. A recall regression means the engine started MISSING
// reachable vulnerabilities, which is the #1-bar failure (a hidden real vulnerability), so the ratchet
// floors recall and lets it only rise. Precision and coverage are reported for context but never gate,
// because raising precision by suppressing a reachable verdict must never be rewarded.
package reachbench

import (
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
)

// Case is one labeled corpus entry: a reachability subject (an advisory-affected symbol in a fixture
// program) and its GROUND-TRUTH reachability. Language partitions the corpus so a per-language ratchet lands
// as each engine ships. Want is one of judgment.Reachable / judgment.NotReachable (a labeled corpus never
// carries "unknown" as ground truth; unknown is only an engine OUTPUT).
type Case struct {
	ID       string                     `json:"id"`
	Language string                     `json:"language"`
	Symbol   string                     `json:"symbol"`
	Want     judgment.ReachabilityState `json:"want"`
}

// Metrics is the score for one language (or the whole corpus). Recall is the gating metric; a case the
// engine left "unknown" or answered wrongly counts against recall when its ground truth is reachable.
type Metrics struct {
	Total     int     `json:"total"`
	Answered  int     `json:"answered"` // cases the engine did not leave unknown
	TP        int     `json:"tp"`       // want reachable, observed reachable
	FN        int     `json:"fn"`       // want reachable, observed not-reachable OR unknown (a MISS)
	FP        int     `json:"fp"`       // want not-reachable, observed reachable (a false alarm)
	TN        int     `json:"tn"`       // want not-reachable, observed not-reachable
	Recall    float64 `json:"recall"`   // TP / (TP+FN); 1.0 when there are no reachable cases
	Precision float64 `json:"precision"`
	Coverage  float64 `json:"coverage"` // Answered / Total
}

// Report is the full scorecard: overall plus per-language metrics.
type Report struct {
	Overall    Metrics            `json:"overall"`
	ByLanguage map[string]Metrics `json:"byLanguage"`
}

// Score scores observed engine verdicts against the labeled corpus. observed maps a case id to the engine's
// four-state verdict; a case with NO entry (or an entry that is neither reachable nor not_reachable) is
// treated as "unknown" (the engine gave no answer), which is a MISS when the ground truth is reachable, so a
// missing verdict can never inflate recall. A case whose Want is not a valid reachable/not-reachable label
// is skipped (a malformed corpus row must not silently count).
func Score(cases []Case, observed map[string]judgment.ReachabilityState) Report {
	byLang := map[string]*Metrics{}
	overall := &Metrics{}
	get := func(lang string) *Metrics {
		if byLang[lang] == nil {
			byLang[lang] = &Metrics{}
		}
		return byLang[lang]
	}
	for _, c := range cases {
		if c.Want != judgment.Reachable && c.Want != judgment.NotReachable {
			continue
		}
		m := get(c.Language)
		obs := observed[c.ID]
		answered := obs == judgment.Reachable || obs == judgment.NotReachable
		for _, t := range []*Metrics{m, overall} {
			t.Total++
			if answered {
				t.Answered++
			}
			switch {
			case c.Want == judgment.Reachable && obs == judgment.Reachable:
				t.TP++
			case c.Want == judgment.Reachable: // observed not-reachable or unknown: a missed reachable
				t.FN++
			case obs == judgment.Reachable: // want not-reachable, observed reachable: a false alarm
				t.FP++
			default: // want not-reachable, observed not-reachable or unknown
				if obs == judgment.NotReachable {
					t.TN++
				}
			}
		}
	}
	finalize(overall)
	out := Report{Overall: *overall, ByLanguage: map[string]Metrics{}}
	for lang, m := range byLang {
		finalize(m)
		out.ByLanguage[lang] = *m
	}
	return out
}

// finalize computes the rate metrics from the counts. Recall and precision are 1.0 when their denominator is
// zero (no positive cases / no positive predictions), so an empty slice does not read as a 0.0 regression.
func finalize(m *Metrics) {
	if m.TP+m.FN > 0 {
		m.Recall = float64(m.TP) / float64(m.TP+m.FN)
	} else {
		m.Recall = 1.0
	}
	if m.TP+m.FP > 0 {
		m.Precision = float64(m.TP) / float64(m.TP+m.FP)
	} else {
		m.Precision = 1.0
	}
	if m.Total > 0 {
		m.Coverage = float64(m.Answered) / float64(m.Total)
	} else {
		m.Coverage = 1.0
	}
}

// Languages returns the corpus languages in sorted order (deterministic reporting/ratcheting).
func Languages(cases []Case) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range cases {
		if !seen[c.Language] {
			seen[c.Language] = true
			out = append(out, c.Language)
		}
	}
	sort.Strings(out)
	return out
}
