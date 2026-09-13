package reachbench

import (
	"fmt"
	"sort"
)

// RecallFloor is the checked-in per-language recall ratchet: the minimum recall each language's engine must
// score on the corpus. It is a monotonic floor: raise an entry when accuracy improves so a later regression
// is caught, and NEVER lower one to make a red build pass (a lowered floor hides a recall regression, which
// is a hidden reachable vulnerability). CheckRecallFloor enforces recall >= floor; the "only rises"
// discipline is enforced by review of any change to the checked-in map.
type RecallFloor map[string]float64

// CheckRecallFloor returns a sorted list of human-readable violations: a language whose measured recall is
// below its floor, or a floored language absent from the report (a corpus that lost a language's cases, so
// the floor is no longer exercised). An empty result means the ratchet passes. A language present in the
// report but ABSENT from the floor is reported too, so a new language cannot land un-ratcheted.
func CheckRecallFloor(report Report, floor RecallFloor) []string {
	var violations []string
	for lang, want := range floor {
		m, ok := report.ByLanguage[lang]
		if !ok {
			violations = append(violations, fmt.Sprintf("language %q has a recall floor %.4f but no cases in the corpus (floor no longer exercised)", lang, want))
			continue
		}
		// A floor is only meaningful if there are reachable (positive) cases to score: recall is defined
		// 1.0 when TP+FN==0 (see finalize), so a corpus that lost all of a language's reachable cases would
		// pass ANY floor at a phantom 1.0. Treat an unexercised floor as a violation, so a recall regression
		// cannot hide behind a corpus that dropped its positive cases.
		if m.TP+m.FN == 0 {
			violations = append(violations, fmt.Sprintf("language %q has a recall floor %.4f but no reachable cases in the corpus (recall not exercised)", lang, want))
			continue
		}
		if m.Recall+1e-9 < want {
			violations = append(violations, fmt.Sprintf("language %q recall %.4f is below the floor %.4f (a recall regression is a missed reachable vulnerability)", lang, m.Recall, want))
		}
	}
	for lang := range report.ByLanguage {
		if _, ok := floor[lang]; !ok {
			violations = append(violations, fmt.Sprintf("language %q is scored but has no recall floor: add one so it is ratcheted", lang))
		}
	}
	sort.Strings(violations)
	return violations
}

// CheckParity returns a sorted list of languages where Synapse's recall is below a baseline competitor's
// recall on the SAME corpus (a head-to-head parity-or-better check, EPIC #1042 5.1). tolerance allows a
// small margin (e.g. 0.0 for strict parity). competitorName only labels the message. A language the
// competitor did not score is skipped (no comparison is possible), never counted as a Synapse loss.
func CheckParity(synapse, competitor Report, competitorName string, tolerance float64) []string {
	var losses []string
	for lang, comp := range competitor.ByLanguage {
		syn, ok := synapse.ByLanguage[lang]
		if !ok {
			// The competitor scored a language Synapse did not: Synapse is not even running there, which is
			// a head-to-head loss, not a pass. Flag it rather than skipping silently.
			losses = append(losses, fmt.Sprintf("language %q: %s scored it (recall %.4f) but Synapse has no result", lang, competitorName, comp.Recall))
			continue
		}
		if syn.Recall+tolerance+1e-9 < comp.Recall {
			losses = append(losses, fmt.Sprintf("language %q: Synapse recall %.4f is below %s recall %.4f", lang, syn.Recall, competitorName, comp.Recall))
		}
	}
	sort.Strings(losses)
	return losses
}
