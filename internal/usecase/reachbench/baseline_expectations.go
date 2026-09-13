package reachbench

import (
	"fmt"
	"sort"
)

// BaselineExpectation is the exact integer scorecard a named OSS baseline must produce on one language's
// corpus subset. It is the checked-in contract that makes the head-to-head non-gameable: a tool that
// silently degrades (an empty or weakened results array while still exiting 0/1), or a corpus edit that
// shrinks a language's denominator or relabels a hard case away, changes these integers and fails the gate
// instead of recording a hollow "win". Derived rates (recall, precision) are intentionally omitted; the
// integers they are computed from are the stable contract.
type BaselineExpectation struct {
	Cases             int
	PositiveExpected  int
	PositiveFound     int
	PositiveProduced  int
	FalsePositiveRise int
}

// baselineExpectations pins, per OSS tool and language, the scorecard the reproducible head-to-head must
// reproduce. Updating any of these is a reviewed change: it means the corpus, a fixture, or a pinned tool
// version genuinely moved, and the reviewer confirms the new numbers are still honest.
//
//   - OSV-Scanner / Go: only the jsonparser advisory pair carries an OSV selector, so of the 4 reachable Go
//     cases OSV proves 1 (called), the other 3 have no OSV analysis. recall 1/4, precision 1/1.
//   - Semgrep CE / Go: the jsonparser.Delete rule matches only the "called" fixture. Same shape as OSV.
//   - Semgrep CE / Python: the os.system sink rule matches all 9 fixtures (every fixture calls the sink), so
//     Semgrep labels all 9 reachable. Of those, 5 are truly reachable (recall 5/5) and 4 are the unreached
//     fixtures whose sink Semgrep cannot prove unreachable (4 false-positive reachable, precision 5/9). This
//     over-approximation is the owned engine's precision advantage, recorded exactly here.
var baselineExpectations = map[string]map[string]BaselineExpectation{
	"osv-scanner": {
		"go": {Cases: 7, PositiveExpected: 4, PositiveFound: 1, PositiveProduced: 1, FalsePositiveRise: 0},
	},
	"semgrep-ce": {
		"go":     {Cases: 7, PositiveExpected: 4, PositiveFound: 1, PositiveProduced: 1, FalsePositiveRise: 0},
		"python": {Cases: 9, PositiveExpected: 5, PositiveFound: 5, PositiveProduced: 9, FalsePositiveRise: 4},
	},
}

// ExpectedBaseline returns the pinned scorecard for a tool+language, ok=false when none is recorded.
func ExpectedBaseline(tool, language string) (BaselineExpectation, bool) {
	byLanguage, ok := baselineExpectations[tool]
	if !ok {
		return BaselineExpectation{}, false
	}
	exp, ok := byLanguage[language]
	return exp, ok
}

// CheckBaselineExpectation returns every mismatch between a loaded baseline report's language score and the
// pinned expectation for that tool+language. An empty result means the baseline reproduced the recorded
// scorecard exactly. It FAILS CLOSED: an unpinned tool+language, or a report missing that language, is a
// breach, so a gated baseline can never pass without a recorded expectation to hold it to.
func CheckBaselineExpectation(report Report, tool, language string) []string {
	exp, ok := ExpectedBaseline(tool, language)
	if !ok {
		return []string{fmt.Sprintf("no pinned baseline expectation for %s/%s", tool, language)}
	}
	var score *LanguageScore
	for i := range report.Languages {
		if report.Languages[i].Language == language {
			score = &report.Languages[i]
			break
		}
	}
	if score == nil {
		return []string{fmt.Sprintf("%s baseline report has no %s language score", tool, language)}
	}
	var breaches []string
	check := func(name string, got, want int) {
		if got != want {
			breaches = append(breaches, fmt.Sprintf("%s/%s %s = %d, expected %d", tool, language, name, got, want))
		}
	}
	check("cases", score.Cases, exp.Cases)
	check("positive_expected", score.PositiveExpected, exp.PositiveExpected)
	check("positive_found", score.PositiveFound, exp.PositiveFound)
	check("positive_produced", score.PositiveProduced, exp.PositiveProduced)
	check("false_positive_reachable", score.FalsePositiveRise, exp.FalsePositiveRise)
	sort.Strings(breaches)
	return breaches
}
