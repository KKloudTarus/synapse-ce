// Package rating turns findings + size measures into deterministic project health grades (A-E) and a
// technical-debt estimate, the counterpart on the code-quality side to risk priority on the security
// side. LLM-free and reproducible: the same findings + LOC always yield the same report, so it is safe on
// the report path (golden rule 5). Grade bands follow the widely used maintainability/reliability/security
// rating conventions.
package rating

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Grade is a letter health grade, A (best) to E (worst).
type Grade string

const (
	GradeA Grade = "A"
	GradeB Grade = "B"
	GradeC Grade = "C"
	GradeD Grade = "D"
	GradeE Grade = "E"
)

// Dimension is a rated axis.
type Dimension string

const (
	Security        Dimension = "security"
	Reliability     Dimension = "reliability"
	Maintainability Dimension = "maintainability"
)

// Report is the computed health of a codebase.
type Report struct {
	Security        Grade   `json:"security"`
	Reliability     Grade   `json:"reliability"`
	Maintainability Grade   `json:"maintainability"`
	TechDebtMinutes int     `json:"tech_debt_minutes"` // remediation effort of maintainability issues
	DebtRatioPct    float64 `json:"debt_ratio_pct"`    // tech debt / estimated development cost
	LinesOfCode     int     `json:"lines_of_code"`
}

// Tunables (deterministic defaults; documented). effortMinutes is the remediation effort assumed per
// issue by severity; devCostPerLineMinutes is the assumed cost to (re)develop one line of code – together
// they define the debt ratio that grades maintainability.
var effortMinutes = map[shared.Severity]int{
	shared.SeverityCritical: 120,
	shared.SeverityHigh:     60,
	shared.SeverityMedium:   20,
	shared.SeverityLow:      10,
	shared.SeverityInfo:     5,
}

const devCostPerLineMinutes = 30

// dimensionOf maps a finding kind to the axis it counts toward (or "" to ignore for rating).
func dimensionOf(k finding.Kind) Dimension {
	switch k {
	case finding.KindReliability:
		return Reliability
	case finding.KindQuality:
		return Maintainability
	case finding.KindSCA, "", finding.KindSAST, finding.KindSecret, finding.KindMisconfig, finding.KindExploitation, finding.KindDAST:
		// An empty Kind is legacy-SCA per the finding taxonomy (back-compat), so it counts toward security.
		return Security
	default:
		return "" // recon/manual/threat/hypothesis are not rating inputs
	}
}

// Compute grades the findings against the codebase size (loc = code lines). Security and Reliability are
// graded by the worst-severity issue on that axis; Maintainability is graded by the technical-debt ratio
// (remediation effort of maintainability issues vs. estimated development cost).
func Compute(findings []finding.Finding, loc int) Report {
	worst := map[Dimension]int{} // dimension -> worst severity rank seen
	debt := 0
	for _, f := range findings {
		dim := dimensionOf(f.Kind)
		if dim == "" {
			continue
		}
		if r := shared.SeverityRank(f.Severity); r > worst[dim] {
			worst[dim] = r
		}
		if dim == Maintainability {
			debt += effortMinutes[f.Severity]
		}
	}

	rep := Report{
		Security:        gradeBySeverity(worst[Security]),
		Reliability:     gradeBySeverity(worst[Reliability]),
		TechDebtMinutes: debt,
		LinesOfCode:     loc,
	}
	devCost := loc * devCostPerLineMinutes
	switch {
	case devCost > 0:
		rep.DebtRatioPct = 100 * float64(debt) / float64(devCost)
		rep.Maintainability = gradeByDebtRatio(rep.DebtRatioPct)
	case debt > 0:
		// Debt but no measurable code size (loc == 0): the ratio is undefined/infinite, so grade worst
		// rather than letting max debt read as the best grade.
		rep.Maintainability = GradeE
	default:
		rep.Maintainability = GradeA
	}
	return rep
}

// gradeBySeverity maps the worst-issue severity rank on an axis to a grade: none->A, low->B, medium->C,
// high->D, critical->E. info and unknown (rank <= 1) are treated as no material issue (grade A) – an
// unknown-severity finding does not, on its own, degrade a health grade.
func gradeBySeverity(rank int) Grade {
	switch {
	case rank >= shared.SeverityRank(shared.SeverityCritical):
		return GradeE
	case rank >= shared.SeverityRank(shared.SeverityHigh):
		return GradeD
	case rank >= shared.SeverityRank(shared.SeverityMedium):
		return GradeC
	case rank >= shared.SeverityRank(shared.SeverityLow):
		return GradeB
	default:
		return GradeA
	}
}

// gradeByDebtRatio maps a technical-debt ratio (%) to a maintainability grade: <=5 A, <=10 B, <=20 C,
// <=50 D, else E.
func gradeByDebtRatio(pct float64) Grade {
	switch {
	case pct <= 5:
		return GradeA
	case pct <= 10:
		return GradeB
	case pct <= 20:
		return GradeC
	case pct <= 50:
		return GradeD
	default:
		return GradeE
	}
}
