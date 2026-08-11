package purplecoverage

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TestResolveVerdictPerCase covers the four verdicts and the ambiguous pairs the resolution order must
// disambiguate — most importantly that a non-executed technique is unknown, NEVER a gap.
func TestResolveVerdictPerCase(t *testing.T) {
	tests := []struct {
		name string
		in   Input
		want Verdict
	}{
		{"out of reach (not emulatable) wins over everything",
			Input{Emulatable: false, Executed: false, Expected: "det.x"}, VerdictOutOfReach},
		{"out of reach even if actual fired",
			Input{Emulatable: false, Executed: true, Expected: "det.x", Actual: []string{"det.x"}}, VerdictOutOfReach},
		{"emulatable but did not execute -> unknown, never gap",
			Input{Emulatable: true, Executed: false, Expected: "det.x"}, VerdictUnknown},
		{"executed and expected fired -> covered",
			Input{Emulatable: true, Executed: true, Expected: "det.x", Actual: []string{"det.other", "det.x"}}, VerdictCovered},
		{"executed but expected did NOT fire -> gap",
			Input{Emulatable: true, Executed: true, Expected: "det.x", Actual: []string{"det.other"}}, VerdictGap},
		{"executed, nothing fired -> gap",
			Input{Emulatable: true, Executed: true, Expected: "det.x"}, VerdictGap},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Resolve(tt.in); got != tt.want {
				t.Fatalf("Resolve = %s, want %s", got, tt.want)
			}
			if got := Resolve(tt.in); got == VerdictGap && !tt.in.Executed {
				t.Fatal("a non-executed technique must never resolve to gap")
			}
		})
	}
}

func TestBonusDetectionsReportedNotHidden(t *testing.T) {
	inputs := []Input{
		{TechniqueID: "emu.a", Expected: "det.a", Emulatable: true, Executed: true, Actual: []string{"det.a"}},
		{TechniqueID: "emu.b", Expected: "det.b", Emulatable: true, Executed: true, Actual: []string{"det.b"}},
	}
	// det.surprise matched no expected → a bonus/noise detection, reported separately.
	all := []string{"det.a", "det.b", "det.surprise", "det.surprise"}
	bonus := BonusDetections(inputs, all)
	if len(bonus) != 1 || bonus[0] != "det.surprise" {
		t.Fatalf("an unexpected actual detection must be reported as bonus (deduped), got %v", bonus)
	}
}

func TestRegressionsCoveredToUncovered(t *testing.T) {
	prev := []Coverage{
		{TechniqueID: "emu.a", TaxonomyRef: "T1", Verdict: VerdictCovered},
		{TechniqueID: "emu.b", TaxonomyRef: "T2", Verdict: VerdictGap},
	}
	curr := []Coverage{
		{TechniqueID: "emu.a", TaxonomyRef: "T1", Verdict: VerdictGap},     // regression: covered -> gap
		{TechniqueID: "emu.b", TaxonomyRef: "T2", Verdict: VerdictCovered}, // progress: gap -> covered (NOT a regression)
	}
	regs := Regressions(prev, curr)
	if len(regs) != 1 || regs[0].TechniqueID != "emu.a" || regs[0].From != VerdictCovered || regs[0].To != VerdictGap {
		t.Fatalf("only the covered->uncovered transition is a regression, got %+v", regs)
	}
}

func TestWorkItemsOnlyForGaps(t *testing.T) {
	cov := []Coverage{
		{TechniqueID: "emu.gap", TaxonomyRef: "T1", Expected: "det.gap", Verdict: VerdictGap},
		{TechniqueID: "emu.cov", TaxonomyRef: "T2", Expected: "det.cov", Verdict: VerdictCovered},
		{TechniqueID: "emu.unk", TaxonomyRef: "T3", Expected: "det.unk", Verdict: VerdictUnknown},
		{TechniqueID: "emu.oor", TaxonomyRef: "T4", Expected: "det.oor", Verdict: VerdictOutOfReach},
	}
	items := WorkItems(cov)
	if len(items) != 1 || items[0].TechniqueID != "emu.gap" || items[0].MissingDetection != "det.gap" {
		t.Fatalf("a work item must be produced ONLY for a gap, referencing the missing detection, got %+v", items)
	}
}

func TestCoverageValidateRequiresTaxonomy(t *testing.T) {
	good := Coverage{TenantID: "t1", RunID: "r1", EngagementID: "eng-1", TechniqueID: "emu.a", TaxonomyRef: "T1", Verdict: VerdictCovered, ComputedAt: time.Unix(1, 0)}
	if err := good.Validate(); err != nil {
		t.Fatalf("a well-formed coverage must validate: %v", err)
	}
	bad := good
	bad.TaxonomyRef = ""
	if err := bad.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("coverage without a taxonomy reference must be rejected, got %v", err)
	}
}
