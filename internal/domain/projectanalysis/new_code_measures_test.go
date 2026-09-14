package projectanalysis

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/hotspot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rating"
)

// changes describes a diff whose new side touches a.go lines 10-12 and 20, and b.go line 5.
func changes() []FileChange {
	return []FileChange{
		{Status: FileStatusModified, NewPath: "src/a.go", Added: []LineRange{{Start: 10, End: 12}, {Start: 20, End: 20}}},
		{Status: FileStatusAdded, NewPath: "src/b.go", Added: []LineRange{{Start: 5, End: 5}}},
	}
}

func measuresFor(coverage *measure.CoverageReport, dup measure.DuplicationReport, fc []FileChange) qualitygate.Snapshot {
	return buildMeasures(Counts{}, Counts{}, rating.Report{}, dup, coverage, hotspot.Summary{}, hotspot.Summary{}, ChangedLineSet(fc))
}

func TestChangedLineSetExpandsAddedRangesOnly(t *testing.T) {
	set := ChangedLineSet([]FileChange{
		{Status: FileStatusModified, NewPath: "src/a.go", Added: []LineRange{{Start: 3, End: 5}}, Removed: []LineRange{{Start: 1, End: 9}}},
		{Status: FileStatusDeleted, OldPath: "gone.go", Added: []LineRange{{Start: 1, End: 1}}},
		{Status: FileStatusModified, NewPath: "bin.png", Binary: true, Added: []LineRange{{Start: 1, End: 1}}},
		{Status: FileStatusModified, NewPath: "../escape.go", Added: []LineRange{{Start: 1, End: 1}}},
		{Status: FileStatusModified, NewPath: "untouched.go"},
	})
	if len(set) != 1 || len(set["src/a.go"]) != 3 || !set["src/a.go"][3] || !set["src/a.go"][5] || set["src/a.go"][6] {
		t.Fatalf("changed set = %+v, want only src/a.go lines 3..5", set)
	}
}

func TestNewCoverageIsMeasuredOverChangedLinesOnly(t *testing.T) {
	// a.go: changed lines 10,11 covered, 12 uncovered, 20 not in the report (a comment, say); an
	// unchanged line 30 is uncovered and must not count. b.go line 5 covered.
	coverage := &measure.CoverageReport{Lines: measure.LineCoverage{
		"src/a.go": {10: true, 11: true, 12: false, 30: false},
		"src/b.go": {5: true},
	}}
	m := measuresFor(coverage, measure.DuplicationReport{}, changes())
	got, ok := m[qualitygate.MetricNewCoverage]
	if !ok {
		t.Fatalf("new_coverage must be measured; snapshot=%v", m)
	}
	if want := 100.0 * 3 / 4; got != want {
		t.Fatalf("new_coverage = %g, want %g (3 of the 4 changed lines the report knows about)", got, want)
	}
	if _, present := m[qualitygate.MetricCoveragePct]; !present {
		t.Fatal("overall coverage must still be reported")
	}
}

func TestNewCoverageIsAbsentWhenItCannotBeMeasured(t *testing.T) {
	covered := &measure.CoverageReport{Lines: measure.LineCoverage{"src/a.go": {10: true}}}
	for name, tc := range map[string]struct {
		coverage *measure.CoverageReport
		fc       []FileChange
	}{
		"no coverage report":              {nil, changes()},
		"no changed lines":                {covered, nil},
		"changed lines the report lacks":  {&measure.CoverageReport{Lines: measure.LineCoverage{"other.go": {1: true}}}, changes()},
		"report without per-line data":    {&measure.CoverageReport{CoveredLines: 5, TotalLines: 10}, changes()},
		"only deleted and binary changes": {covered, []FileChange{{Status: FileStatusDeleted, OldPath: "src/a.go"}, {Status: FileStatusModified, NewPath: "x.png", Binary: true, Added: []LineRange{{Start: 1, End: 1}}}}},
	} {
		t.Run(name, func(t *testing.T) {
			m := measuresFor(tc.coverage, measure.DuplicationReport{}, tc.fc)
			if v, present := m[qualitygate.MetricNewCoverage]; present {
				t.Fatalf("new_coverage must be absent, not %g: a value nobody measured would let a gate pass on it", v)
			}
		})
	}
}

func TestNewDuplicationIsMeasuredOverChangedLines(t *testing.T) {
	// One block occurs in a.go 11-20 (overlapping changed lines 11, 12, 20 — not 10) and b.go 1-3 (missing
	// changed line 5). Another occurrence in c.go, an unchanged file, must not count.
	dup := measure.DuplicationReport{Blocks: []measure.DuplicationBlock{{
		Tokens: 40,
		Occurrences: []measure.CodeRange{
			{File: "src/a.go", StartLine: 11, EndLine: 20},
			{File: "src/b.go", StartLine: 1, EndLine: 3},
			{File: "src/c.go", StartLine: 1, EndLine: 100},
		},
	}}, DuplicatedLines: 113, TotalLines: 400}
	m := measuresFor(nil, dup, changes())
	got, ok := m[qualitygate.MetricNewDuplication]
	if !ok {
		t.Fatalf("new_duplication must be measured; snapshot=%v", m)
	}
	if want := 100.0 * 3 / 5; got != want {
		t.Fatalf("new_duplication = %g, want %g (3 of 5 changed lines sit in a duplicated occurrence)", got, want)
	}
	// Two occurrences covering the same changed line count it once.
	dup.Blocks = append(dup.Blocks, measure.DuplicationBlock{Occurrences: []measure.CodeRange{{File: "src/a.go", StartLine: 12, EndLine: 12}}})
	if again := measuresFor(nil, dup, changes())[qualitygate.MetricNewDuplication]; again != got {
		t.Fatalf("overlapping occurrences double-counted a changed line: %g -> %g", got, again)
	}
}

func TestNewDuplicationBoundariesAndAbsence(t *testing.T) {
	changed := []FileChange{{Status: FileStatusModified, NewPath: "src/a.go", Added: []LineRange{{Start: 10, End: 10}}}}
	for name, tc := range map[string]struct {
		occ  measure.CodeRange
		want float64
	}{
		"ends exactly on the changed line":   {measure.CodeRange{File: "src/a.go", StartLine: 1, EndLine: 10}, 100},
		"starts exactly on the changed line": {measure.CodeRange{File: "src/a.go", StartLine: 10, EndLine: 30}, 100},
		"stops one line short":               {measure.CodeRange{File: "src/a.go", StartLine: 1, EndLine: 9}, 0},
		"starts one line late":               {measure.CodeRange{File: "src/a.go", StartLine: 11, EndLine: 30}, 0},
	} {
		t.Run(name, func(t *testing.T) {
			dup := measure.DuplicationReport{Blocks: []measure.DuplicationBlock{{Occurrences: []measure.CodeRange{tc.occ}}}}
			got, ok := measuresFor(nil, dup, changed)[qualitygate.MetricNewDuplication]
			if !ok || got != tc.want {
				t.Fatalf("new_duplication = %g ok=%v, want %g", got, ok, tc.want)
			}
		})
	}
	// With no changed lines there is nothing to measure: absent, never a 0 that a `<=` would pass.
	if v, present := measuresFor(nil, measure.DuplicationReport{DuplicatedLines: 50, TotalLines: 100}, nil)[qualitygate.MetricNewDuplication]; present {
		t.Fatalf("new_duplication must be absent without changed lines, got %g", v)
	}
	// A measured 0 is a value: changed lines exist and none is duplicated.
	if v, present := measuresFor(nil, measure.DuplicationReport{}, changed)[qualitygate.MetricNewDuplication]; !present || v != 0 {
		t.Fatalf("new_duplication over changed lines with no duplication must be a measured 0, got %g present=%v", v, present)
	}
}

// TestNewCodeMetricsGateEndToEnd is the acceptance criterion: a gate condition on the new-code metrics
// enforces the measured value, and fails closed with an explicit "unmeasured" when there is none.
func TestNewCodeMetricsGateEndToEnd(t *testing.T) {
	gate := qualitygate.Gate{Conditions: []qualitygate.Condition{
		{Metric: qualitygate.MetricNewCoverage, Op: qualitygate.OpGE, Threshold: 80},
		{Metric: qualitygate.MetricNewDuplication, Op: qualitygate.OpLE, Threshold: 3},
	}}
	coverage := &measure.CoverageReport{Lines: measure.LineCoverage{"src/a.go": {10: true, 11: true, 12: true, 20: false}, "src/b.go": {5: true}}}
	measured := qualitygate.Evaluate(gate, measuresFor(coverage, measure.DuplicationReport{}, changes()))
	if !measured.Passed {
		t.Fatalf("80%% new coverage and 0%% new duplication must pass: %+v", measured.Failures())
	}
	unmeasured := qualitygate.Evaluate(gate, measuresFor(nil, measure.DuplicationReport{}, nil))
	if unmeasured.Passed || len(unmeasured.Failures()) != 2 {
		t.Fatalf("with nothing measured both conditions must fail: %+v", unmeasured)
	}
	for _, f := range unmeasured.Failures() {
		if !f.Unmeasured {
			t.Fatalf("%s must fail as unmeasured, not on a value: %+v", f.Condition, f)
		}
	}
}
