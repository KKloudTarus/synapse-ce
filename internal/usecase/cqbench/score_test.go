package cqbench

import (
	"bytes"
	"strings"
	"testing"
)

func intp(v int) *int           { return &v }
func floatp(v float64) *float64 { return &v }

func testCorpus() Corpus {
	return Corpus{
		SchemaVersion: CorpusSchemaVersion,
		Cases: []Case{
			{
				Name:     "go-a",
				Language: "go",
				Fixture:  "go-a",
				Issues: []Issue{
					{File: "a.go", Line: 10, Type: TypeCodeSmell},
					{File: "a.go", Line: 40, Type: TypeBug},
				},
			},
			{
				Name:     "py-a",
				Language: "python",
				Fixture:  "py-a",
				Issues: []Issue{
					{File: "a.py", Line: 5, Type: TypeVulnerability},
				},
			},
		},
	}
}

func TestEvaluatePerfectScore(t *testing.T) {
	c := testCorpus()
	obs := []CaseObservation{
		{Case: "go-a", Issues: []Issue{
			{File: "a.go", Line: 10, Type: TypeCodeSmell},
			{File: "a.go", Line: 40, Type: TypeBug},
		}},
		{Case: "py-a", Issues: []Issue{{File: "a.py", Line: 5, Type: TypeVulnerability}}},
	}
	rep, err := Evaluate("owned", c, obs)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if rep.Cases != 2 || rep.Engine != "owned" || rep.CorpusDigest == "" {
		t.Fatalf("report header = %+v", rep)
	}
	for _, cell := range rep.Types {
		if cell.Recall != 1 || cell.Precision != 1 || cell.FN != 0 || cell.FP != 0 {
			t.Errorf("cell %s/%s not perfect: %+v", cell.Language, cell.Type, cell)
		}
	}
}

func TestEvaluateLineToleranceAndMisses(t *testing.T) {
	c := testCorpus()
	obs := []CaseObservation{
		// go-a: code_smell detected 2 lines off (within tolerance → TP); bug missed; an extra spurious bug (FP).
		{Case: "go-a", Issues: []Issue{
			{File: "a.go", Line: 12, Type: TypeCodeSmell},
			{File: "a.go", Line: 99, Type: TypeBug},
		}},
		// py-a: vulnerability detected 3 lines off (outside tolerance → FP + FN).
		{Case: "py-a", Issues: []Issue{{File: "a.py", Line: 8, Type: TypeVulnerability}}},
	}
	rep, err := Evaluate("owned", c, obs)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	cells := map[string]TypeScore{}
	for _, cell := range rep.Types {
		cells[CellKey(cell.Language, cell.Type)] = cell
	}
	if got := cells["go/code_smell"]; got.TP != 1 || got.FP != 0 || got.FN != 0 {
		t.Errorf("go/code_smell within tolerance should be a clean TP, got %+v", got)
	}
	if got := cells["go/bug"]; got.TP != 0 || got.FP != 1 || got.FN != 1 || got.Recall != 0 {
		t.Errorf("go/bug: missed expected + spurious detection, got %+v", got)
	}
	if got := cells["python/vulnerability"]; got.TP != 0 || got.FP != 1 || got.FN != 1 {
		t.Errorf("python/vuln beyond tolerance is FP+FN, got %+v", got)
	}
}

func TestEvaluateWrongTypeDoesNotMatch(t *testing.T) {
	c := Corpus{SchemaVersion: CorpusSchemaVersion, Cases: []Case{
		{Name: "x", Language: "go", Fixture: "x", Issues: []Issue{{File: "x.go", Line: 3, Type: TypeBug}}},
	}}
	// Same location, wrong type: the bug is missed and the smell is spurious.
	rep, err := Evaluate("owned", c, []CaseObservation{
		{Case: "x", Issues: []Issue{{File: "x.go", Line: 3, Type: TypeCodeSmell}}},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	cells := map[string]TypeScore{}
	for _, cell := range rep.Types {
		cells[CellKey(cell.Language, cell.Type)] = cell
	}
	if cells["go/bug"].FN != 1 || cells["go/code_smell"].FP != 1 {
		t.Errorf("a type mismatch must not match: %+v", cells)
	}
}

func TestEvaluateOneToOneMatching(t *testing.T) {
	// Two expected smells close together; two detections. Each detection must claim a distinct expected issue,
	// not both collapse onto the nearest one.
	c := Corpus{SchemaVersion: CorpusSchemaVersion, Cases: []Case{
		{Name: "x", Language: "go", Fixture: "x", Issues: []Issue{
			{File: "x.go", Line: 10, Type: TypeCodeSmell},
			{File: "x.go", Line: 11, Type: TypeCodeSmell},
		}},
	}}
	rep, err := Evaluate("owned", c, []CaseObservation{
		{Case: "x", Issues: []Issue{
			{File: "x.go", Line: 10, Type: TypeCodeSmell},
			{File: "x.go", Line: 11, Type: TypeCodeSmell},
		}},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if rep.Types[0].TP != 2 || rep.Types[0].FP != 0 || rep.Types[0].FN != 0 {
		t.Errorf("two distinct issues must both match one-to-one, got %+v", rep.Types[0])
	}
}

func TestEvaluateRejectsBadObservations(t *testing.T) {
	c := testCorpus()
	full := []CaseObservation{{Case: "go-a"}, {Case: "py-a"}}
	if _, err := Evaluate("owned", c, append(full, CaseObservation{Case: "go-a"})); err == nil {
		t.Error("duplicate observation must error")
	}
	if _, err := Evaluate("owned", c, []CaseObservation{{Case: "go-a"}, {Case: "nope"}}); err == nil {
		t.Error("unknown case must error")
	}
	if _, err := Evaluate("owned", c, []CaseObservation{{Case: "go-a"}}); err == nil {
		t.Error("omitting a corpus case must error")
	}
	if _, err := Evaluate("", c, full); err == nil {
		t.Error("empty engine name must error")
	}
}

func TestCheckRatchet(t *testing.T) {
	rep := Report{Types: []TypeScore{
		{Language: "go", Type: TypeBug, TP: 1, FP: 0, FN: 1, Recall: 0.5, Precision: 1},
		{Language: "go", Type: TypeCodeSmell, TP: 1, FP: 9, FN: 0, Recall: 1, Precision: 0.1},
	}}
	floors := Floors{Recall: map[string]float64{"go/bug": 0.8}, PrecisionTripwire: 0.2}
	breaches := CheckRatchet(rep, floors)
	if len(breaches) != 2 {
		t.Fatalf("want 2 breaches (recall floor + precision tripwire), got %v", breaches)
	}
	if !strings.Contains(breaches[0], "go/bug") || !strings.Contains(breaches[1], "go/code_smell") {
		t.Errorf("breaches not sorted/attributed: %v", breaches)
	}
	// A cell with no floor and healthy precision is not gated.
	if b := CheckRatchet(Report{Types: []TypeScore{{Language: "rust", Type: TypeBug, TP: 1, Recall: 0.1, Precision: 1}}}, floors); len(b) != 0 {
		t.Errorf("an ungated cell must not breach, got %v", b)
	}
}

func TestCheckRatchetTripwireIgnoresUnlabelledCells(t *testing.T) {
	// A lone false positive in a cell with NO labelled issues (Expected=0) must not trip the precision wire:
	// there is nothing to recall there, and the docstring promises an unfloored cell is not gated.
	rep := Report{Types: []TypeScore{
		{Language: "go", Type: TypeBug, Expected: 0, Detected: 1, TP: 0, FP: 1, FN: 0, Precision: 0, Recall: 0},
	}}
	floors := Floors{Recall: map[string]float64{}, PrecisionTripwire: 0.1}
	if breaches := CheckRatchet(rep, floors); len(breaches) != 0 {
		t.Fatalf("a false positive in an unlabelled cell must not trip the wire, got %v", breaches)
	}
	// But a cell WITH labelled issues whose precision collapses still trips.
	rep2 := Report{Types: []TypeScore{
		{Language: "go", Type: TypeBug, Expected: 1, Detected: 20, TP: 1, FP: 19, FN: 0, Precision: 0.05, Recall: 1},
	}}
	if breaches := CheckRatchet(rep2, floors); len(breaches) != 1 {
		t.Fatalf("an all-flagging labelled cell must trip the wire, got %v", breaches)
	}
}

func TestMatchGroupCrossedPair(t *testing.T) {
	// Expected [1,3], detected [3,5], tolerance 2: the optimal one-to-one match pairs 3->1 and 5->3, so both
	// detections are true positives. A nearest-first greedy would wrongly score TP=1.
	c := Corpus{SchemaVersion: CorpusSchemaVersion, Cases: []Case{
		{Name: "x", Language: "go", Fixture: "x", Issues: []Issue{
			{File: "x.go", Line: 1, Type: TypeBug},
			{File: "x.go", Line: 3, Type: TypeBug},
		}},
	}}
	rep, err := Evaluate("owned", c, []CaseObservation{
		{Case: "x", Issues: []Issue{
			{File: "x.go", Line: 3, Type: TypeBug},
			{File: "x.go", Line: 5, Type: TypeBug},
		}},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if rep.Types[0].TP != 2 || rep.Types[0].FP != 0 || rep.Types[0].FN != 0 {
		t.Fatalf("crossed pair must match both one-to-one, got %+v", rep.Types[0])
	}
}

func TestValidateCorpusRejectsDuplicateFixture(t *testing.T) {
	c := Corpus{SchemaVersion: CorpusSchemaVersion, Cases: []Case{
		{Name: "a", Language: "go", Fixture: "shared"},
		{Name: "b", Language: "go", Fixture: "shared"},
	}}
	if _, err := Evaluate("owned", c, nil); err == nil {
		t.Error("two cases sharing a fixture dir must be rejected by validateCorpus")
	}
}

func TestCompareToBaseline(t *testing.T) {
	c := testCorpus()
	owned, _ := Evaluate("owned", c, []CaseObservation{
		{Case: "go-a", Issues: []Issue{{File: "a.go", Line: 10, Type: TypeCodeSmell}, {File: "a.go", Line: 40, Type: TypeBug}}},
		{Case: "py-a", Issues: []Issue{{File: "a.py", Line: 5, Type: TypeVulnerability}}},
	})
	base, _ := Evaluate("sonarqube-ce", c, []CaseObservation{
		{Case: "go-a", Issues: []Issue{{File: "a.go", Line: 10, Type: TypeCodeSmell}}}, // misses the bug
		{Case: "py-a", Issues: []Issue{{File: "a.py", Line: 5, Type: TypeVulnerability}}},
	})
	lines, err := CompareToBaseline(owned, base)
	if err != nil {
		t.Fatalf("CompareToBaseline: %v", err)
	}
	if len(lines) == 0 {
		t.Fatal("expected head-to-head lines")
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "sonarqube-ce") {
		t.Errorf("comparison must name the baseline engine: %s", joined)
	}
	// Different corpora must be refused.
	other := testCorpus()
	other.Cases = other.Cases[:1]
	otherRep, _ := Evaluate("x", other, []CaseObservation{{Case: "go-a", Issues: []Issue{{File: "a.go", Line: 10, Type: TypeCodeSmell}, {File: "a.go", Line: 40, Type: TypeBug}}}})
	if _, err := CompareToBaseline(owned, otherRep); err == nil {
		t.Error("comparing across different corpora must error")
	}
}

func TestMetricAgreement(t *testing.T) {
	c := Corpus{SchemaVersion: CorpusSchemaVersion, Cases: []Case{
		{Name: "m", Language: "go", Fixture: "m", Metrics: &Metrics{MaxCyclomatic: intp(18), DuplicatedLines: intp(20), CoveragePercent: floatp(80)}},
	}}
	rep, err := Evaluate("owned", c, []CaseObservation{
		// cyclomatic within tolerance (18 vs 19), duplication off by 10 (disagree), coverage unmeasured.
		{Case: "m", Metrics: &Metrics{MaxCyclomatic: intp(19), DuplicatedLines: intp(30)}},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	got := map[string]MetricAgreement{}
	for _, m := range rep.Metrics {
		got[m.Metric] = m
	}
	if got["max_cyclomatic"].Agreed != 1 || got["max_cyclomatic"].Comparable != 1 {
		t.Errorf("cyclomatic within tolerance should agree: %+v", got["max_cyclomatic"])
	}
	if got["duplicated_lines"].Agreed != 0 || got["duplicated_lines"].Comparable != 1 {
		t.Errorf("duplication beyond tolerance should disagree: %+v", got["duplicated_lines"])
	}
	if _, ok := got["coverage_percent"]; ok {
		t.Errorf("coverage was not observed, so it must not be comparable: %+v", got["coverage_percent"])
	}
}

func TestReportRoundTrip(t *testing.T) {
	c := testCorpus()
	rep, err := Evaluate("owned", c, []CaseObservation{
		{Case: "go-a", Issues: []Issue{{File: "a.go", Line: 10, Type: TypeCodeSmell}, {File: "a.go", Line: 40, Type: TypeBug}}},
		{Case: "py-a", Issues: []Issue{{File: "a.py", Line: 5, Type: TypeVulnerability}}},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	var buf bytes.Buffer
	if err := EncodeReport(&buf, rep); err != nil {
		t.Fatalf("EncodeReport: %v", err)
	}
	loaded, err := LoadReport(&buf)
	if err != nil {
		t.Fatalf("LoadReport: %v", err)
	}
	if loaded.CorpusDigest != rep.CorpusDigest || loaded.Engine != rep.Engine || loaded.Cases != rep.Cases {
		t.Errorf("round-trip drifted: %+v vs %+v", loaded, rep)
	}
}

func TestDecodeInputStrict(t *testing.T) {
	good := `{"schema_version":"synapse-codequality-input-v1","engine":"owned",
	 "corpus":{"schema_version":"synapse-codequality-corpus-v1","cases":[
	   {"name":"x","language":"go","fixture":"x","issues":[{"file":"x.go","line":3,"type":"bug"}]}]},
	 "observations":[{"case":"x","issues":[{"file":"x.go","line":3,"type":"bug"}]}]}`
	in, err := DecodeInput(strings.NewReader(good))
	if err != nil {
		t.Fatalf("DecodeInput: %v", err)
	}
	rep, err := EvaluateInput(in)
	if err != nil {
		t.Fatalf("EvaluateInput: %v", err)
	}
	if rep.Types[0].TP != 1 {
		t.Errorf("expected 1 TP, got %+v", rep.Types)
	}
	// Unknown field must be rejected.
	if _, err := DecodeInput(strings.NewReader(`{"schema_version":"synapse-codequality-input-v1","engine":"o","corpus":{},"extra":1}`)); err == nil {
		t.Error("unknown field must be rejected")
	}
}

func TestDefaultCorpusAndFloorsValid(t *testing.T) {
	c := DefaultCorpus() // panics if the embedded corpus is invalid
	if c.SchemaVersion != CorpusSchemaVersion || len(c.Cases) == 0 {
		t.Fatalf("default corpus invalid: %+v", c)
	}
	f := DefaultFloors()
	if f.Recall == nil {
		t.Error("default floors should decode a (possibly empty) recall map")
	}
	// The default corpus must evaluate cleanly against a perfect observation set (digest + schema wiring).
	obs := make([]CaseObservation, 0, len(c.Cases))
	for _, cs := range c.Cases {
		obs = append(obs, CaseObservation{Case: cs.Name, Issues: cs.Issues})
	}
	if _, err := Evaluate("owned", c, obs); err != nil {
		t.Fatalf("default corpus does not evaluate: %v", err)
	}
}

func TestCorpusValidationRejectsBadCases(t *testing.T) {
	bad := []Corpus{
		{SchemaVersion: "wrong", Cases: []Case{{Name: "x", Language: "go", Fixture: "x"}}},
		{SchemaVersion: CorpusSchemaVersion, Cases: nil},
		{SchemaVersion: CorpusSchemaVersion, Cases: []Case{{Name: "x", Language: "go", Fixture: "x", Issues: []Issue{{File: "x", Line: 0, Type: TypeBug}}}}},
		{SchemaVersion: CorpusSchemaVersion, Cases: []Case{{Name: "x", Language: "go", Fixture: "x", Issues: []Issue{{File: "x", Line: 1, Type: "nonsense"}}}}},
		{SchemaVersion: CorpusSchemaVersion, Cases: []Case{{Name: "x", Language: "go", Fixture: "x"}, {Name: "x", Language: "go", Fixture: "y"}}},
	}
	for i, c := range bad {
		if _, err := Evaluate("owned", c, nil); err == nil {
			t.Errorf("bad corpus %d must be rejected", i)
		}
	}
}
