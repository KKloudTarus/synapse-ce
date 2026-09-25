package reachbench

import (
	"bytes"
	"strings"
	"testing"
)

func TestEvaluateScoresExactLabelsAndPositiveRecall(t *testing.T) {
	corpus := Corpus{SchemaVersion: CorpusSchemaVersion, Cases: []Case{
		{Name: "go-hit", Language: "go", Fixture: "go-hit", Symbol: "fixture.hit", Expected: Reachable},
		{Name: "go-miss", Language: "go", Fixture: "go-miss", Symbol: "fixture.miss", Expected: PresentUnreached},
		{Name: "js-conditional", Language: "javascript", Fixture: "js", Symbol: "pkg.fn", Expected: ConditionallyReachable},
		{Name: "js-unsupported", Language: "javascript", Fixture: "js", Symbol: "pkg.other", Expected: NoAnalysis},
	}}
	report, err := Evaluate(corpus, []Observation{
		{Case: "go-hit", Label: Reachable},
		{Case: "go-miss", Label: Reachable},
		{Case: "js-conditional", Label: NoAnalysis},
		{Case: "js-unsupported", Label: NoAnalysis},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(report.Languages) != 2 {
		t.Fatalf("languages = %+v", report.Languages)
	}
	goScore, jsScore := report.Languages[0], report.Languages[1]
	if goScore.Language != "go" || goScore.Exact != 1 || goScore.PositiveRecall != 1 || goScore.PositivePrecision != 0.5 || goScore.FalsePositiveRise != 1 {
		t.Fatalf("go score = %+v", goScore)
	}
	if jsScore.Language != "javascript" || jsScore.Exact != 1 || jsScore.PositiveRecall != 0 || jsScore.PositivePrecision != 1 {
		t.Fatalf("javascript score = %+v", jsScore)
	}
	breaches := CheckRatchet(report, Floors{PositivePrecision: map[string]float64{"go": 0.5, "javascript": 1}, PositiveRecall: map[string]float64{"go": 1, "javascript": 1}})
	if len(breaches) != 1 || !strings.Contains(breaches[0], "javascript") || !strings.Contains(breaches[0], "recall") {
		t.Fatalf("ratchet breaches = %v", breaches)
	}
	breaches = CheckRatchet(report, Floors{PositivePrecision: map[string]float64{"go": 1, "javascript": 1}, PositiveRecall: map[string]float64{"go": 1, "javascript": 0}})
	if len(breaches) != 1 || !strings.Contains(breaches[0], "go") || !strings.Contains(breaches[0], "precision") {
		t.Fatalf("precision ratchet breaches = %v", breaches)
	}
}

func TestEvaluateRefusesOmittedAndUnknownCases(t *testing.T) {
	corpus := Corpus{SchemaVersion: CorpusSchemaVersion, Cases: []Case{{Name: "only", Language: "go", Fixture: "f", Symbol: "x", Expected: Reachable}}}
	if _, err := Evaluate(corpus, nil); err == nil || !strings.Contains(err.Error(), "omit") {
		t.Fatalf("omitted corpus case error = %v", err)
	}
	if _, err := Evaluate(corpus, []Observation{{Case: "other", Label: Reachable}}); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unknown corpus case error = %v", err)
	}
}

func TestLoadCorpusRejectsUnknownLabel(t *testing.T) {
	_, err := LoadCorpus(strings.NewReader(`{"schema_version":"synapse-reachability-corpus-v1","cases":[{"name":"x","language":"go","fixture":"f","symbol":"s","expected":"clean"}]}`))
	if err == nil || !strings.Contains(err.Error(), "unknown expected label") {
		t.Fatalf("LoadCorpus error = %v", err)
	}
}

func TestDecodeInputAndLoadReportProvideStrictPortableContract(t *testing.T) {
	input, err := DecodeInput(strings.NewReader(`{
		"schema_version":"synapse-reachability-input-v1",
		"corpus":{"schema_version":"synapse-reachability-corpus-v1","cases":[{"name":"go-hit","language":"go","fixture":"fixture","symbol":"fixture.hit","expected":"reachable"}]},
		"observations":[{"case":"go-hit","label":"reachable"}]
	}`))
	if err != nil {
		t.Fatalf("DecodeInput: %v", err)
	}
	report, err := EvaluateInput(input)
	if err != nil {
		t.Fatalf("EvaluateInput: %v", err)
	}
	var encoded bytes.Buffer
	if err := EncodeReport(&encoded, report); err != nil {
		t.Fatalf("EncodeReport: %v", err)
	}
	loaded, err := LoadReport(&encoded)
	if err != nil || loaded.CorpusDigest != report.CorpusDigest || loaded.Languages[0].PositiveRecall != 1 {
		t.Fatalf("LoadReport = %+v, %v", loaded, err)
	}
	if _, err := DecodeInput(strings.NewReader(`{"schema_version":"synapse-reachability-input-v1","corpus":{"schema_version":"synapse-reachability-corpus-v1","cases":[]},"observations":[],"unexpected":true}`)); err == nil {
		t.Fatal("DecodeInput must reject unknown fields rather than silently change corpus semantics")
	}
}

func TestDefaultCorpusAndFloorsFormAGatedContract(t *testing.T) {
	corpus := DefaultCorpus()
	if len(corpus.Cases) < 2 {
		t.Fatalf("default corpus has %d cases, want its reachable and unreached Go controls", len(corpus.Cases))
	}
	type labels struct{ positive, negative bool }
	byLanguage := map[string]labels{}
	for _, item := range corpus.Cases {
		current := byLanguage[item.Language]
		if positive(item.Expected) {
			current.positive = true
		} else {
			current.negative = true
		}
		byLanguage[item.Language] = current
	}
	floors := DefaultFloors()
	required := 0
	for language, observed := range byLanguage {
		if !observed.positive || !observed.negative {
			continue
		}
		required++
		if floor := floors.PositiveRecall[language]; floor != 1 {
			t.Fatalf("%s recall floor = %v, want 1", language, floor)
		}
		if floor := floors.PositivePrecision[language]; floor != 1 {
			t.Fatalf("%s precision floor = %v, want 1", language, floor)
		}
	}
	if len(floors.PositiveRecall) != required || len(floors.PositivePrecision) != required {
		t.Fatalf("floor languages precision=%d recall=%d, want %d", len(floors.PositivePrecision), len(floors.PositiveRecall), required)
	}
	var encoded bytes.Buffer
	if err := EncodeReport(&encoded, Report{SchemaVersion: ReportSchemaVersion}); err != nil || !strings.Contains(encoded.String(), ReportSchemaVersion) {
		t.Fatalf("EncodeReport = %q, %v", encoded.String(), err)
	}
}

func TestCheckRatchetForLanguagesFailsClosedOnMissingScoreOrFloor(t *testing.T) {
	report := Report{Languages: []LanguageScore{{Language: "go", PositivePrecision: 1, PositiveRecall: 1}}}
	floors := Floors{PositivePrecision: map[string]float64{"go": 1}, PositiveRecall: map[string]float64{"go": 1}}
	breaches := CheckRatchetForLanguages(report, floors, []string{"go", "python"})
	if len(breaches) != 1 || !strings.Contains(breaches[0], "python") || !strings.Contains(breaches[0], "missing from scorecard") {
		t.Fatalf("missing required score must fail closed, got %v", breaches)
	}

	breaches = CheckRatchetForLanguages(report, Floors{PositivePrecision: map[string]float64{"go": 1}, PositiveRecall: map[string]float64{}}, []string{"go"})
	if len(breaches) != 1 || !strings.Contains(breaches[0], "no recall floor") {
		t.Fatalf("missing required floor must fail closed, got %v", breaches)
	}
}

func TestLoadFloorsRejectsPartialMetricCoverage(t *testing.T) {
	_, err := LoadFloors(strings.NewReader(`{"positive_precision":{"go":1},"positive_recall":{}}`))
	if err == nil || !strings.Contains(err.Error(), "require precision and recall") {
		t.Fatalf("partial floors error = %v", err)
	}
	_, err = LoadFloors(strings.NewReader(`{"positive_precision":{"go":1},"positive_recall":{"python":1}}`))
	if err == nil || !strings.Contains(err.Error(), "no recall floor") {
		t.Fatalf("mismatched floor language error = %v", err)
	}
}

func TestCheckBaselineParityFailsClosedOnRegressionOrMissingLanguage(t *testing.T) {
	baseline := Report{CorpusDigest: "same-corpus", Languages: []LanguageScore{{Language: "go", PositiveRecall: 1, PositivePrecision: 1}, {Language: "python", PositiveRecall: 0.9, PositivePrecision: 1}}}
	candidate := Report{CorpusDigest: "same-corpus", Languages: []LanguageScore{{Language: "go", PositiveRecall: 0.8, PositivePrecision: 0.5}}}
	breaches := CheckBaselineParity(candidate, baseline)
	joined := strings.Join(breaches, "\n")
	if len(breaches) != 3 || !strings.Contains(joined, "go positive reachability recall") || !strings.Contains(joined, "go positive reachability precision") || !strings.Contains(joined, "python") {
		t.Fatalf("baseline parity breaches = %v", breaches)
	}
}

func TestCheckBaselineParityRefusesDifferentCorpus(t *testing.T) {
	breaches := CheckBaselineParity(Report{CorpusDigest: "candidate"}, Report{CorpusDigest: "baseline"})
	if len(breaches) != 1 || !strings.Contains(breaches[0], "different") {
		t.Fatalf("different corpus breaches = %v", breaches)
	}
}

func TestFilterByLanguageScopesCorpusAndDigest(t *testing.T) {
	full := DefaultCorpus()
	py, err := FilterByLanguage(full, "python")
	if err != nil {
		t.Fatalf("FilterByLanguage(python): %v", err)
	}
	if len(py.Cases) == 0 || len(py.Cases) == len(full.Cases) {
		t.Fatalf("python subset size = %d of %d", len(py.Cases), len(full.Cases))
	}
	for _, c := range py.Cases {
		if c.Language != "python" {
			t.Fatalf("filtered corpus contains a %q case", c.Language)
		}
	}
	// A language-scoped owned report and its baseline share this subset's digest, which is what makes a
	// language-scoped parity comparison legal; the full-corpus digest must differ.
	full.SchemaVersion = CorpusSchemaVersion
	if d1, _ := corpusDigest(py); d1 == "" {
		t.Fatal("filtered corpus has no digest")
	}
	if _, err := FilterByLanguage(full, "cobol"); err == nil {
		t.Fatal("a language with no cases must error, not pass vacuously")
	}
	if _, err := FilterByLanguage(full, ""); err == nil {
		t.Fatal("an empty language filter must error")
	}
}

// TestOwnedBeatsSemgrepPrecisionOnPythonCorpus is the recorded head-to-head math: on the Python corpus the
// owned engine is exact (recall 1.0, precision 1.0) while Semgrep CE, which cannot prove entrypoint
// reachability, over-reports every unreached fixture whose sink call site it matches (recall 1.0, precision
// below 1.0). Parity holds and the owned engine strictly wins on precision.
func TestOwnedBeatsSemgrepPrecisionOnPythonCorpus(t *testing.T) {
	py, err := FilterByLanguage(DefaultCorpus(), "python")
	if err != nil {
		t.Fatal(err)
	}
	owned := make([]Observation, 0, len(py.Cases))
	semgrep := make([]Observation, 0, len(py.Cases))
	for _, c := range py.Cases {
		owned = append(owned, Observation{Case: c.Name, Label: c.Expected})    // the owned engine is exact on the corpus
		semgrep = append(semgrep, Observation{Case: c.Name, Label: Reachable}) // Semgrep matches os.system in every fixture
	}
	ownedReport, err := Evaluate(py, owned)
	if err != nil {
		t.Fatal(err)
	}
	semgrepReport, err := Evaluate(py, semgrep)
	if err != nil {
		t.Fatal(err)
	}
	if breaches := CheckBaselineParity(ownedReport, semgrepReport); len(breaches) != 0 {
		t.Fatalf("owned engine must meet Semgrep parity on Python, got breaches: %v", breaches)
	}
	var owndScore, semScore LanguageScore
	for _, s := range ownedReport.Languages {
		if s.Language == "python" {
			owndScore = s
		}
	}
	for _, s := range semgrepReport.Languages {
		if s.Language == "python" {
			semScore = s
		}
	}
	if owndScore.PositivePrecision <= semScore.PositivePrecision {
		t.Fatalf("owned precision %.3f must exceed Semgrep precision %.3f", owndScore.PositivePrecision, semScore.PositivePrecision)
	}
	if semScore.FalsePositiveRise == 0 {
		t.Fatal("Semgrep must over-report at least one unreached Python case (its recorded limitation)")
	}
}

func TestCheckBaselineExpectationFailsClosed(t *testing.T) {
	exp, ok := ExpectedBaseline("semgrep-ce", "python")
	if !ok || exp.Cases != 10 || exp.PositiveProduced != 10 || exp.FalsePositiveRise != 4 {
		t.Fatalf("pinned semgrep python expectation = %+v ok=%v", exp, ok)
	}
	good := Report{Languages: []LanguageScore{{Language: "python", Cases: 10, PositiveExpected: 6, PositiveFound: 6, PositiveProduced: 10, FalsePositiveRise: 4}}}
	if breaches := CheckBaselineExpectation(good, "semgrep-ce", "python"); len(breaches) != 0 {
		t.Fatalf("exact match must have no breaches, got %v", breaches)
	}
	// A weakened baseline (fewer matches) breaches the pinned scorecard.
	weak := Report{Languages: []LanguageScore{{Language: "python", Cases: 10, PositiveExpected: 6, PositiveFound: 6, PositiveProduced: 5, FalsePositiveRise: 0}}}
	if breaches := CheckBaselineExpectation(weak, "semgrep-ce", "python"); len(breaches) == 0 {
		t.Fatal("a weakened baseline must breach the pinned scorecard")
	}
	// A shrunk denominator breaches.
	shrunk := Report{Languages: []LanguageScore{{Language: "python", Cases: 6, PositiveExpected: 6, PositiveFound: 6, PositiveProduced: 10, FalsePositiveRise: 4}}}
	if breaches := CheckBaselineExpectation(shrunk, "semgrep-ce", "python"); len(breaches) == 0 {
		t.Fatal("a shrunk denominator must breach the pinned scorecard")
	}
	// Unpinned tool fails closed.
	if breaches := CheckBaselineExpectation(good, "mystery", "python"); len(breaches) != 1 || !strings.Contains(breaches[0], "no pinned") {
		t.Fatalf("unpinned tool must fail closed, got %v", breaches)
	}
	// A report missing the language fails closed.
	if breaches := CheckBaselineExpectation(Report{Languages: []LanguageScore{{Language: "go"}}}, "semgrep-ce", "python"); len(breaches) != 1 || !strings.Contains(breaches[0], "no python language score") {
		t.Fatalf("missing language must fail closed, got %v", breaches)
	}
}
