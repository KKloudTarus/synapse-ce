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
	breaches := CheckRatchet(report, Floors{PositiveRecall: map[string]float64{"go": 1, "javascript": 1}})
	if len(breaches) != 1 || !strings.Contains(breaches[0], "javascript") {
		t.Fatalf("ratchet breaches = %v", breaches)
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
	if floor := DefaultFloors().PositiveRecall["go"]; floor != 1 {
		t.Fatalf("Go recall floor = %v, want 1", floor)
	}
	var encoded bytes.Buffer
	if err := EncodeReport(&encoded, Report{SchemaVersion: ReportSchemaVersion}); err != nil || !strings.Contains(encoded.String(), ReportSchemaVersion) {
		t.Fatalf("EncodeReport = %q, %v", encoded.String(), err)
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
