package benchmark

import (
	"math"
	"strings"
	"testing"
)

func approx(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestEvaluateAccuracyRejectsSchema(t *testing.T) {
	if _, err := EvaluateAccuracy(AccuracyInput{SchemaVersion: "nope"}); err == nil {
		t.Fatal("expected schema-version error")
	}
}

func TestEvaluateAccuracyConfusionCounts(t *testing.T) {
	in := AccuracyInput{
		SchemaVersion: AccuracyInputSchemaVersion,
		Observations: []AccuracyObservation{
			// 2 TP, 1 FP (extra), 1 FN (missed).
			{Case: "npm-a", Group: "npm", Expected: []string{"lodash|CVE-1", "lodash|CVE-2", "axios|CVE-3"}, Produced: []string{"lodash|CVE-1", "lodash|CVE-2", "lodash|CVE-9"}},
			// perfect.
			{Case: "pypi-a", Group: "PyPI", Expected: []string{"flask|CVE-4"}, Produced: []string{"flask|CVE-4"}},
			// clean negative: nothing expected, nothing produced -> no counts.
			{Case: "go-clean", Group: "Go", Expected: nil, Produced: nil},
		},
	}
	rep, err := EvaluateAccuracy(in)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if rep.Cases != 3 {
		t.Fatalf("cases = %d, want 3", rep.Cases)
	}
	// Overall: TP=3, FP=1, FN=1.
	o := rep.Overall
	if o.TruePositives != 3 || o.FalsePositives != 1 || o.FalseNegatives != 1 {
		t.Fatalf("overall counts = %+v, want TP3 FP1 FN1", o)
	}
	if !approx(o.Precision, 3.0/4.0) || !approx(o.Recall, 3.0/4.0) {
		t.Fatalf("overall precision/recall = %v/%v, want 0.75/0.75", o.Precision, o.Recall)
	}
	if !approx(o.F1, 0.75) {
		t.Fatalf("overall f1 = %v, want 0.75", o.F1)
	}
	if !approx(o.FalseDiscoveryRate, 0.25) || !approx(o.FalseNegativeRate, 0.25) {
		t.Fatalf("overall fdr/fn rate = %v/%v, want 0.25/0.25", o.FalseDiscoveryRate, o.FalseNegativeRate)
	}
	// Groups sorted: Go, PyPI, npm.
	if len(rep.Groups) != 3 || rep.Groups[0].Group != "Go" || rep.Groups[1].Group != "PyPI" || rep.Groups[2].Group != "npm" {
		t.Fatalf("groups = %+v, want sorted [Go PyPI npm]", rep.Groups)
	}
	npm := rep.Groups[2].Metrics
	if npm.TruePositives != 2 || npm.FalsePositives != 1 || npm.FalseNegatives != 1 {
		t.Fatalf("npm group = %+v, want TP2 FP1 FN1", npm)
	}
	pypi := rep.Groups[1].Metrics
	if !approx(pypi.Precision, 1) || !approx(pypi.Recall, 1) || !approx(pypi.F1, 1) {
		t.Fatalf("PyPI group must be perfect, got %+v", pypi)
	}
}

func TestEvaluateAccuracyNoDataConventions(t *testing.T) {
	rep, err := EvaluateAccuracy(AccuracyInput{
		SchemaVersion: AccuracyInputSchemaVersion,
		Observations:  []AccuracyObservation{{Case: "empty"}},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	o := rep.Overall
	if !approx(o.Precision, 1) || !approx(o.Recall, 1) {
		t.Fatalf("no-data precision/recall = %v/%v, want 1/1", o.Precision, o.Recall)
	}
	if !approx(o.FalseDiscoveryRate, 0) || !approx(o.FalseNegativeRate, 0) {
		t.Fatalf("no-data fdr/fn rate = %v/%v, want 0/0", o.FalseDiscoveryRate, o.FalseNegativeRate)
	}
}

func TestEvaluateAccuracyDedupsWithinCase(t *testing.T) {
	rep, err := EvaluateAccuracy(AccuracyInput{
		SchemaVersion: AccuracyInputSchemaVersion,
		Observations: []AccuracyObservation{
			{Case: "dup", Expected: []string{"a|CVE-1", "a|CVE-1", " "}, Produced: []string{"a|CVE-1", "a|CVE-1"}},
		},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if rep.Overall.TruePositives != 1 || rep.Overall.FalsePositives != 0 || rep.Overall.FalseNegatives != 0 {
		t.Fatalf("dedup counts = %+v, want TP1 FP0 FN0", rep.Overall)
	}
}

func TestEvaluateAccuracyRejectsDuplicateAndEmptyCase(t *testing.T) {
	if _, err := EvaluateAccuracy(AccuracyInput{SchemaVersion: AccuracyInputSchemaVersion, Observations: []AccuracyObservation{{Case: ""}}}); err == nil {
		t.Fatal("expected empty-case error")
	}
	_, err := EvaluateAccuracy(AccuracyInput{SchemaVersion: AccuracyInputSchemaVersion, Observations: []AccuracyObservation{{Case: "x"}, {Case: "x"}}})
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate-case error, got %v", err)
	}
}
