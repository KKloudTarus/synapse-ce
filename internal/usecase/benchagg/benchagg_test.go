package benchagg

import (
	"encoding/json"
	"testing"
)

func secrets() DimensionResult {
	return DimensionResult{
		Semantics:      MetricSemantics{Dimension: "secrets", Positive: "a live-format credential", Unit: "finding"},
		TP:             7, FP: 1, FN: 0, TN: 3, RecallFloor: 1.0, PrecisionFloor: 0.8,
	}
}
func iac() DimensionResult {
	return DimensionResult{
		Semantics:      MetricSemantics{Dimension: "iac-misconfig", Positive: "a misconfigured resource", Unit: "resource"},
		TP:             6, FP: 0, FN: 0, TN: 6, RecallFloor: 1.0, PrecisionFloor: 1.0,
	}
}
func cspm() DimensionResult {
	return DimensionResult{
		Semantics:      MetricSemantics{Dimension: "cspm", Positive: "a posture violation", Unit: "resource"},
		TP:             8, FP: 0, FN: 0, TN: 2, RecallFloor: 1.0, PrecisionFloor: 1.0,
	}
}

func TestAggregatePreservesPerDimensionSemantics(t *testing.T) {
	rep, err := Aggregate([]DimensionResult{cspm(), secrets(), iac()})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Schema != ReportSchemaVersion {
		t.Errorf("schema = %q, want %q", rep.Schema, ReportSchemaVersion)
	}
	if len(rep.Dimensions) != 3 {
		t.Fatalf("want 3 dimension rows, got %d", len(rep.Dimensions))
	}
	// Rows are sorted by dimension id for determinism.
	if rep.Dimensions[0].Dimension != "cspm" || rep.Dimensions[1].Dimension != "iac-misconfig" || rep.Dimensions[2].Dimension != "secrets" {
		t.Errorf("rows not sorted by dimension: %v", []string{rep.Dimensions[0].Dimension, rep.Dimensions[1].Dimension, rep.Dimensions[2].Dimension})
	}
	// Each row keeps its OWN positive/unit semantics; the aggregate never conflates them.
	byID := map[string]DimensionRow{}
	for _, d := range rep.Dimensions {
		byID[d.Dimension] = d
	}
	if byID["secrets"].Unit != "finding" || byID["cspm"].Unit != "resource" || byID["secrets"].Positive != "a live-format credential" {
		t.Errorf("per-dimension semantics not preserved: %+v", byID)
	}
	// Metrics are per dimension: secrets recall 7/7=1.0, precision 7/8=0.875.
	if r := byID["secrets"].Recall; r != 1.0 {
		t.Errorf("secrets recall = %v, want 1.0", r)
	}
	if p := byID["secrets"].Precision; p < 0.874 || p > 0.876 {
		t.Errorf("secrets precision = %v, want ~0.875", p)
	}
	if !rep.AllFloorsMet {
		t.Errorf("all dimensions meet floors, want AllFloorsMet true")
	}
	if f := rep.FailingDimensions(); len(f) != 0 {
		t.Errorf("no dimension should fail, got %v", f)
	}
}

func TestAggregateFlagsAFailingDimensionWithoutMergingMatrices(t *testing.T) {
	bad := secrets()
	bad.Semantics.Dimension = "secrets"
	bad.FP = 5 // precision 7/12 = 0.583 < 0.8 floor
	rep, err := Aggregate([]DimensionResult{iac(), bad})
	if err != nil {
		t.Fatal(err)
	}
	if rep.AllFloorsMet {
		t.Errorf("a below-floor dimension must make AllFloorsMet false")
	}
	if f := rep.FailingDimensions(); len(f) != 1 || f[0] != "secrets" {
		t.Errorf("FailingDimensions must name only secrets, got %v", f)
	}
	// The passing dimension's row is untouched (no cross-dimension contamination).
	for _, d := range rep.Dimensions {
		if d.Dimension == "iac-misconfig" && !d.FloorsMet {
			t.Errorf("iac-misconfig meets its floors and must stay passing regardless of the secrets failure")
		}
	}
}

func TestAggregateRefusesDuplicateAndEmptyDimension(t *testing.T) {
	if _, err := Aggregate([]DimensionResult{secrets(), secrets()}); err == nil {
		t.Error("duplicate dimension id must be refused")
	}
	empty := secrets()
	empty.Semantics.Dimension = ""
	if _, err := Aggregate([]DimensionResult{empty}); err == nil {
		t.Error("empty dimension id must be refused")
	}
	if _, err := Aggregate(nil); err == nil {
		t.Error("no results must be refused")
	}
}

func TestDimensionResultMetricEdges(t *testing.T) {
	noPos := DimensionResult{Semantics: MetricSemantics{Dimension: "d"}, TP: 0, FN: 0, FP: 2}
	if noPos.Recall() != 0 {
		t.Errorf("recall with no positive cases must be 0, got %v", noPos.Recall())
	}
	noFlag := DimensionResult{Semantics: MetricSemantics{Dimension: "d"}, TP: 0, FP: 0, FN: 3}
	if noFlag.Precision() != 0 {
		t.Errorf("precision with nothing flagged must be 0, got %v", noFlag.Precision())
	}
	// A zero floor is vacuously met.
	if !noFlag.MeetsFloors() {
		t.Errorf("zero floors must be vacuously met")
	}
}

func TestReportIsMachineReadable(t *testing.T) {
	rep, err := Aggregate([]DimensionResult{secrets(), cspm()})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var round Report
	if err := json.Unmarshal(data, &round); err != nil {
		t.Fatalf("aggregate report must round-trip through JSON: %v", err)
	}
	if round.Schema != ReportSchemaVersion || len(round.Dimensions) != 2 || round.AllFloorsMet != rep.AllFloorsMet {
		t.Errorf("JSON round-trip lost data: %+v", round)
	}
}
