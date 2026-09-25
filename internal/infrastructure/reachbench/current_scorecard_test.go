package reachbench

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	measurement "github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
)

func TestCurrentGoBinaryOracleIsVersionBoundAndCoversControls(t *testing.T) {
	positives, noAnalysis := 0, 0
	for _, item := range currentGoBinaryCases {
		if item.Expected == measurement.OutcomeReachable {
			positives++
		}
		if item.Expected == measurement.OutcomeNoAnalysis {
			noAnalysis++
		}
		if item.ID != "unversioned-identity" && item.ID != "wrong-version" && !strings.Contains(item.Subject, "@v0.59.0") {
			t.Fatalf("case %q is not version-bound: %q", item.ID, item.Subject)
		}
	}
	if positives != 2 || noAnalysis != 3 {
		t.Fatalf("oracle coverage = positives %d no-analysis %d", positives, noAnalysis)
	}
}

func TestCurrentGoBinaryBindingsRequireWorker(t *testing.T) {
	_, err := currentGoBinaryBindings(measurement.ProductionInventory{Cohorts: []measurement.ProductionCohort{{ID: "go", Mode: "binary", Bindings: []measurement.CompositionBinding{{ID: "api", State: measurement.BindingEnabled}}}}})
	if err == nil || !strings.Contains(err.Error(), "api and worker") {
		t.Fatalf("missing worker error = %v", err)
	}
}

func TestCurrentProductionInventoryDoesNotReuseHistoricalCheckpointIdentity(t *testing.T) {
	historicalDigest, err := measurement.DigestProductionInventory(measurement.DefaultProductionInventory())
	if err != nil {
		t.Fatal(err)
	}
	current, err := measurement.CurrentProductionInventory()
	if err != nil {
		t.Fatal(err)
	}
	if current.ID != "synapse-ce-current-go-binary-inventory-v1" {
		t.Fatalf("current contract reused historical inventory ID: %q", current.ID)
	}
	currentDigest, err := measurement.DigestProductionInventory(current)
	if err != nil {
		t.Fatal(err)
	}
	if historicalDigest == currentDigest {
		t.Fatal("current 100-cell inventory reused the historical 95-cell checkpoint identity")
	}
	bindings, err := currentGoBinaryBindings(current)
	if err != nil || len(bindings) != 2 {
		t.Fatalf("current worker contract = %#v, %v", bindings, err)
	}
}

func TestCurrentGoBinaryScorecardRequiresBothMeasuredBindingsAndRatchets(t *testing.T) {
	dir := t.TempDir()
	writeBindingReport(t, dir, "api", "")
	writeBindingReport(t, dir, "worker", "")
	scorecard, err := RunCurrentGoBinaryScorecard(context.Background(), scorecardSource(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if scorecard.Decision != "pass" || scorecard.ObservedCells != 10 || len(scorecard.Bindings) != 2 {
		t.Fatalf("complete scorecard = %+v", scorecard)
	}
	for _, binding := range scorecard.Bindings {
		if len(binding.Cases) != 5 || binding.ReachablePrecision != 1 || binding.ReachableRecall != 1 || binding.CoverageRate != 0.4 || binding.NoAnalysisRate != 0.6 || binding.FalseSuppressions != 0 {
			t.Fatalf("binding score = %+v", binding)
		}
	}
	if err := os.Remove(filepath.Join(dir, "worker.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := RunCurrentGoBinaryScorecard(context.Background(), scorecardSource(), dir); err == nil {
		t.Fatal("missing worker report did not fail closed")
	}
	writeBindingReport(t, dir, "worker", "drop")
	scorecard, err = RunCurrentGoBinaryScorecard(context.Background(), scorecardSource(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if scorecard.Decision != "fail" || scorecard.Bindings[1].DroppedFindings != 1 {
		t.Fatalf("dropped finding did not fail ratchet: %+v", scorecard)
	}
	writeBindingReport(t, dir, "worker", "exempt")
	scorecard, err = RunCurrentGoBinaryScorecard(context.Background(), scorecardSource(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if scorecard.Decision != "fail" || scorecard.Bindings[1].FalseSuppressions != 1 {
		t.Fatalf("gate exemption did not fail ratchet: %+v", scorecard)
	}
}

func writeBindingReport(t *testing.T, dir, binding, defect string) {
	t.Helper()
	report := currentBindingReport{BindingID: binding}
	for _, item := range currentGoBinaryCases {
		report.Cases = append(report.Cases, CurrentCaseScore{ID: item.ID, ExpectedOutcome: item.Expected, ActualOutcome: item.Expected, ExpectedCoverage: item.Coverage, ActualCoverage: item.Coverage, JudgmentCount: map[measurement.Outcome]int{measurement.OutcomeReachable: 1}[item.Expected], FindingRetained: true})
	}
	if defect == "drop" {
		report.Cases[0].FindingRetained = false
	}
	if defect == "exempt" {
		report.Cases[0].GateExempted = true
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, binding+".json"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}

func scorecardSource() RevisionIdentity {
	return RevisionIdentity{ID: AnalyzerSubjectID, Commit: strings.Repeat("a", 40), Tree: strings.Repeat("b", 40)}
}
