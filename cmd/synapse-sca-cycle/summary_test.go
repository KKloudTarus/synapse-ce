package main

import (
	"bytes"
	"strings"
	"testing"

	capture "github.com/KKloudTarus/synapse-ce/internal/infrastructure/scabench"
	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

func TestPrintCandidateSummaryShowsScoresAndFailureReason(t *testing.T) {
	result := capture.CandidateResult{
		Candidate: &bench.Result{
			RunMetrics: []bench.RunMetric{{Run: bench.RunIdentity{TargetID: "sles", Engine: bench.EngineOwned}, Metrics: bench.EngineResult{TruePositives: 16, FalseNegatives: 0, Unknown: 582}}},
			Gate:       &bench.Gate{Checks: []bench.GateCheck{{Expected: bench.ExpectedRunIdentity{TargetID: "sles", Engine: bench.EngineOwned}, ReasonCodes: []bench.GateReasonCode{bench.GateReasonThresholdBreach}}}},
		},
	}
	var output bytes.Buffer
	printCandidateSummary(&output, result)
	for _, value := range []string{"0/1 cells", "pre-rebind gate: false", "sles", "owned", "16", "582", "threshold_breach"} {
		if !strings.Contains(output.String(), value) {
			t.Fatalf("summary %q does not contain %q", output.String(), value)
		}
	}
}
