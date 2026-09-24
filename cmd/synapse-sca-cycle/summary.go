package main

import (
	"fmt"
	"io"
	"strings"

	capture "github.com/KKloudTarus/synapse-ce/internal/infrastructure/scabench"
	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

func printCandidateSummary(output io.Writer, result capture.CandidateResult) {
	if result.Candidate == nil || result.Candidate.Gate == nil {
		return
	}
	_, _ = fmt.Fprintf(output, "Candidate gate: %d/%d cells; pre-rebind gate: %t; accepted: false\n",
		countPassedChecks(result.Candidate.Gate.Checks), len(result.Candidate.Gate.Checks), result.Gate.HistoricalPassed)
	_, _ = fmt.Fprintln(output, "TARGET                                 ENGINE       TP  FP  FN  UNKNOWN  GATE")
	metrics := make(map[string]bench.EngineResult, len(result.Candidate.RunMetrics))
	for _, item := range result.Candidate.RunMetrics {
		metrics[string(item.Run.Engine)+"\x00"+item.Run.TargetID] = item.Metrics
	}
	for _, check := range result.Candidate.Gate.Checks {
		metric, found := metrics[string(check.Expected.Engine)+"\x00"+check.Expected.TargetID]
		if !found {
			_, _ = fmt.Fprintf(output, "%-38s %-12s %3s %3s %3s %8s  missing_metrics\n",
				check.Expected.TargetID, check.Expected.Engine, "-", "-", "-", "-")
			continue
		}
		status := "pass"
		if !check.Passed {
			codes := make([]string, len(check.ReasonCodes))
			for index, code := range check.ReasonCodes {
				codes[index] = string(code)
			}
			status = strings.Join(codes, ",")
			if status == "" {
				status = "fail"
			}
		}
		_, _ = fmt.Fprintf(output, "%-38s %-12s %3d %3d %3d %8d  %s\n",
			check.Expected.TargetID, check.Expected.Engine, metric.TruePositives, metric.FalsePositives,
			metric.FalseNegatives, metric.Unknown, status)
	}
}

func countPassedChecks(checks []bench.GateCheck) int {
	passed := 0
	for _, check := range checks {
		if check.Passed {
			passed++
		}
	}
	return passed
}
