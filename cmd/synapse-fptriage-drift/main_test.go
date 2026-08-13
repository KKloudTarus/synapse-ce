package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

func TestRunWritesAlertReportBeforeReturningFailure(t *testing.T) {
	directory := t.TempDir()
	baselinePath := filepath.Join(directory, "baseline.json")
	observedPath := filepath.Join(directory, "observed.json")
	outputPath := filepath.Join(directory, "report.json")
	writeTestJSON(t, baselinePath, testBaseline())
	writeTestJSON(t, observedPath, map[string]any{
		"generated_at": "2026-08-13T00:00:00Z",
		"distribution": testDistribution(100, map[string]int{"go": 2000, "typescript": 8000}),
	})

	err := run(baselinePath, observedPath, outputPath, true)
	if !errors.Is(err, errDriftAlert) {
		t.Fatalf("run() error = %v", err)
	}
	data, readErr := os.ReadFile(outputPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	var report sca.AITriageDriftReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "drift_detected" || report.ReportID == "" || len(report.Alerts) != 1 {
		t.Fatalf("report = %+v", report)
	}
	if err := run(baselinePath, observedPath, outputPath, false); err != nil {
		t.Fatalf("run(fail-on-alert=false) error = %v", err)
	}
}

func TestRunRejectsOutputThatOverwritesInput(t *testing.T) {
	directory := t.TempDir()
	baselinePath := filepath.Join(directory, "baseline.json")
	observedPath := filepath.Join(directory, "observed.json")
	writeTestJSON(t, baselinePath, testBaseline())
	writeTestJSON(t, observedPath, testDistribution(100, map[string]int{"go": 6000, "typescript": 4000}))

	if err := run(baselinePath, observedPath, observedPath, false); err == nil {
		t.Fatal("run() accepted an output path that overwrites observed input")
	}
}

func testBaseline() map[string]any {
	return map[string]any{
		"schema_version": "synapse-ai-triage-drift-baseline-v1",
		"version":        "production-2026-08", "provenance": "security/review-42", "approved_by": "security@example.com",
		"minimum_samples": 50, "maximum_total_variation_basis_points": 1000,
		"distribution": testDistribution(100, map[string]int{"go": 6000, "typescript": 4000}),
	}
}

func testDistribution(sampleSize int, languages map[string]int) map[string]any {
	return map[string]any{
		"schema_version": "synapse-ai-triage-distribution-v1", "sample_size": sampleSize,
		"language_basis_points": languages,
		"cwe_basis_points":      map[string]int{"CWE-79": 10_000},
		"project_basis_points":  map[string]int{"project-a": 10_000},
	}
}

func writeTestJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
