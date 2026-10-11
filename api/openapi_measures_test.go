package api_test

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestMeasureUnavailableReasonListsEveryNewCodeCoverageReason pins the contract to what the measures
// API can return for new_code_coverage: the three reasons a snapshot records today
// (measure.NewCodeCoverageNoReport, NoChangedLines, NotInReport), the read model's legacy_analysis, and
// measure.NewCodeCoverageLegacyUnavailable, which snapshots stored before those reasons existed still
// carry. A reason missing from the enum is one the API emits and generated clients reject.
func TestMeasureUnavailableReasonListsEveryNewCodeCoverageReason(t *testing.T) {
	b, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	reasons := stringSet(schemas["MeasureUnavailableReason"].(map[string]any)["enum"].([]any))
	for _, reason := range []string{
		"no_coverage_report",
		"no_changed_lines",
		"changed_lines_not_in_report",
		"legacy_analysis",
		"changed_line_coverage_not_available",
	} {
		if !reasons[reason] {
			t.Errorf("MeasureUnavailableReason does not list %q, which the measures API returns for new_code_coverage", reason)
		}
	}
}
