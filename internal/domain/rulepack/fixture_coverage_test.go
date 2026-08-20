package rulepack

import "testing"

func TestValidationRequiresPositiveFixtureCoverageForEveryRule(t *testing.T) {
	spec := testSpec()
	second := spec.Rules[0]
	second.ID = "det.second"
	second.Title = "second test rule"
	spec.Rules = append(spec.Rules, second)
	spec.ExpectedCost = append(spec.ExpectedCost, RuleCostBudget{
		RuleID:                 second.ID,
		MaxLatencyMicros:       100,
		MaxCPUMicrosPerHostDay: 1000,
	})

	if _, err := New(spec); err == nil {
		t.Fatal("rule without positive replay fixture must be rejected")
	}
}
