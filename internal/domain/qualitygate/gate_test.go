package qualitygate

import "testing"

func TestEvaluatePassFail(t *testing.T) {
	g := Gate{Conditions: []Condition{
		{Metric: "new_critical", Op: OpLE, Threshold: 0},
		{Metric: "coverage", Op: OpGE, Threshold: 80},
	}}
	// pass: 0 new criticals, 90 coverage
	if r := Evaluate(g, Snapshot{"new_critical": 0, "coverage": 90}); !r.Passed {
		t.Errorf("should pass, got failures %+v", r.Failures())
	}
	// fail: 2 new criticals, 70 coverage -> both fail
	r := Evaluate(g, Snapshot{"new_critical": 2, "coverage": 70})
	if r.Passed || len(r.Failures()) != 2 {
		t.Errorf("should fail both conditions, got passed=%v failures=%d", r.Passed, len(r.Failures()))
	}
}

func TestMissingMetricIsZero(t *testing.T) {
	g := Gate{Conditions: []Condition{{Metric: "new_high", Op: OpLE, Threshold: 0}}}
	if r := Evaluate(g, Snapshot{}); !r.Passed {
		t.Errorf("absent metric reads as 0, should pass <=0")
	}
}

func TestUnknownOpFailsClosed(t *testing.T) {
	g := Gate{Conditions: []Condition{{Metric: "x", Op: Op("~="), Threshold: 0}}}
	if Evaluate(g, Snapshot{"x": 0}).Passed {
		t.Error("unknown operator must fail closed")
	}
}

func TestDefaultGate(t *testing.T) {
	g := Default()
	if len(g.Conditions) == 0 {
		t.Fatal("default gate must have conditions")
	}
	// A clean snapshot (all A ratings, no new issues) passes the default gate.
	clean := Snapshot{"security_rating": 1, "reliability_rating": 1}
	if !Evaluate(g, clean).Passed {
		t.Errorf("clean snapshot should pass the default gate, failures %+v", Evaluate(g, clean).Failures())
	}
	// A new critical fails it.
	if Evaluate(g, Snapshot{"new_critical": 1, "security_rating": 1, "reliability_rating": 1}).Passed {
		t.Error("a new critical must fail the default gate")
	}
}

func TestValidMetricAcceptsNewCodeCoverageAndDuplication(t *testing.T) {
	for _, m := range []string{MetricNewCoverage, MetricNewDuplication, MetricSecurityHotspotsReviewed} {
		if !ValidMetric(m) {
			t.Errorf("metric %q must be a valid gate condition metric", m)
		}
	}
	if ValidMetric("not_a_metric") {
		t.Error("an unknown metric must be rejected")
	}
	// A custom gate using the new-code metrics validates, and — since neither is measured yet — a
	// `new_coverage >= 80` condition reads 0 and fails closed while `new_duplication <= 3` passes at 0.
	g := Gate{Key: "clean-as-you-code", Name: "Clean as You Code", Conditions: []Condition{
		{Metric: MetricNewCoverage, Op: OpGE, Threshold: 80},
		{Metric: MetricNewDuplication, Op: OpLE, Threshold: 3},
	}}
	if _, err := g.Normalize(); err != nil {
		t.Fatalf("custom gate with new-code metrics must validate: %v", err)
	}
	res := Evaluate(g, Snapshot{})
	if res.Passed {
		t.Error("an unmeasured new_coverage>=80 must fail closed on an empty snapshot")
	}
	if len(res.Failures()) != 1 || res.Failures()[0].Condition.Metric != MetricNewCoverage {
		t.Errorf("only new_coverage should fail closed at 0; failures=%+v", res.Failures())
	}
}
