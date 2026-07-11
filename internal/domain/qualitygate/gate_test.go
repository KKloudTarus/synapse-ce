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
