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
	// A custom gate using the new-code metrics validates. On a snapshot that measured neither, BOTH
	// conditions fail closed and are marked unmeasured — including `new_duplication <= 3`, which used
	// to pass at a 0 nobody had computed.
	g := Gate{Key: "clean-as-you-code", Name: "Clean as You Code", Conditions: []Condition{
		{Metric: MetricNewCoverage, Op: OpGE, Threshold: 80},
		{Metric: MetricNewDuplication, Op: OpLE, Threshold: 3},
	}}
	if _, err := g.Normalize(); err != nil {
		t.Fatalf("custom gate with new-code metrics must validate: %v", err)
	}
	res := Evaluate(g, Snapshot{})
	if res.Passed || len(res.Failures()) != 2 {
		t.Fatalf("both unmeasured new-code conditions must fail closed; passed=%v failures=%+v", res.Passed, res.Failures())
	}
	for _, f := range res.Failures() {
		if !f.Unmeasured {
			t.Errorf("%s failed but was not marked unmeasured: %+v", f.Condition, f)
		}
	}
	// Once measured, the same conditions are judged on the value.
	res = Evaluate(g, Snapshot{MetricNewCoverage: 85, MetricNewDuplication: 2.5})
	if !res.Passed {
		t.Errorf("measured values within threshold must pass: %+v", res.Failures())
	}
	for _, r := range res.Results {
		if r.Unmeasured {
			t.Errorf("a measured condition must not be marked unmeasured: %+v", r)
		}
	}
}

// TestMissingMeasurementFailsClosed pins the counter/measurement split. A counter such as new_high absent
// from the snapshot is a genuine 0 (TestMissingMetricIsZero); coverage, new_coverage and new_duplication
// absent are "no data", and no operator turns "no data" into a pass — not `<=`, which is the one that
// used to.
func TestMissingMeasurementFailsClosed(t *testing.T) {
	for _, metric := range []string{MetricCoveragePct, MetricNewCoverage, MetricNewDuplication} {
		for _, op := range []Op{OpLE, OpGE, OpLT, OpGT, OpEQ} {
			t.Run(metric+" "+string(op), func(t *testing.T) {
				g := Gate{Conditions: []Condition{{Metric: metric, Op: op, Threshold: 0}}}
				res := Evaluate(g, Snapshot{})
				if res.Passed {
					t.Fatalf("unmeasured %s %s 0 must fail closed", metric, op)
				}
				if len(res.Results) != 1 || !res.Results[0].Unmeasured || res.Results[0].Actual != 0 {
					t.Fatalf("result must be unmeasured with no value: %+v", res.Results)
				}
				// A measured zero is a value, and is judged as one.
				measured := Evaluate(g, Snapshot{metric: 0})
				if measured.Results[0].Unmeasured {
					t.Fatalf("a measured 0 must not read as unmeasured: %+v", measured.Results[0])
				}
			})
		}
	}
	if !RequiresMeasurement(MetricNewDuplication) || RequiresMeasurement(MetricNewHigh) {
		t.Error("RequiresMeasurement must cover the measurement metrics and not the counters")
	}
}
