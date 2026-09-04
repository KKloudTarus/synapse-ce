package assessmentrollout

import "testing"

func TestEvaluateReadCutoverRequiresProductionSLOGate(t *testing.T) {
	snapshot := passingSnapshot()
	snapshot.CycleListP95Millis = 600
	decision, err := Evaluate(PhaseReadCutover, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed || !hasFinding(decision.Blockers, "production_latency_slo") {
		t.Fatalf("safety ceiling must not authorize cutover: %+v", decision)
	}
	snapshot.CycleListP95Millis = 500
	decision, err = Evaluate(PhaseReadCutover, snapshot)
	if err != nil || !decision.Allowed {
		t.Fatalf("expected cutover approval, decision=%+v err=%v", decision, err)
	}
}

func TestEvaluateCanaryAndRollbackAbortConditions(t *testing.T) {
	snapshot := passingSnapshot()
	snapshot.IntegrityViolations = 1
	snapshot.ComparisonBacklog = 1001
	snapshot.DeadLetterGrowth10Minutes = 1
	decision, err := Evaluate(PhaseInternalCanary, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"integrity_violation", "comparison_backlog_hard_limit", "dead_letter_growth"} {
		if !hasFinding(decision.Blockers, code) {
			t.Fatalf("missing blocker %s in %+v", code, decision)
		}
	}
	rollback := passingSnapshot()
	rollback.LifecycleReadEnabled = false
	rollback.LifecycleUIDefaultEnabled = false
	rollback.SourceRowsPreserved = true
	rollback.ImmutableArtifactsPreserved = true
	rollback.RollbackDrillPassed = true
	decision, err = Evaluate(PhaseRollbackDrill, rollback)
	if err != nil || !decision.Allowed {
		t.Fatalf("expected rollback drill approval, decision=%+v err=%v", decision, err)
	}
}

func passingSnapshot() Snapshot {
	return Snapshot{
		TenantID: "tenant-a", ComparableItems: 1000, ProducerItems: 1000, APIRequests: 1000,
		APIWindowMinutes: 15, LatencyWindowMinutes: 15, CycleListP95Millis: 500, CycleDetailP95Millis: 750,
		ComparisonPageP95Millis: 750, ProductionSLOContinuousMinutes: 30, TargetCardinality: true,
		Comparison100KDurationSeconds: 300, MetricsRecorded: true, ApprovalRecorded: true, ReadCutoverApproved: true,
	}
}

func hasFinding(findings []Finding, code string) bool {
	for _, finding := range findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}
