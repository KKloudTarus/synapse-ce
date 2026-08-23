package rulepack

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/purplecoverage"
	rulepackdomain "github.com/KKloudTarus/synapse-ce/internal/domain/rulepack"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func gatePack(t *testing.T) rulepackdomain.RulePack {
	t.Helper()
	now := time.Unix(1_700_000_000, 0).UTC()
	rule := detection.Rule{
		ID: "det.test", Version: 2, Class: detection.ClassProcess, Title: "test", Severity: shared.SeverityHigh,
		Matcher: detection.Matcher{Class: detection.ClassProcess, All: []detection.Predicate{
			{Field: detection.FieldProcArg, Op: detection.OpContains, Value: "--danger"},
			{Field: detection.FieldProcComm, Op: detection.OpEquals, Value: "tool"},
		}},
	}
	positive := detection.Event{Class: detection.ClassProcess, At: now, Host: "h1", Process: &detection.ProcessEvent{Comm: "tool", Args: []string{"run", "--danger"}}}
	negative := detection.Event{Class: detection.ClassProcess, At: now, Host: "h1", Process: &detection.ProcessEvent{Comm: "tool", Args: []string{"run", "--safe"}}}
	p, err := rulepackdomain.New(rulepackdomain.RulePack{
		ID: "runtime-core", Version: 3, Rules: []detection.Rule{rule}, MinAgentVersion: "1.2.0",
		RequiredSchemaVersions: []int{1},
		RequiredSensors:        []rulepackdomain.SensorRequirement{{ID: "ebpf", MinVersion: "2.0.0"}},
		RequiredFields:         []detection.Field{detection.FieldProcArg, detection.FieldProcComm},
		ATTACKMappings:         []rulepackdomain.ATTACKMapping{{RuleID: "det.test", TechniqueID: "T1059"}},
		PositiveFixtures:       []rulepackdomain.Fixture{{ID: "positive", Event: positive, ExpectedRuleIDs: []string{"det.test"}}},
		NegativeFixtures:       []rulepackdomain.Fixture{{ID: "negative", Event: negative}},
		ExpectedCost:           []rulepackdomain.RuleCostBudget{{RuleID: "det.test", MaxLatencyMicros: 100, MaxCPUMicrosPerHostDay: 1000}},
		SuppressionPolicy:      rulepackdomain.SuppressionPolicy{MaxSuppressionRateBPS: 500},
		RolloutCohort:          []string{"canary-a"}, RollbackVersion: 2,
	})
	if err != nil {
		t.Fatalf("New rulepack: %v", err)
	}
	return *p
}

func gateDeployment(p rulepackdomain.RulePack, state rulepackdomain.DeploymentState) rulepackdomain.RulePackDeployment {
	return rulepackdomain.RulePackDeployment{
		PackID: p.ID, PackVersion: p.Version, PackDigest: p.Digest,
		AgentVersion: "1.2.1", SchemaVersion: 1,
		Sensors:         []rulepackdomain.SensorRequirement{{ID: "ebpf", MinVersion: "2.1.0"}},
		AvailableFields: []detection.Field{detection.FieldProcArg, detection.FieldProcComm},
		Cohort:          "canary-a", State: state, PreviousVersion: 2,
	}
}

func gatePolicy() GatePolicy {
	return GatePolicy{
		MinimumPrecisionBPS: 9500, MaximumFalsePositiveRateBPS: 500,
		MinimumAnalystDispositionRateBPS: 9000, MinimumRequiredFieldAvailabilityBPS: 10_000,
		MinimumATTACKCoverageBPS: 10_000, MaximumCanaryDetectionsPerHostDayMilli: 20_000,
		MaximumProdDetectionsPerHostDayMilli: 20_000, MinimumReviewedDetections: 50, MinimumHostDays: 5,
	}
}

func goodSample() QualitySample {
	return QualitySample{
		Detections: 100, TruePositives: 98, FalsePositives: 2, SuppressedDetections: 1, HostDays: 10,
		AvailableFields: []detection.Field{detection.FieldProcArg, detection.FieldProcComm},
	}
}

func goodGateInput(p rulepackdomain.RulePack) GateInput {
	canary, prod := goodSample(), goodSample()
	return GateInput{
		Deployment: gateDeployment(p, rulepackdomain.DeploymentCanary),
		Policy:     gatePolicy(),
		Costs:      []RuleCostObservation{{RuleID: "det.test", LatencyMicros: 50, CPUMicrosPerHostDay: 500}},
		Retro:      []RetroEvidence{{RuleID: "det.test", ContextEvents: 4, MatchedEvents: 1, Complete: true}},
		Purple: []purplecoverage.Coverage{{
			TenantID: "t1", EngagementID: "e1", RunID: "run1", AssetID: "asset1", TechniqueID: "emu.test",
			TaxonomyRef: "T1059", Expected: "det.test", Actual: []string{"det.test"}, Verdict: purplecoverage.VerdictCovered, ComputedAt: time.Unix(1, 0).UTC(),
		}},
		Evaluation: goodSample(), Canary: &canary, Production: &prod,
	}
}

func TestEvaluatePassesInFixedReleaseOrder(t *testing.T) {
	p := gatePack(t)
	report, err := Evaluate(p, goodGateInput(p))
	if err != nil {
		t.Fatal(err)
	}
	if !report.PreCanaryPassed || !report.CanaryPassed || !report.Passed {
		t.Fatalf("report did not pass: %+v", report)
	}
	want := []Stage{StageCompatibility, StagePositiveReplay, StageNegativeReplay, StagePerformance, StageRetroHunt, StageEmulation, StageFPBudget, StageCanary, StageProduction}
	if len(report.Stages) != len(want) {
		t.Fatalf("stages = %d", len(report.Stages))
	}
	for i := range want {
		if report.Stages[i].Stage != want[i] || !report.Stages[i].Pass {
			t.Fatalf("stage[%d] = %+v, want %s pass", i, report.Stages[i], want[i])
		}
	}
	if report.ATTACKCoverageBPS != 10_000 || report.EvaluationMetrics.PrecisionBPS != 9800 || report.CanaryMetrics == nil || report.CanaryMetrics.RequiredFieldAvailabilityBPS != 10_000 {
		t.Fatalf("metrics = %+v", report)
	}
	promoted, err := Advance(p, gateDeployment(p, rulepackdomain.DeploymentCanary), goodGateInput(p), rulepackdomain.DeploymentPromoted)
	if err != nil || promoted.State != rulepackdomain.DeploymentPromoted {
		t.Fatalf("promotion = %+v, %v", promoted, err)
	}
}

func TestEvaluatePartialReportAdmitsCanaryButNotPromotion(t *testing.T) {
	p := gatePack(t)
	in := goodGateInput(p)
	in.Canary, in.Production = nil, nil
	in.Deployment = gateDeployment(p, rulepackdomain.DeploymentCandidate)
	report, err := Evaluate(p, in)
	if err != nil {
		t.Fatal(err)
	}
	if !report.PreCanaryPassed || report.CanaryPassed || report.Passed {
		t.Fatalf("partial report flags = pre=%t canary=%t passed=%t", report.PreCanaryPassed, report.CanaryPassed, report.Passed)
	}
	canary, err := Advance(p, in.Deployment, in, rulepackdomain.DeploymentCanary)
	if err != nil || canary.State != rulepackdomain.DeploymentCanary {
		t.Fatalf("candidate should be admitted to canary: %+v %v", canary, err)
	}
	if _, err := Advance(p, canary, in, rulepackdomain.DeploymentPromoted); err == nil {
		t.Fatal("partial report must not promote")
	}
}

func TestAdvanceRecomputesEvidenceAgainstActualDeployment(t *testing.T) {
	p := gatePack(t)
	in := goodGateInput(p)
	in.Canary, in.Production = nil, nil
	in.Deployment = gateDeployment(p, rulepackdomain.DeploymentCandidate)

	actual := gateDeployment(p, rulepackdomain.DeploymentCandidate)
	actual.AvailableFields = []detection.Field{detection.FieldProcComm}
	if _, err := Advance(p, actual, in, rulepackdomain.DeploymentCanary); err == nil {
		t.Fatal("advance must evaluate the actual deployment, not the deployment claimed by gate input")
	}
}

func TestFailedProductionQualityCannotPromoteButCannotBlockRollback(t *testing.T) {
	p := gatePack(t)
	in := goodGateInput(p)
	bad := goodSample()
	bad.TruePositives, bad.FalsePositives = 50, 50
	in.Production = &bad
	report, err := Evaluate(p, in)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatal("bad production precision must fail")
	}
	if _, err := Advance(p, in.Deployment, in, rulepackdomain.DeploymentPromoted); err == nil {
		t.Fatal("failed report must not promote")
	}
	rolled, err := Advance(p, in.Deployment, GateInput{}, rulepackdomain.DeploymentRolledBack)
	if err != nil || rolled.State != rulepackdomain.DeploymentRolledBack {
		t.Fatalf("failed metrics must not block rollback: %+v %v", rolled, err)
	}
}

func TestPerformanceAndRetroEvidenceFailClosed(t *testing.T) {
	p := gatePack(t)
	in := goodGateInput(p)
	in.Costs[0].LatencyMicros = 101
	in.Retro[0].Complete = false
	report, err := Evaluate(p, in)
	if err != nil {
		t.Fatal(err)
	}
	if report.PreCanaryPassed || report.Stages[3].Pass || report.Stages[4].Pass {
		t.Fatalf("perf/retro failures were not enforced: %+v", report.Stages)
	}
}

func TestEvaluateRejectsUnprovenCoveredPurpleEvidence(t *testing.T) {
	p := gatePack(t)
	in := goodGateInput(p)
	in.Purple[0].Actual = nil
	if _, err := Evaluate(p, in); err == nil {
		t.Fatal("covered purple evidence without the expected actual detection must fail")
	}
}

func TestEvaluateRejectsPurpleEvidenceMixedScope(t *testing.T) {
	p := gatePack(t)
	in := goodGateInput(p)
	other := in.Purple[0]
	other.AssetID = "asset2"
	in.Purple = append(in.Purple, other)
	if _, err := Evaluate(p, in); err == nil {
		t.Fatal("purple evidence from multiple assets must fail")
	}
}

type fakeHunter struct {
	result ports.HuntResult
	query  ports.HuntQuery
}

func (f *fakeHunter) Hunt(_ context.Context, q ports.HuntQuery) (ports.HuntResult, error) {
	f.query = q
	return f.result, nil
}

func TestCollectRetroEvidenceRunsCandidateRuleOverHuntWindow(t *testing.T) {
	p := gatePack(t)
	now := time.Unix(10, 0).UTC()
	event := detection.Event{Class: detection.ClassProcess, At: now, Host: "h1", Process: &detection.ProcessEvent{Comm: "tool", Args: []string{"run", "--danger"}}}
	hunter := &fakeHunter{result: ports.HuntResult{Events: []detection.Event{event}, Complete: true}}
	out, err := CollectRetroEvidence(context.Background(), p, hunter, []RetroCase{{
		RuleID: "det.test", Query: ports.HuntQuery{HostID: "h1", Class: detection.ClassProcess, Since: now.Add(-time.Minute), Until: now.Add(time.Minute), Limit: 100},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].MatchedEvents != 1 || out[0].ContextEvents != 1 || hunter.query.Kind != ports.HuntRetroRule {
		t.Fatalf("retro evidence = %+v query=%+v", out, hunter.query)
	}
}

type fakePurpleReader struct{ rows []purplecoverage.Coverage }

func (f fakePurpleReader) Trend(context.Context, shared.ID) ([]purplecoverage.Coverage, error) {
	return f.rows, nil
}

func TestCollectPurpleEvidenceBindsExactRun(t *testing.T) {
	row := purplecoverage.Coverage{TenantID: "t1", EngagementID: "e1", RunID: "run1", AssetID: "asset1", TechniqueID: "emu.test", TaxonomyRef: "T1059", Expected: "det.test", Actual: []string{"det.test"}, Verdict: purplecoverage.VerdictCovered, ComputedAt: time.Unix(1, 0).UTC()}
	other := row
	other.RunID = "run2"
	out, err := CollectPurpleEvidence(context.Background(), fakePurpleReader{rows: []purplecoverage.Coverage{other, row}}, PurpleRequest{EngagementID: "e1", RunID: "run1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].RunID != "run1" {
		t.Fatalf("purple evidence = %+v", out)
	}
}

func TestCollectPurpleEvidenceRejectsMismatchedEngagement(t *testing.T) {
	row := purplecoverage.Coverage{TenantID: "t1", EngagementID: "e2", RunID: "run1", AssetID: "asset1", TechniqueID: "emu.test", TaxonomyRef: "T1059", Expected: "det.test", Actual: []string{"det.test"}, Verdict: purplecoverage.VerdictCovered, ComputedAt: time.Unix(1, 0).UTC()}
	if _, err := CollectPurpleEvidence(context.Background(), fakePurpleReader{rows: []purplecoverage.Coverage{row}}, PurpleRequest{EngagementID: "e1", RunID: "run1"}); err == nil {
		t.Fatal("purple collector must reject a row from another engagement")
	}
}
