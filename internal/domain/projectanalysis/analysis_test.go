package projectanalysis

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestBuildFirstAnalysisTreatsEveryIssueAsNew(t *testing.T) {
	analysis, err := Build(Input{
		ID: "a1", TenantID: "tenant", ProjectID: "project", ProjectKey: "demo", CreatedAt: time.Now(), LinesOfCode: 100,
		Findings: []finding.Finding{
			{ID: "one", DedupKey: "one", Kind: finding.KindSecret, Severity: shared.SeverityHigh, Status: finding.StatusOpen},
			{ID: "two", DedupKey: "two", Kind: finding.KindQuality, Severity: shared.SeverityLow, Status: finding.StatusOpen},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if analysis.NewCode.Counts.Total != 2 || analysis.Measures[qualitygate.MetricNewHigh] != 1 || analysis.Measures[qualitygate.MetricNewSecret] != 1 {
		t.Fatalf("new code=%+v measures=%+v", analysis.NewCode, analysis.Measures)
	}
	if analysis.Gate.Passed {
		t.Fatalf("high secret must fail default gate: %+v", analysis.Gate)
	}
	if analysis.Coverage != nil {
		t.Fatal("coverage must remain unavailable")
	}
	if analysis.Delta != nil {
		t.Fatalf("first analysis delta=%+v, want nil", analysis.Delta)
	}
}

func TestLegacyAnalysisDecode(t *testing.T) {
	data := []byte(`{"id":"legacy1","tenant_id":"tenant"}`)
	var analysis Analysis
	if err := json.Unmarshal(data, &analysis); err != nil {
		t.Fatal(err)
	}
	if len(analysis.Snapshot.Nodes) != 1 {
		t.Fatalf("expected 1 fallback root node, got %d", len(analysis.Snapshot.Nodes))
	}
	root := analysis.Snapshot.Nodes[0]
	if root.Path != "" || root.Kind != measure.NodeProject {
		t.Fatalf("expected project root node, got %+v", root)
	}
	if root.TechDebtAvailable || root.IssueTypeAvailable || root.AttributionAvailable || root.FunctionsKnown {
		t.Fatalf("legacy root must have strictly unavailable measures")
	}
	if analysis.Snapshot.NewCodeCoverage.Availability != measure.AvailabilityUnavailable {
		t.Fatalf("legacy new code coverage must be unavailable")
	}
}

func TestBuildPersistsOnlyValidBehavioralHotspots(t *testing.T) {
	report := &measure.BehavioralHotspotsReport{
		Version:      measure.BehavioralHotspotsSchemaVersion,
		Availability: measure.BehavioralUnavailable,
		Reason:       "history_unavailable",
	}
	analysis, err := Build(Input{
		ID: "a1", TenantID: "tenant", ProjectID: "project", ProjectKey: "demo", CreatedAt: time.Now(),
		BehavioralHotspots: report,
	})
	if err != nil {
		t.Fatalf("build valid analysis: %v", err)
	}
	if analysis.BehavioralHotspots == nil || analysis.BehavioralHotspots.Reason != "history_unavailable" {
		t.Fatalf("behavioral snapshot not persisted: %+v", analysis.BehavioralHotspots)
	}

	invalid := *report
	invalid.Reason = ""
	if _, err := Build(Input{
		ID: "a2", TenantID: "tenant", ProjectID: "project", ProjectKey: "demo", CreatedAt: time.Now(),
		BehavioralHotspots: &invalid,
	}); err == nil {
		t.Fatal("expected invalid behavioral snapshot to be rejected")
	}
}

type mockCatalog struct{}

func (m mockCatalog) Get(k rule.Key) (rule.Rule, error) {
	return rule.Rule{}, shared.ErrNotFound
}

func TestEmptyCurrentSnapshotNotLegacy(t *testing.T) {
	snap, err := measure.BuildSnapshot(measure.BuildSnapshotInput{
		RuleCatalog: mockCatalog{},
		Inventory:   measure.NewInventory(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Nodes) != 1 {
		t.Fatalf("expected 1 root node from empty snapshot, got %d", len(snap.Nodes))
	}
	analysis := Analysis{ID: "empty1", TenantID: "tenant", Snapshot: snap}
	b, err := json.Marshal(analysis)
	if err != nil {
		t.Fatal(err)
	}

	var decoded Analysis
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Snapshot.Nodes) != 1 {
		t.Fatalf("expected 1 root node after roundtrip, got %d", len(decoded.Snapshot.Nodes))
	}
	if decoded.Snapshot.NewCodeCoverage.Reason == "legacy_analysis" {
		t.Fatalf("empty modern snapshot incorrectly treated as legacy after roundtrip")
	}
}

func TestBuildRecordsDefaultGateInfo(t *testing.T) {
	analysis, err := Build(Input{ID: "a1", TenantID: "tenant", ProjectID: "project", ProjectKey: "demo", CreatedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if analysis.GateInfo.Key != qualitygate.DefaultKey || analysis.GateInfo.Name != "Synapse way" || analysis.GateInfo.Source != "default" {
		t.Fatalf("gate info=%+v", analysis.GateInfo)
	}
}

func TestBuildUsesProvidedGate(t *testing.T) {
	analysis, err := Build(Input{
		ID: "a1", TenantID: "tenant", ProjectID: "project", ProjectKey: "demo", CreatedAt: time.Now(),
		Gate:     qualitygate.Gate{Conditions: []qualitygate.Condition{{Metric: qualitygate.MetricNewHigh, Op: qualitygate.OpLE, Threshold: 1}}},
		Findings: []finding.Finding{{ID: "one", DedupKey: "one", Kind: finding.KindSCA, Severity: shared.SeverityHigh, Status: finding.StatusOpen}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !analysis.Gate.Passed || len(analysis.Gate.Results) != 1 {
		t.Fatalf("provided gate was not evaluated: %+v", analysis.Gate)
	}
}

func TestBuildLeavesNewCodeMaintainabilityUnavailableWithoutDiffLines(t *testing.T) {
	base, err := Build(Input{ID: "a1", TenantID: "tenant", ProjectID: "project", ProjectKey: "demo", CreatedAt: time.Now(), LinesOfCode: 100})
	if err != nil {
		t.Fatal(err)
	}
	current, err := Build(Input{
		ID: "a2", TenantID: "tenant", ProjectID: "project", ProjectKey: "demo", CreatedAt: time.Now(), LinesOfCode: 10100, Previous: &base,
		Findings: []finding.Finding{{ID: "quality", DedupKey: "quality", Kind: finding.KindQuality, Severity: shared.SeverityHigh, Status: finding.StatusOpen}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if current.NewCode.Rating.Maintainability != nil || current.NewCode.Rating.Security != "A" || current.NewCode.Rating.Reliability != "A" {
		t.Fatalf("new code=%+v", current.NewCode)
	}
}

func TestBuildUsesIdentityDifferenceNotAggregateDifference(t *testing.T) {
	previous, err := Build(Input{
		ID: "a1", TenantID: "tenant", ProjectID: "project", ProjectKey: "demo", CreatedAt: time.Now(), LinesOfCode: 100,
		Findings: []finding.Finding{{ID: "old", DedupKey: "old", Kind: finding.KindSCA, Severity: shared.SeverityLow, Status: finding.StatusOpen}},
	})
	if err != nil {
		t.Fatal(err)
	}
	current, err := Build(Input{
		ID: "a2", TenantID: "tenant", ProjectID: "project", ProjectKey: "demo", CreatedAt: time.Now(), LinesOfCode: 100, Previous: &previous,
		Findings: []finding.Finding{{ID: "replacement", DedupKey: "replacement", Kind: finding.KindSCA, Severity: shared.SeverityHigh, Status: finding.StatusOpen}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if current.Delta == nil || current.Issues.Total != 1 || current.NewCode.Counts.Total != 1 || current.Delta.Issues.Total != 0 {
		t.Fatalf("current=%+v new=%+v delta=%+v", current.Issues, current.NewCode.Counts, current.Delta)
	}
	if current.NewCode.PreviousID != "a1" || current.Measures[qualitygate.MetricNewHigh] != 1 {
		t.Fatalf("new code=%+v measures=%+v", current.NewCode, current.Measures)
	}
}

func TestBuildPersistsSignedComplexityDeltaWithBaseline(t *testing.T) {
	coverage := measure.ComplexityCoverageSummary{Version: measure.ComplexitySchemaVersion, EligibleFiles: 1, MeasuredFiles: 1, Availability: measure.AvailabilityAvailable}
	previous := Analysis{
		ID: "a1", SourceRef: "main", CreatedAt: time.Unix(1, 0).UTC(),
		Snapshot: measure.Snapshot{Nodes: []measure.Node{
			{Path: "", Kind: measure.NodeProject, ComplexityAvailable: true, ComplexityCoverage: coverage, Counters: measure.Counters{Cyclomatic: 10, Cognitive: 8}},
			{Path: "src/a.go", Kind: measure.NodeFile, ComplexityAvailable: true, ComplexityCoverage: coverage, Counters: measure.Counters{Cyclomatic: 10, Cognitive: 8}},
		}},
	}
	current, err := Build(Input{
		ID: "a2", TenantID: "tenant", ProjectID: "project", ProjectKey: "demo", CreatedAt: time.Unix(2, 0).UTC(),
		SourceRef: "main", Previous: &previous, ComplexityBaseline: &previous,
		Snapshot: measure.Snapshot{Nodes: []measure.Node{
			{Path: "", Kind: measure.NodeProject, ComplexityAvailable: true, ComplexityCoverage: coverage, Counters: measure.Counters{Cyclomatic: 7, Cognitive: 11}},
			{Path: "src/a.go", Kind: measure.NodeFile, ComplexityAvailable: true, ComplexityCoverage: coverage, Counters: measure.Counters{Cyclomatic: 7, Cognitive: 11}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if current.Delta == nil || current.Delta.Complexity == nil {
		t.Fatalf("complexity delta missing: %+v", current.Delta)
	}
	delta := current.Delta.Complexity.Nodes["src/a.go"]
	if delta.Availability != measure.AvailabilityAvailable || delta.Cyclomatic != -3 || delta.Cognitive != 3 {
		t.Fatalf("signed file delta = %+v", delta)
	}
	if current.Delta.Complexity.BaselineAnalysisID != "a1" || current.Delta.Complexity.BaselineSourceRef != "main" {
		t.Fatalf("baseline metadata = %+v", current.Delta.Complexity)
	}
	encoded, err := json.Marshal(current.Delta)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip Delta
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if got := roundTrip.Complexity.Nodes["src/a.go"].Cyclomatic; got != -3 {
		t.Fatalf("JSON round-trip clamped signed delta to %d", got)
	}
}

func TestBuildMarksComplexityTrendUnavailableForUnknownBranch(t *testing.T) {
	previous := Analysis{ID: "a1", SourceRef: "main"}
	current, err := Build(Input{
		ID: "a2", TenantID: "tenant", ProjectID: "project", ProjectKey: "demo", CreatedAt: time.Now(),
		Previous: &previous, ComplexityBaselineReason: "unknown_branch",
	})
	if err != nil {
		t.Fatal(err)
	}
	if current.Delta == nil || current.Delta.Complexity == nil || current.Delta.Complexity.Reason != "unknown_branch" {
		t.Fatalf("unknown-branch complexity delta = %+v", current.Delta)
	}
}

func TestBuildDetectsMaterialNewCodeAndUsesEligibleOverallGate(t *testing.T) {
	base := func(issue finding.Finding) Analysis {
		analysis, err := Build(Input{ID: "a1", TenantID: "tenant", ProjectID: "project", ProjectKey: "demo", CreatedAt: time.Now(), LinesOfCode: 100, Findings: []finding.Finding{issue}})
		if err != nil {
			t.Fatal(err)
		}
		return analysis
	}
	cases := []struct {
		name     string
		previous finding.Finding
		current  finding.Finding
		wantNew  bool
	}{
		{"severity escalation", finding.Finding{ID: "one", DedupKey: " key ", Kind: finding.KindSCA, Severity: shared.SeverityLow, Status: finding.StatusOpen}, finding.Finding{ID: "one", DedupKey: "key", Kind: finding.KindSCA, Severity: shared.SeverityHigh, Status: finding.StatusOpen}, true},
		{"kind change", finding.Finding{ID: "one", DedupKey: "key", Kind: finding.KindSCA, Severity: shared.SeverityLow, Status: finding.StatusOpen}, finding.Finding{ID: "one", DedupKey: "key", Kind: finding.KindReliability, Severity: shared.SeverityLow, Status: finding.StatusOpen}, true},
		{"false positive reactivated", finding.Finding{ID: "one", DedupKey: "key", Kind: finding.KindSCA, Severity: shared.SeverityLow, Status: finding.StatusFalsePos}, finding.Finding{ID: "one", DedupKey: "key", Kind: finding.KindSCA, Severity: shared.SeverityLow, Status: finding.StatusOpen}, true},
		{"remediated reactivated", finding.Finding{ID: "one", DedupKey: "key", Kind: finding.KindSCA, Severity: shared.SeverityLow, Status: finding.StatusRemediated}, finding.Finding{ID: "one", DedupKey: "key", Kind: finding.KindSCA, Severity: shared.SeverityLow, Status: finding.StatusOpen}, true},
		{"ordinary workflow", finding.Finding{ID: "one", DedupKey: "key", Kind: finding.KindSCA, Severity: shared.SeverityLow, Status: finding.StatusOpen}, finding.Finding{ID: "one", DedupKey: "key", Kind: finding.KindSCA, Severity: shared.SeverityLow, Status: finding.StatusConfirmed}, false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			previous := base(tt.previous)
			current, err := Build(Input{ID: "a2", TenantID: "tenant", ProjectID: "project", ProjectKey: "demo", CreatedAt: time.Now(), LinesOfCode: 100, Previous: &previous, Findings: []finding.Finding{tt.current}})
			if err != nil {
				t.Fatal(err)
			}
			if got := current.NewCode.Counts.Total == 1; got != tt.wantNew {
				t.Fatalf("new=%v, want %v", got, tt.wantNew)
			}
		})
	}

	previous := base(finding.Finding{ID: "old", DedupKey: "old", Kind: finding.KindSCA, Severity: shared.SeverityHigh, Status: finding.StatusOpen})
	current, err := Build(Input{ID: "a2", TenantID: "tenant", ProjectID: "project", ProjectKey: "demo", CreatedAt: time.Now(), LinesOfCode: 100, Previous: &previous, Findings: []finding.Finding{{ID: "old", DedupKey: "old", Kind: finding.KindSCA, Severity: shared.SeverityHigh, Status: finding.StatusOpen}}})
	if err != nil {
		t.Fatal(err)
	}
	if current.Gate.Passed || current.Measures[qualitygate.MetricSecurityRating] != 4 {
		t.Fatalf("old high must fail overall gate: %+v", current)
	}

	exempt, err := Build(Input{ID: "a3", TenantID: "tenant", ProjectID: "project", ProjectKey: "demo", CreatedAt: time.Now(), LinesOfCode: 100, GateExempt: map[string]bool{"old": true}, Findings: []finding.Finding{{ID: "old", DedupKey: "old", Kind: finding.KindSCA, Severity: shared.SeverityHigh, Status: finding.StatusFalsePos}}})
	if err != nil {
		t.Fatal(err)
	}
	if exempt.Issues.Total != 1 || !exempt.Gate.Passed {
		t.Fatalf("exempt issue must remain visible and pass gate: %+v", exempt)
	}

	nonPublishable, err := Build(Input{ID: "a4", TenantID: "tenant", ProjectID: "project", ProjectKey: "demo", CreatedAt: time.Now(), Findings: []finding.Finding{{ID: "claim", DedupKey: "claim", Kind: finding.KindExploitation, EvidenceScore: finding.EvidenceThreshold - 1}}})
	if err != nil {
		t.Fatal(err)
	}
	if nonPublishable.Issues.Total != 0 {
		t.Fatalf("non-publishable issue leaked into snapshot: %+v", nonPublishable)
	}
}

func TestBuildDeduplicatesRootAndCodeQualityFinding(t *testing.T) {
	analysis, err := Build(Input{
		ID: "a1", TenantID: "tenant", ProjectID: "project", ProjectKey: "demo", CreatedAt: time.Now(), LinesOfCode: 100,
		Findings: []finding.Finding{
			{ID: "one", DedupKey: "same", Kind: finding.KindSAST, Severity: shared.SeverityCritical, Status: finding.StatusOpen},
			{ID: "two", DedupKey: "same", Kind: finding.KindSAST, Severity: shared.SeverityCritical, Status: finding.StatusOpen},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if analysis.Issues.Total != 1 || len(analysis.InternalIssues) != 1 || analysis.Measures[qualitygate.MetricNewCritical] != 1 {
		t.Fatalf("analysis=%+v", analysis)
	}
}
