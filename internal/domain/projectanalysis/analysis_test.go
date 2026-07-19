package projectanalysis

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
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

func TestEmptyCurrentSnapshotNotLegacy(t *testing.T) {
	data := []byte(`{"id":"empty1","tenant_id":"tenant","snapshot":{"nodes":[]}}`)
	var analysis Analysis
	if err := json.Unmarshal(data, &analysis); err != nil {
		t.Fatal(err)
	}
	if len(analysis.Snapshot.Nodes) != 0 {
		t.Fatalf("expected 0 nodes from explicit empty snapshot, got %d", len(analysis.Snapshot.Nodes))
	}
	if analysis.Snapshot.NewCodeCoverage.Reason == "legacy_analysis" {
		t.Fatalf("empty modern snapshot incorrectly treated as legacy")
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
