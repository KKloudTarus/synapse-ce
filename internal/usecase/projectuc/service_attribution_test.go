package projectuc

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/codequality"
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

func TestRecordProjectAnalysisIssueAttribution(t *testing.T) {
	ctx := context.Background()
	projects := memory.NewProjectRepository()
	engagements := memory.NewEngagementRepository()
	analyses := memory.NewProjectAnalysisStore()
	svc := NewService(projects, engagements, fixedClock{}, fixedIDs{}, &captureAudit{}, true)
	svc.SetAnalysisStore(analyses)
	svc.SetRuleCatalog(projectRuleCatalog{rules: map[rule.Key]rule.Rule{
		"code-smell": {Key: "code-smell", Type: rule.TypeCodeSmell, Qualities: []rule.Quality{rule.QualityMaintainability}, RemediationEffort: 5},
	}})

	p, err := svc.Create(ctx, CreateInput{TenantID: "tenant", CreatedBy: "alice", Name: "Project", Key: "project", SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}})
	if err != nil {
		t.Fatal(err)
	}
	e, err := engagements.GetByProjectID(ctx, p.TenantID, p.ID)
	if err != nil {
		t.Fatal(err)
	}

	result := &scauc.ScanResult{
		CodeQuality: &codequality.Report{
			Inventory: measure.Inventory{
				Files: []measure.FileInventory{
					{Path: "src/main.go", Language: "go", CodeLines: 100},
				},
			},
			Findings: []finding.Finding{
				// Issue 1 in src/main.go
				{ID: "q1", DedupKey: "quality:code-smell:src/main.go:10", RuleKey: "code-smell", Kind: finding.KindQuality, Severity: shared.SeverityMedium, Status: finding.StatusOpen},
				// Issue 2 in src/main.go
				{ID: "q2", DedupKey: "quality:code-smell:src/main.go:20", RuleKey: "code-smell", Kind: finding.KindQuality, Severity: shared.SeverityMedium, Status: finding.StatusOpen},
				// Issue 3 malformed path fallback to root
				{ID: "q3", DedupKey: "quality:code-smell:unknown.go:10", RuleKey: "code-smell", Kind: finding.KindQuality, Severity: shared.SeverityMedium, Status: finding.StatusOpen},
			},
		},
	}

	if err := svc.RecordProjectAnalysis(ctx, e.ID, "job-1", time.Unix(1, 0), result); err != nil {
		t.Fatal(err)
	}

	list, _, err := analyses.List(ctx, p.TenantID, p.ID, "", 1, time.Time{}, "")
	if err != nil || len(list) != 1 {
		t.Fatalf("analysis=%+v err=%v", list, err)
	}
	analysis := list[0]
	snapshot := analysis.Snapshot

	if len(snapshot.Nodes) != 3 {
		t.Fatalf("expected 3 nodes (root, src, src/main.go), got %d", len(snapshot.Nodes))
	}

	var root, src, file *measure.Node
	for i := range snapshot.Nodes {
		n := &snapshot.Nodes[i]
		if n.Path == "" {
			root = n
		} else if n.Path == "src" {
			src = n
		} else if n.Path == "src/main.go" {
			file = n
		}
	}

	// 1. Root level rolls up all 3 issues (3 * 5 = 15 mins)
	if root.Counters.IssuesByType[string(rule.TypeCodeSmell)] != 3 {
		t.Errorf("root issues by type = %d, want 3", root.Counters.IssuesByType[string(rule.TypeCodeSmell)])
	}
	if root.Counters.RemediationEffortMinutes != 15 {
		t.Errorf("root remediation = %d, want 15", root.Counters.RemediationEffortMinutes)
	}
	// Root should have AttributionAvailable = false because one issue lacked a valid inventory path
	if root.AttributionAvailable {
		t.Errorf("root AttributionAvailable should be false")
	}

	// 2. Directory level rolls up 2 issues from file (2 * 5 = 10 mins)
	if src.Counters.IssuesByType[string(rule.TypeCodeSmell)] != 2 {
		t.Errorf("src issues by type = %d, want 2", src.Counters.IssuesByType[string(rule.TypeCodeSmell)])
	}
	if src.Counters.RemediationEffortMinutes != 10 {
		t.Errorf("src remediation = %d, want 10", src.Counters.RemediationEffortMinutes)
	}
	// Note: snapshot logic propagates AttributionAvailable=false to ALL nodes if one fails.
	if src.AttributionAvailable {
		t.Errorf("src AttributionAvailable should be false")
	}

	// 3. File level rolls up 2 issues (2 * 5 = 10 mins)
	if file.Counters.IssuesByType[string(rule.TypeCodeSmell)] != 2 {
		t.Errorf("file issues by type = %d, want 2", file.Counters.IssuesByType[string(rule.TypeCodeSmell)])
	}
	if file.Counters.RemediationEffortMinutes != 10 {
		t.Errorf("file remediation = %d, want 10", file.Counters.RemediationEffortMinutes)
	}
}
