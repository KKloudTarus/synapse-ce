package projectuc

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/codequality"
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

func TestBaselineBranchForRecording(t *testing.T) {
	cases := []struct {
		name            string
		recordingBranch string
		ci              *projectanalysis.CIContext
		want            string
	}{
		{"no ci", "feature/x", nil, "feature/x"},
		{"non-pr ci", "main", &projectanalysis.CIContext{Branch: "main"}, "main"},
		{"pr uses target branch", "feature/x", &projectanalysis.CIContext{Branch: "feature/x", PullRequest: "42", TargetBranch: "main"}, "main"},
		{"pr target trimmed", "feature/x", &projectanalysis.CIContext{PullRequest: "42", TargetBranch: "  develop "}, "develop"},
		// A PR number without a target branch cannot re-base: keep the recording branch.
		{"pr without target", "feature/x", &projectanalysis.CIContext{PullRequest: "42"}, "feature/x"},
		// A target branch without a PR number is not a PR analysis: keep the recording branch.
		{"target without pr", "feature/x", &projectanalysis.CIContext{TargetBranch: "main"}, "feature/x"},
	}
	for _, c := range cases {
		if got := baselineBranchForRecording(c.recordingBranch, c.ci); got != c.want {
			t.Errorf("%s: baselineBranchForRecording(%q, %+v) = %q, want %q", c.name, c.recordingBranch, c.ci, got, c.want)
		}
	}
}

func prQualityFinding(dedupKey string) finding.Finding {
	return finding.Finding{DedupKey: dedupKey, RuleKey: "code-smell", Kind: finding.KindQuality, Severity: shared.SeverityMedium, Status: finding.StatusOpen}
}

func prQualityResult(commit string, dedupKeys ...string) *scauc.ScanResult {
	findings := make([]finding.Finding, 0, len(dedupKeys))
	for _, k := range dedupKeys {
		findings = append(findings, prQualityFinding(k))
	}
	return &scauc.ScanResult{
		Target: "/repo", SourceCommit: commit,
		CodeQuality: &codequality.Report{
			Inventory: measure.Inventory{Files: []measure.FileInventory{{Path: "src/a.go", Language: "go", CodeLines: 100}}},
			Findings:  findings,
		},
	}
}

// TestImportPullRequestAnalysisBasesNewCodeOnTargetBranch proves the #1127 wiring end to end: a PR
// import lists its New-Code baseline from the target branch, so an issue already present on the target
// is not new, and only the issue the PR adds is counted as new.
func TestImportPullRequestAnalysisBasesNewCodeOnTargetBranch(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _ := newImportService(t)

	// Baseline on the target branch "main" already has issue X.
	main := prQualityResult("0123456789abcdef0123456789abcdef0123aaaa", "quality:code-smell:src/a.go:1")
	if _, err := svc.ImportAnalysis(ctx, "tenant", "project", ImportAnalysisInput{Actor: "ci-bot", CI: projectanalysis.CIContext{Branch: "main"}, Result: main}); err != nil {
		t.Fatal(err)
	}

	// A PR from feature/x targeting main carries X (unchanged) and adds Z.
	prCI := projectanalysis.CIContext{Branch: "feature/x", PullRequest: "42", TargetBranch: "main", RepoSlug: "acme/app", HeadSHA: "0123456789abcdef0123456789abcdef0123bbbb"}
	prResult := prQualityResult("0123456789abcdef0123456789abcdef0123bbbb", "quality:code-smell:src/a.go:1", "quality:code-smell:src/a.go:5")
	pr, err := svc.ImportAnalysis(ctx, "tenant", "project", ImportAnalysisInput{Actor: "ci-bot", CI: prCI, Result: prResult})
	if err != nil {
		t.Fatal(err)
	}
	if pr.NewCode.Counts.Total != 1 {
		t.Fatalf("PR new-code total = %d, want 1 (only the target-absent issue Z is new; X is already on main)", pr.NewCode.Counts.Total)
	}
}
