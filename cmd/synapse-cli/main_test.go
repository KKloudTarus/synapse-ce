package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/coverage"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/gitdiff"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/sast"
)

func TestSASTLocationNormalizesPath(t *testing.T) {
	loc := sastLocation(`src\pkg\main.go`, 5)
	if loc == nil || loc.File != "src/pkg/main.go" || loc.StartLine != 5 || loc.Validate() != nil {
		t.Fatalf("sastLocation = %+v", loc)
	}
}

func TestFindingFileLinePrefersStructuredLocation(t *testing.T) {
	f := finding.Finding{
		DedupKey:       "cq:sast:text:bidi-unicode:wrong.go:99",
		SourceLocation: &finding.SourceLocation{File: "src/main.go", StartLine: 10, EndLine: 10},
	}
	file, line, ok := findingFileLine(f)
	if !ok || file != "src/main.go" || line != 10 {
		t.Fatalf("findingFileLine = (%q, %d, %v)", file, line, ok)
	}
}

func TestFindingFileLineFallsBackForInvalidLocation(t *testing.T) {
	f := finding.Finding{
		DedupKey:       "cq:quality:quality-todo-comment:a.go:3",
		SourceLocation: &finding.SourceLocation{StartLine: 1, EndLine: 1},
	}
	file, line, ok := findingFileLine(f)
	if !ok || file != "a.go" || line != 3 {
		t.Fatalf("findingFileLine = (%q, %d, %v)", file, line, ok)
	}
}

func TestFilterNewCodeUsesStructuredLocationForColonRule(t *testing.T) {
	f := finding.Finding{
		RuleKey:        "text:bidi-unicode",
		DedupKey:       "cq:sast:text:bidi-unicode:src/main.go:10",
		SourceLocation: &finding.SourceLocation{File: "src/main.go", StartLine: 10, EndLine: 10},
	}
	got := filterNewCode([]finding.Finding{f}, gitdiff.ChangedLines{"src/main.go": {10: true}})
	if len(got) != 1 {
		t.Fatalf("filterNewCode returned %d findings", len(got))
	}
}

func TestRunGateFailsForRubyEvalRequestData(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.rb"), []byte("def run(x)\n eval(params[:x])\nend\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	findings, err := sast.New().AnalyzeSource(context.Background(), root)
	if err != nil {
		t.Fatalf("analyze Ruby source: %v", err)
	}
	var found bool
	for _, raw := range findings {
		if raw.RuleID == "rb:eval-request-data" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("SAST findings do not include rb:eval-request-data: %+v", findings)
	}

	err = runGate([]string{root})
	if err == nil || !strings.Contains(err.Error(), "quality gate FAILED") {
		t.Fatalf("runGate error = %v, want critical Ruby SAST finding to fail the gate", err)
	}
}

func TestFilterByConfidence(t *testing.T) {
	findings := []finding.Finding{
		{Title: "high", Confidence: "high"},
		{Title: "medium", Confidence: "medium"},
		{Title: "low", Confidence: "low"},
		{Title: "sast-no-confidence", Confidence: ""}, // SAST/misconfig carry none — must be kept
	}
	got := filterByConfidence(findings, "high")
	titles := map[string]bool{}
	for _, f := range got {
		titles[f.Title] = true
	}
	if !titles["high"] || !titles["sast-no-confidence"] {
		t.Fatalf("--min-confidence high must keep high + unscored findings: %+v", titles)
	}
	if titles["medium"] || titles["low"] {
		t.Fatalf("--min-confidence high must drop medium/low: %+v", titles)
	}
}

func TestScopeToNewCodeKeepsUnanchoredFindings(t *testing.T) {
	changed := gitdiff.ChangedLines{"app.go": {10: true}}
	findings := []finding.Finding{
		{Title: "sast on changed line", SourceLocation: &finding.SourceLocation{File: "app.go", StartLine: 10, EndLine: 10}},
		{Title: "sast on unchanged line", SourceLocation: &finding.SourceLocation{File: "app.go", StartLine: 99, EndLine: 99}},
		{Title: "sca vuln (no line)", Kind: finding.KindSCA, DedupKey: "CVE-2024-1:pkg:1.0"},
	}
	out := scopeToNewCode(findings, changed)
	got := map[string]bool{}
	for _, f := range out {
		got[f.Title] = true
	}
	if !got["sast on changed line"] {
		t.Error("a line-anchored finding on a changed line must be kept")
	}
	if got["sast on unchanged line"] {
		t.Error("a line-anchored finding on an unchanged line must be dropped")
	}
	if !got["sca vuln (no line)"] {
		t.Error("a non-line-anchored SCA finding must be KEPT (dropping it would falsely report clean)")
	}
}

func TestLoadAndApplySynapseignore(t *testing.T) {
	dir := t.TempDir()
	yaml := "suppress:\n  - rule: github-token\n    reason: \"rotated test token\"\n    expires: \"2099-12-31\"\n  - rule: old-rule\n    reason: \"stale\"\n    expires: \"2020-01-01\"\n"
	if err := os.WriteFile(filepath.Join(dir, ".synapseignore"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	rs, err := loadSynapseignore(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(rs) != 2 {
		t.Fatalf("want 2 rules, got %d", len(rs))
	}
	findings := []finding.Finding{
		{Title: "gh", RuleKey: "github-token"},
		{Title: "kept", RuleKey: "aws-access-key-id"},
	}
	kept, n := applySuppressions(findings, rs, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	if n != 1 || len(kept) != 1 || kept[0].RuleKey != "aws-access-key-id" {
		t.Fatalf("active suppression must drop github-token only: kept=%+v n=%d", kept, n)
	}

	// A malformed entry (no reason) fails loudly.
	if err := os.WriteFile(filepath.Join(dir, ".synapseignore"), []byte("suppress:\n  - rule: x\n    expires: \"2099-01-01\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSynapseignore(dir); err == nil {
		t.Fatal("a suppression with no reason must be rejected")
	}

	// Missing file => empty ruleset, no error.
	if rs, err := loadSynapseignore(t.TempDir()); err != nil || rs != nil {
		t.Fatalf("missing .synapseignore must be (nil, nil), got %v %v", rs, err)
	}
}

// TestRunQualityEmitsSARIFWhenGateFails locks the report/gate ordering: `quality --sarif --fail-on ...`
// must write the SARIF document even though the gate then fails the command. Redirecting stdout to a
// file used to leave that file empty, so the CI step that failed the build also destroyed its evidence.
func TestRunQualityEmitsSARIFWhenGateFails(t *testing.T) {
	root := t.TempDir()
	src := "// TODO: fix this\nfunction f(a) {\n  return a;\n}\n"
	if err := os.WriteFile(filepath.Join(root, "app.js"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		args     []string
		contains string
	}{
		{name: "sarif", args: []string{root, "--sarif", "--fail-on", "info"}, contains: `"results"`},
		{name: "text", args: []string{root, "--fail-on", "info"}, contains: "findings:"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := runQualityTo(&buf, tc.args)
			if err == nil {
				t.Fatal("runQualityTo returned nil, want the --fail-on gate error")
			}
			if !strings.Contains(err.Error(), "at or above info") {
				t.Fatalf("gate error = %v, want the --fail-on message", err)
			}
			if buf.Len() == 0 {
				t.Fatal("report is empty; it must be written before the gate decision")
			}
			if !strings.Contains(buf.String(), tc.contains) {
				t.Fatalf("report missing %q, got:\n%s", tc.contains, buf.String())
			}
		})
	}
}

// TestRunQualitySARIFIsValidJSON checks the emitted SARIF actually decodes and carries the findings, so
// the ordering test above cannot pass on a truncated or half-written document.
func TestRunQualitySARIFIsValidJSON(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.js"), []byte("// TODO: fix this\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := runQualityTo(&buf, []string{root, "--sarif", "--fail-on", "info"}); err == nil {
		t.Fatal("runQualityTo returned nil, want the --fail-on gate error")
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("decode sarif: %v\n%s", err, buf.String())
	}
	if len(doc.Runs) == 0 || len(doc.Runs[0].Results) == 0 {
		t.Fatalf("sarif carries no results: %s", buf.String())
	}
}

// TestApplyNewCodeMetrics: in new-code mode the CLI writes new_coverage and new_duplication only when it
// could measure them. The gate treats an absent key as "no data" and fails the condition; a 0 written
// for a missing report would let `new_duplication <= 3` pass on nothing, which is exactly the outcome
// the absent key exists to prevent.
func TestApplyNewCodeMetrics(t *testing.T) {
	changed := gitdiff.ChangedLines{"src/a.go": {10: true, 11: true, 12: true, 13: true}}
	lc := coverage.LineCoverage{"./src/a.go": {10: true, 11: true, 12: false, 99: false}}
	dup := &measure.DuplicationReport{Blocks: []measure.DuplicationBlock{{Occurrences: []measure.CodeRange{{File: "src/a.go", StartLine: 12, EndLine: 13}}}}}

	snap := qualitygate.Snapshot{}
	applyNewCodeMetrics(snap, lc, dup, changed)
	if got, ok := snap[qualitygate.MetricNewCoverage]; !ok || got != 100.0*2/3 {
		t.Fatalf("new_coverage = %g ok=%v, want %g (2 of the 3 changed lines the report knows about; line 99 is unchanged)", got, ok, 100.0*2/3)
	}
	if got, ok := snap[qualitygate.MetricNewDuplication]; !ok || got != 50 {
		t.Fatalf("new_duplication = %g ok=%v, want 50 (lines 12-13 of 4 changed lines are duplicated)", got, ok)
	}

	// No coverage report: new_coverage stays absent; new_duplication is still measured.
	snap = qualitygate.Snapshot{}
	applyNewCodeMetrics(snap, nil, dup, changed)
	if _, present := snap[qualitygate.MetricNewCoverage]; present {
		t.Fatal("new_coverage must be absent without a report")
	}
	if _, present := snap[qualitygate.MetricNewDuplication]; !present {
		t.Fatal("new_duplication must still be measured without a coverage report")
	}

	// A report that matches no changed line, and a diff with no lines: nothing is written.
	snap = qualitygate.Snapshot{}
	applyNewCodeMetrics(snap, coverage.LineCoverage{"other.go": {1: true}}, dup, gitdiff.ChangedLines{})
	if len(snap) != 0 {
		t.Fatalf("nothing measurable must write nothing, got %v", snap)
	}

	// The absent keys are what make the gate fail closed rather than pass on 0.
	res := qualitygate.Evaluate(qualitygate.Gate{Conditions: []qualitygate.Condition{{Metric: qualitygate.MetricNewDuplication, Op: qualitygate.OpLE, Threshold: 3}}}, snap)
	if res.Passed || !res.Results[0].Unmeasured {
		t.Fatalf("an unmeasured new_duplication must fail closed: %+v", res.Results)
	}
}

func TestGoModulePath(t *testing.T) {
	dir := t.TempDir()
	if got := goModulePath(dir); got != "" {
		t.Fatalf("no go.mod must read as no module, got %q", got)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("// comment\nmodule  example.com/acme/app // trailing\n\ngo 1.27\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := goModulePath(dir); got != "example.com/acme/app" {
		t.Fatalf("module path = %q, want example.com/acme/app", got)
	}
}

// TestRunGateStripsGoModulePathForNewCodeCoverage is the wiring test: the only place that supplies the
// module path to the parser is runGate, and its effect is visible only when coverage keys must match the
// diff's repo-relative paths. A Go profile keyed by import path passes a new-code coverage floor only if
// that prefix was stripped; a regression to Options{} leaves every parser test green and fails this one.
func TestRunGateStripsGoModulePathForNewCodeCoverage(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	root := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	write("go.mod", "module example.com/acme/app\n\ngo 1.27\n")
	write("calc.go", "package app\n\nfunc Add(a, b int) int {\n\treturn a + b\n}\n")
	git("init", "-q", "-b", "main")
	git("add", ".")
	git("commit", "-q", "-m", "base")
	// The change adds lines 7-9; the profile marks them covered under the IMPORT path.
	write("calc.go", "package app\n\nfunc Add(a, b int) int {\n\treturn a + b\n}\n\nfunc Sub(a, b int) int {\n\treturn a - b\n}\n")
	git("add", ".")
	git("commit", "-q", "-m", "change")
	write("cover.out", "mode: set\nexample.com/acme/app/calc.go:3.24,5.2 1 1\nexample.com/acme/app/calc.go:7.24,9.2 1 1\n")
	write(".synapse-gate.yaml", "conditions:\n  - metric: coverage\n    op: \">=\"\n    threshold: 50\n")

	if err := runGate([]string{root, "--new-code-only", "--base", "HEAD~1", "--coverage", filepath.Join(root, "cover.out")}); err != nil {
		t.Fatalf("new-code coverage floor must pass once the module path is stripped: %v", err)
	}
	// The same profile with a module the tree does not declare cannot be matched: the floor fails.
	write("go.mod", "module example.com/other/mod\n\ngo 1.27\n")
	if err := runGate([]string{root, "--new-code-only", "--base", "HEAD~1", "--coverage", filepath.Join(root, "cover.out")}); err == nil || !strings.Contains(err.Error(), "quality gate FAILED") {
		t.Fatalf("with an unmatched module path the import-path keys must not match the diff, got %v", err)
	}
}
