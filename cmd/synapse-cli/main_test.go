package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
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
