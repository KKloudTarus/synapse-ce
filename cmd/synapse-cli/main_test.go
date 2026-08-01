package main

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/gitdiff"
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
