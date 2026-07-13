package codequality

import (
	"context"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeAnalyzer struct {
	raws []ports.CodeAnalysisRawFinding
}

func (f fakeAnalyzer) Analyze(context.Context, string) ([]ports.CodeAnalysisRawFinding, error) {
	return f.raws, nil
}

type fakeDup struct{ rep measure.DuplicationReport }

func (f fakeDup) Duplication(context.Context, string) (measure.DuplicationReport, error) {
	return f.rep, nil
}

type fakeMetrics struct {
	rep       measure.ComplexityReport
	available bool
}

func (f fakeMetrics) Complexity(context.Context, string) (measure.ComplexityReport, bool, error) {
	return f.rep, f.available, nil
}

func byRule(findings []finding.Finding, ruleKey string) *finding.Finding {
	for i := range findings {
		if findings[i].RuleKey == ruleKey {
			return &findings[i]
		}
	}
	return nil
}

func TestServiceMapsAndBridges(t *testing.T) {
	analyzer := fakeAnalyzer{raws: []ports.CodeAnalysisRawFinding{
		{Kind: "quality", RuleID: "quality-todo-comment", CWE: "CWE-546", Severity: shared.SeverityInfo, Title: "TODO", File: "a.go", Line: 3},
		{Kind: "reliability", RuleID: "reliability-empty-catch", CWE: "CWE-390", Severity: shared.SeverityMedium, Title: "Empty catch", File: "b.js", Line: 9},
	}}
	dup := fakeDup{rep: measure.DuplicationReport{Blocks: []measure.DuplicationBlock{
		{Tokens: 120, Occurrences: []measure.CodeRange{{File: "x.go", StartLine: 10, EndLine: 20}, {File: "y.go", StartLine: 30, EndLine: 40}}},
	}}}
	metrics := fakeMetrics{available: true, rep: measure.ComplexityReport{Functions: []measure.FunctionComplexity{
		{File: "c.py", Line: 5, Name: "big", Language: "Python", Cyclomatic: 25, Cognitive: 30},
		{File: "c.py", Line: 60, Name: "small", Language: "Python", Cyclomatic: 2, Cognitive: 1},
	}}}

	svc := New(analyzer, WithDuplication(dup), WithComplexity(metrics, 15))
	fs, err := svc.Analyze(context.Background(), "root")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	todo := byRule(fs, "quality-todo-comment")
	if todo == nil || todo.Kind != finding.KindQuality || todo.DedupKey != "quality:quality-todo-comment:a.go:3" {
		t.Errorf("todo mapping wrong: %+v", todo)
	}
	if todo.Class != finding.ClassFirstParty || todo.Status != finding.StatusOpen {
		t.Errorf("todo class/status wrong: %+v", todo)
	}
	if todo.RuleKey != "quality-todo-comment" {
		t.Errorf("todo RuleKey = %q", todo.RuleKey)
	}

	ec := byRule(fs, "reliability-empty-catch")
	if ec == nil || ec.Kind != finding.KindReliability {
		t.Errorf("empty-catch kind wrong: %+v", ec)
	}
	if ec.RuleKey != "reliability-empty-catch" {
		t.Errorf("empty-catch RuleKey = %q", ec.RuleKey)
	}

	dupF := byRule(fs, "quality-duplicated-block")
	if dupF == nil || dupF.Kind != finding.KindQuality || !strings.Contains(dupF.Title, "x.go") {
		t.Errorf("duplication bridge wrong: %+v", dupF)
	}
	if dupF.RuleKey != "quality-duplicated-block" {
		t.Errorf("duplication RuleKey = %q", dupF.RuleKey)
	}

	hc := byRule(fs, "quality-high-complexity")
	if hc == nil || !strings.Contains(hc.Title, "25") {
		t.Errorf("complexity bridge should flag the cyclomatic-25 function: %+v", hc)
	}
	if hc.RuleKey != "quality-high-complexity" {
		t.Errorf("complexity RuleKey = %q", hc.RuleKey)
	}
	// The cyclomatic-2 function must NOT be flagged.
	for _, f := range fs {
		if strings.Contains(f.Title, "small") {
			t.Errorf("low-complexity function must not be flagged: %+v", f)
		}
	}
}

type fakeBugs struct {
	bugs      []ports.BugFinding
	available bool
}

func (f fakeBugs) Bugs(context.Context, string) ([]ports.BugFinding, bool, error) {
	return f.bugs, f.available, nil
}

func TestBugsBridgeEmitsReliability(t *testing.T) {
	bugs := fakeBugs{available: true, bugs: []ports.BugFinding{
		{Rule: "reliability-unreachable-code", Message: "unreachable", File: "a.go", Line: 7},
		{Rule: "reliability-constant-condition", Message: "always true", File: "b.py", Line: 3},
	}}
	svc := New(fakeAnalyzer{}, WithBugs(bugs))
	fs, err := svc.Analyze(context.Background(), "root")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	unr := byRule(fs, "reliability-unreachable-code")
	if unr == nil || unr.Kind != finding.KindReliability || unr.DedupKey != "reliability:reliability-unreachable-code:a.go:7" {
		t.Errorf("unreachable bug mapping wrong: %+v", unr)
	}
	cc := byRule(fs, "reliability-constant-condition")
	if cc == nil || cc.Kind != finding.KindReliability {
		t.Errorf("constant-condition bug missing/wrong: %+v", cc)
	}
	// unavailable detector emits nothing.
	svc2 := New(fakeAnalyzer{}, WithBugs(fakeBugs{available: false, bugs: bugs.bugs}))
	fs2, _ := svc2.Analyze(context.Background(), "root")
	if len(fs2) != 0 {
		t.Errorf("unavailable bug detector must emit nothing, got %+v", fs2)
	}
}

func TestComplexityUnavailableSkipsBridge(t *testing.T) {
	svc := New(fakeAnalyzer{}, WithComplexity(fakeMetrics{available: false, rep: measure.ComplexityReport{
		Functions: []measure.FunctionComplexity{{Name: "x", Cyclomatic: 99}},
	}}, 15))
	fs, err := svc.Analyze(context.Background(), "root")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	for _, f := range fs {
		if strings.Contains(f.DedupKey, "high-complexity") {
			t.Errorf("unavailable metrics must not produce complexity findings: %+v", f)
		}
	}
}

func TestAnalyzerOnly(t *testing.T) {
	// No dup/metrics wired: only the rule-engine findings come through.
	svc := New(fakeAnalyzer{raws: []ports.CodeAnalysisRawFinding{
		{Kind: "quality", RuleID: "quality-todo-comment", Severity: shared.SeverityInfo, Title: "TODO", File: "a.go", Line: 1},
	}})
	fs, err := svc.Analyze(context.Background(), "root")
	if err != nil || len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d err=%v", len(fs), err)
	}
}

func TestTestScopedInfoSmellsSuppressed(t *testing.T) {
	raws := []ports.CodeAnalysisRawFinding{
		{Kind: "quality", RuleID: "quality-commented-out-code", Severity: shared.SeverityInfo, Title: "commented", File: "src/test/java/FooTest.java", Line: 3},
		{Kind: "quality", RuleID: "quality-commented-out-code", Severity: shared.SeverityInfo, Title: "commented", File: "src/main/java/Foo.java", Line: 9},
		{Kind: "reliability", RuleID: "reliability-empty-catch", Severity: shared.SeverityMedium, Title: "empty catch", File: "src/test/java/FooTest.java", Line: 5},
	}
	// Default: info smell in test code is dropped; the prod info smell and the test-scoped MEDIUM stay.
	fs, err := New(fakeAnalyzer{raws: raws}).Analyze(context.Background(), "root")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(fs) != 2 {
		t.Fatalf("default should drop the test-scoped info smell, want 2, got %d: %+v", len(fs), fs)
	}
	if byRule(fs, "reliability-empty-catch") == nil {
		t.Errorf("a medium finding in test code must be kept")
	}
	// The prod commented-out-code must survive; the test one must not.
	var prod, test int
	for _, f := range fs {
		if strings.Contains(f.DedupKey, "src/main/") {
			prod++
		}
		if strings.Contains(f.DedupKey, "FooTest.java") && f.Kind == finding.KindQuality {
			test++
		}
	}
	if prod != 1 || test != 0 {
		t.Errorf("want prod-info kept (1) and test-info dropped (0); got prod=%d test=%d", prod, test)
	}

	// Opt-in restores full verbosity.
	all, err := New(fakeAnalyzer{raws: raws}, WithTestScopedSmells(true)).Analyze(context.Background(), "root")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("WithTestScopedSmells(true) should keep all 3, got %d", len(all))
	}
}

func TestIsTestPath(t *testing.T) {
	tests := map[string]bool{
		"src/test/java/com/x/FooTest.java":  true,
		"services/kyc/src/test/java/A.java": true,
		"pkg/foo_test.go":                   true,
		"app/user.test.ts":                  true,
		"app/user.spec.ts":                  true,
		"tests/test_login.py":               true,
		"foo/testdata/sample.json":          true,
		"a/__tests__/b.js":                  true,
		"Bar.kt":                            false,
		"BarTest.kt":                        true,
		// Production files that must NOT be misclassified (the substring-match FP class).
		"src/main/java/com/x/Latest.java":   false,
		"src/main/java/com/x/Contest.java":  false,
		"src/main/java/com/x/Greatest.java": false,
		"pkg/testing/helper.go":             false, // production test-helper package
		"api/spec/handler.go":               false, // production spec dir
		"src/main/java/com/x/Foo.java":      false,
	}
	for path, want := range tests {
		if got := isTestPath(path); got != want {
			t.Errorf("isTestPath(%q) = %v, want %v", path, got, want)
		}
	}
}
