package codequality

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/codeanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeAnalyzer struct {
	raws      []ports.CodeAnalysisRawFinding
	truncated bool
}

func (f fakeAnalyzer) Analyze(context.Context, string) (ports.CodeAnalysisReport, error) {
	return ports.CodeAnalysisReport{Findings: f.raws, Truncated: f.truncated}, nil
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
	if todo == nil || todo.Kind != finding.KindQuality || todo.DedupKey != "cq:quality:quality-todo-comment:a.go:3" {
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
	if dupF == nil || dupF.Kind != finding.KindQuality || dupF.Severity != shared.SeverityLow || !strings.Contains(dupF.Title, "x.go") {
		t.Errorf("duplication bridge wrong: %+v", dupF)
	}
	if dupF.RuleKey != "quality-duplicated-block" {
		t.Errorf("duplication RuleKey = %q", dupF.RuleKey)
	}

	hc := byRule(fs, "quality-high-complexity")
	if hc == nil || hc.Kind != finding.KindQuality || hc.Severity != shared.SeverityMedium || !strings.Contains(hc.Title, "25") {
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

func TestCodeQualitySASTKeysAreNamespaced(t *testing.T) {
	fs, err := New(fakeAnalyzer{raws: []ports.CodeAnalysisRawFinding{{
		Kind: "sast", RuleID: "weak-hash-md5", File: "cmd/app/main.go", Line: 42,
	}}}).Analyze(context.Background(), "root")
	if err != nil || len(fs) != 1 {
		t.Fatalf("findings = %+v, err = %v", fs, err)
	}
	if got, want := fs[0].DedupKey, "cq:sast:weak-hash-md5:cmd/app/main.go:42"; got != want {
		t.Fatalf("DedupKey = %q, want %q", got, want)
	}
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
	if unr == nil || unr.Kind != finding.KindReliability || unr.Severity != shared.SeverityMedium || unr.DedupKey != "cq:reliability:reliability-unreachable-code:a.go:7" {
		t.Errorf("unreachable bug mapping wrong: %+v", unr)
	}
	cc := byRule(fs, "reliability-constant-condition")
	if cc == nil || cc.Kind != finding.KindReliability || cc.Severity != shared.SeverityMedium {
		t.Errorf("constant-condition bug missing/wrong: %+v", cc)
	}
	// unavailable detector emits nothing.
	svc2 := New(fakeAnalyzer{}, WithBugs(fakeBugs{available: false, bugs: bugs.bugs}))
	fs2, _ := svc2.Analyze(context.Background(), "root")
	if len(fs2) != 0 {
		t.Errorf("unavailable bug detector must emit nothing, got %+v", fs2)
	}
}

func TestKotlinCognitiveComplexityOwnsKotlinFinding(t *testing.T) {
	metrics := fakeMetrics{available: true, rep: measure.ComplexityReport{Functions: []measure.FunctionComplexity{
		{File: "High.kt", Line: 4, Name: "classify", Language: "Kotlin", Cyclomatic: 25, Cognitive: 30},
		{File: "Low.kt", Line: 2, Name: "simple", Language: "Kotlin", Cyclomatic: 20, Cognitive: 1},
		{File: "high.py", Line: 3, Name: "branch", Language: "Python", Cyclomatic: 25, Cognitive: 30},
	}}}
	fs, err := New(fakeAnalyzer{}, WithComplexity(metrics, 15)).Analyze(context.Background(), "root")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	kotlin := byRule(fs, "kotlin-cognitive-complexity")
	if kotlin == nil || kotlin.Kind != finding.KindQuality || kotlin.Severity != shared.SeverityMedium {
		t.Fatalf("expected Kotlin cognitive-complexity quality/medium finding: %+v", kotlin)
	}
	generic := byRule(fs, "quality-high-complexity")
	if generic == nil || !strings.Contains(generic.Title, "high.py") {
		t.Fatalf("expected unchanged non-Kotlin complexity finding: %+v", generic)
	}
	for _, f := range fs {
		if f.RuleKey == "quality-high-complexity" && strings.Contains(f.Title, "High.kt") {
			t.Fatalf("Kotlin function was reported by generic rule: %+v", f)
		}
		if strings.Contains(f.Title, "simple") {
			t.Fatalf("low Kotlin complexity reported: %+v", f)
		}
	}
}

func TestSwiftCognitiveComplexityBridge(t *testing.T) {
	metrics := fakeMetrics{available: true, rep: measure.ComplexityReport{Functions: []measure.FunctionComplexity{
		{File: "a.swift", Line: 7, Name: "complex", Language: "Swift", Cyclomatic: 16, Cognitive: 20},
		{File: "b.swift", Line: 3, Name: "simple", Language: "Swift", Cyclomatic: 2, Cognitive: 15},
		{File: "c.go", Line: 1, Name: "other", Language: "Go", Cyclomatic: 2, Cognitive: 30},
	}}}
	fs, err := New(fakeAnalyzer{}, WithComplexity(metrics, 15)).Analyze(context.Background(), "root")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	f := byRule(fs, "swift:cognitive-complexity")
	if f == nil || f.Kind != finding.KindQuality || f.SourceLocation.StartLine != 7 || f.DedupKey != "cq:quality:swift:cognitive-complexity:a.swift:7" {
		t.Fatalf("Swift cognitive finding = %+v", f)
	}
	if byRule(fs, "quality-high-complexity") == nil {
		t.Fatal("generic cyclomatic bridge must coexist")
	}
}

func TestPHPCognitiveComplexityOwnsPHPFinding(t *testing.T) {
	metrics := fakeMetrics{available: true, rep: measure.ComplexityReport{Functions: []measure.FunctionComplexity{
		{File: "High.php", Line: 4, Name: "classify", Language: "PHP", Cyclomatic: 25, Cognitive: 30},
		{File: "Low.php", Line: 2, Name: "simple", Language: "PHP", Cyclomatic: 20, Cognitive: 1},
	}}}
	fs, err := New(fakeAnalyzer{}, WithComplexity(metrics, 15)).Analyze(context.Background(), "root")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	php := byRule(fs, "php:cognitive-complexity")
	if php == nil || php.Kind != finding.KindQuality || php.Severity != shared.SeverityMedium || !strings.Contains(php.Title, "classify") {
		t.Fatalf("expected PHP cognitive-complexity finding: %+v", fs)
	}
	for _, f := range fs {
		if f.RuleKey == "quality-high-complexity" && strings.Contains(f.Title, ".php") {
			t.Fatalf("PHP function was reported by generic rule: %+v", f)
		}
		if strings.Contains(f.Title, "simple") {
			t.Fatalf("low-cognitive PHP function reported: %+v", f)
		}
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

func TestBuildReportMarksTruncatedCodeAnalysis(t *testing.T) {
	report, err := New(fakeAnalyzer{truncated: true}).BuildReport(context.Background(), "root")
	if err != nil {
		t.Fatalf("BuildReport: %v", err)
	}
	if !report.Truncated {
		t.Fatal("truncated analyzer output must mark the code-quality report incomplete")
	}
}

func TestSwiftCognitiveComplexityBridgeDoesNotCapFindings(t *testing.T) {
	functions := make([]measure.FunctionComplexity, 21)
	for i := range functions {
		functions[i] = measure.FunctionComplexity{File: "a.swift", Line: i + 1, Name: "complex", Language: "Swift", Cognitive: 16}
	}
	fs, err := New(fakeAnalyzer{}, WithComplexity(fakeMetrics{available: true, rep: measure.ComplexityReport{Functions: functions}}, 15)).Analyze(context.Background(), "root")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	var cognitive int
	for _, f := range fs {
		if f.RuleKey == "swift:cognitive-complexity" {
			cognitive++
		}
	}
	if cognitive != len(functions) {
		t.Fatalf("cognitive findings = %d, want %d", cognitive, len(functions))
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
		"Parser.vb":                         false,
		"ParserTest.vb":                     true,
		"ParserTests.vb":                    true,
		"ParserTest.VB":                     true,
		"ParserTests.vB":                    true,
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

func TestServiceBridgesXMLSASTFindings(t *testing.T) {
	analyzer := fakeAnalyzer{raws: []ports.CodeAnalysisRawFinding{
		{Kind: "sast", RuleID: "xml:external-entity", CWE: "CWE-611", Severity: shared.SeverityHigh, Title: "External general entity declaration", File: "config.xml", Line: 2},
		{Kind: "sast", RuleID: "xml:entity-expansion", CWE: "CWE-776", Severity: shared.SeverityMedium, Title: "Dangerous XML entity expansion structure", File: "payload.xml", Line: 5},
		{Kind: "reliability", RuleID: "xml:not-well-formed", CWE: "", Severity: shared.SeverityMedium, Title: "XML document is not well formed", File: "bad.xml", Line: 1},
		{Kind: "reliability", RuleID: "xml:mismatched-tag", CWE: "", Severity: shared.SeverityMedium, Title: "Mismatched XML end tag", File: "mismatch.xml", Line: 1},
	}}

	svc := New(analyzer)
	fs, err := svc.Analyze(context.Background(), "root")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	xxe := byRule(fs, "xml:external-entity")
	if xxe == nil || xxe.Kind != finding.KindSAST {
		t.Fatalf("expected XML external-entity to become KindSAST, got %+v", xxe)
	}
	if xxe.RuleKey != "xml:external-entity" || xxe.SourceLocation == nil || xxe.SourceLocation.File != "config.xml" || xxe.SourceLocation.StartLine != 2 {
		t.Fatalf("colon-bearing rule identity/location lost: %+v", xxe)
	}

	exp := byRule(fs, "xml:entity-expansion")
	if exp == nil || exp.Kind != finding.KindSAST {
		t.Fatalf("expected XML entity-expansion to become KindSAST, got %+v", exp)
	}

	mal := byRule(fs, "xml:not-well-formed")
	if mal == nil || mal.Kind != finding.KindReliability {
		t.Fatalf("expected XML not-well-formed to remain KindReliability, got %+v", mal)
	}

	mismatch := byRule(fs, "xml:mismatched-tag")
	if mismatch == nil || mismatch.Kind != finding.KindReliability {
		t.Fatalf("expected XML mismatched-tag to remain KindReliability, got %+v", mismatch)
	}
}

func TestServiceRealXMLAnalyzerIntegration(t *testing.T) {
	// Create a temporary directory with various XMLs
	dir := t.TempDir()

	files := map[string]string{
		"config.xml": `<!DOCTYPE root [
		<!ENTITY xxe SYSTEM "file:///etc/passwd">
	]>
	<root>&xxe;</root>`,
		"mismatch.xml":   `<root><item></other></root>`,
		"undeclared.xml": `<root><cfg:item/></root>`,
		"bad.xml":        `<service name=api></service>`,
	}

	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	// Instantiate real analyzer
	realAnalyzer := codeanalysis.New()
	svc := New(realAnalyzer)

	fs, err := svc.Analyze(context.Background(), dir)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	check := func(ruleID string, expectedKind finding.Kind) {
		f := byRule(fs, ruleID)
		if f == nil {
			t.Fatalf("expected real analyzer to detect %s, got findings: %+v", ruleID, fs)
		}
		if f.Kind != expectedKind {
			t.Errorf("expected %s to have kind %q, got %q", ruleID, expectedKind, f.Kind)
		}
	}

	check("xml:external-entity", finding.KindSAST)
	check("xml:mismatched-tag", finding.KindReliability)
	check("xml:undeclared-prefix", finding.KindReliability)
	check("xml:not-well-formed", finding.KindReliability)
}

// TestAnalyzerKindsMapToDomainKinds pins the full kind vocabulary the deterministic analyzers can emit.
// The astwalk language packs speak "security" (HTML security rules) and "maintainability" (CSS rules) on
// top of the domain "quality"/"reliability"/"sast"; every one of them must resolve to a domain kind. The
// unknown case is the regression guard: a kind added to a language pack later must degrade, not crash.
func TestAnalyzerKindsMapToDomainKinds(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want finding.Kind
	}{
		{name: "quality", raw: "quality", want: finding.KindQuality},
		{name: "maintainability", raw: "maintainability", want: finding.KindQuality},
		{name: "reliability", raw: "reliability", want: finding.KindReliability},
		{name: "sast", raw: "sast", want: finding.KindSAST},
		{name: "security", raw: "security", want: finding.KindSAST},
		{name: "mixed case", raw: "Security", want: finding.KindSAST},
		{name: "padded", raw: " reliability ", want: finding.KindReliability},
		{name: "unknown falls back", raw: "accessibility", want: finding.KindQuality},
		{name: "empty falls back", raw: "", want: finding.KindQuality},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := domainKind(tc.raw); got != tc.want {
				t.Fatalf("domainKind(%q) = %q, want %q", tc.raw, got, tc.want)
			}
			if !tc.want.Valid() {
				t.Fatalf("domainKind(%q) produced an invalid domain kind %q", tc.raw, tc.want)
			}
		})
	}
}

// TestAnalyzeAcceptsEveryAnalyzerKind runs the service over raw findings carrying every kind an analyzer
// can report, through both the primary and the structural analyzer slots. Before the fix the structural
// slot failed the whole run with `unknown code-analysis finding kind "security"` on any tree with HTML.
func TestAnalyzeAcceptsEveryAnalyzerKind(t *testing.T) {
	raws := []ports.CodeAnalysisRawFinding{
		{Kind: "quality", RuleID: "quality-todo-comment", Severity: shared.SeverityLow, Title: "todo", File: "a.js", Line: 1},
		{Kind: "maintainability", RuleID: "css:important-overuse", Severity: shared.SeverityLow, Title: "important", File: "a.css", Line: 2},
		{Kind: "reliability", RuleID: "js:always-true", Severity: shared.SeverityMedium, Title: "always true", File: "a.js", Line: 3},
		{Kind: "sast", RuleID: "js:eval", CWE: "95", Severity: shared.SeverityHigh, Title: "eval", File: "a.js", Line: 4},
		{Kind: "security", RuleID: "html:javascript-url", CWE: "79", Severity: shared.SeverityHigh, Title: "javascript url", File: "a.html", Line: 5},
		{Kind: "some-future-kind", RuleID: "html:future", Severity: shared.SeverityLow, Title: "future", File: "a.html", Line: 6},
	}
	for _, slot := range []string{"primary", "structural"} {
		t.Run(slot, func(t *testing.T) {
			var svc *Service
			if slot == "primary" {
				svc = New(fakeAnalyzer{raws: raws})
			} else {
				svc = New(fakeAnalyzer{}, WithStructuralAnalyzer(fakeAnalyzer{raws: raws}))
			}
			got, err := svc.Analyze(context.Background(), "/repo")
			if err != nil {
				t.Fatalf("Analyze: %v", err)
			}
			if len(got) != len(raws) {
				t.Fatalf("got %d findings, want %d", len(got), len(raws))
			}
			want := map[string]finding.Kind{
				"quality-todo-comment":  finding.KindQuality,
				"css:important-overuse": finding.KindQuality,
				"js:always-true":        finding.KindReliability,
				"js:eval":               finding.KindSAST,
				"html:javascript-url":   finding.KindSAST,
				"html:future":           finding.KindQuality,
			}
			for rule, wantKind := range want {
				f := byRule(got, rule)
				if f == nil {
					t.Fatalf("rule %q missing from findings", rule)
				}
				if f.Kind != wantKind {
					t.Errorf("rule %q kind = %q, want %q", rule, f.Kind, wantKind)
				}
				if !strings.HasPrefix(f.DedupKey, "cq:"+string(wantKind)+":") {
					t.Errorf("rule %q dedup key = %q, want the resolved domain kind in the key", rule, f.DedupKey)
				}
			}
		})
	}
}

// TestEveryAnalyzerKindIsMappedExplicitly keeps the fallback in domainKind from quietly demoting a
// security signal.
//
// domainKind answers KindQuality for a kind it does not recognize, which is deliberate: a rule added
// to a language pack must not be able to crash a whole run, and that crash is exactly the defect
// this release fixed. The cost is that an unmapped SECURITY kind silently becomes a low-severity
// quality finding and stops failing the gate. This test walks the kind vocabulary the language packs
// actually emit and requires each to be mapped on purpose, so a new one is a decision rather than a
// demotion.
func TestEveryAnalyzerKindIsMappedExplicitly(t *testing.T) {
	packKinds, err := analyzerKindVocabulary()
	if err != nil {
		t.Fatalf("read the language packs: %v", err)
	}
	if len(packKinds) < 3 {
		t.Fatalf("found %d kinds in the language packs; the vocabulary is no longer being read", len(packKinds))
	}
	for _, kind := range packKinds {
		if _, mapped := analyzerKinds[kind]; !mapped {
			t.Errorf("language packs emit kind %q with no entry in analyzerKinds, so it silently becomes a quality finding; map it on purpose", kind)
		}
	}

	// A security vocabulary must never fall through to the quality fallback.
	for _, kind := range []string{"sast", "security"} {
		if got := domainKind(kind); got != finding.KindSAST {
			t.Errorf("domainKind(%q) = %q, want %q: a security signal must not be demoted", kind, got, finding.KindSAST)
		}
	}
}

// analyzerKindVocabulary reads the kind literals the language-pack rule tables declare. The tables
// are Go composite literals whose first element is the kind, so the vocabulary is readable without
// running the cgo analyzers this test cannot build.
func analyzerKindVocabulary() ([]string, error) {
	matches, err := filepath.Glob(filepath.Join("..", "..", "infrastructure", "tools", "astwalk", "*_quality_cgo.go"))
	if err != nil {
		return nil, err
	}
	kindLiteral := regexp.MustCompile(`\{"([a-z_]+)",`)
	seen := map[string]bool{}
	var out []string
	for _, path := range matches {
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, readErr
		}
		for _, m := range kindLiteral.FindAllStringSubmatch(string(src), -1) {
			if !seen[m[1]] {
				seen[m[1]] = true
				out = append(out, m[1])
			}
		}
	}
	sort.Strings(out)
	return out, nil
}
