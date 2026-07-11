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

func byRule(fs []finding.Finding) map[string]finding.Finding {
	m := map[string]finding.Finding{}
	for _, f := range fs {
		// dedup key is <kind>:<rule>:<file>:<line>; index by rule id (2nd field)
		parts := strings.SplitN(f.DedupKey, ":", 3)
		if len(parts) >= 2 {
			m[parts[1]] = f
		}
	}
	return m
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
	m := byRule(fs)

	todo, ok := m["quality-todo-comment"]
	if !ok || todo.Kind != finding.KindQuality || todo.DedupKey != "quality:quality-todo-comment:a.go:3" {
		t.Errorf("todo mapping wrong: %+v", todo)
	}
	if todo.Class != finding.ClassFirstParty || todo.Status != finding.StatusOpen {
		t.Errorf("todo class/status wrong: %+v", todo)
	}
	ec, ok := m["reliability-empty-catch"]
	if !ok || ec.Kind != finding.KindReliability {
		t.Errorf("empty-catch kind wrong: %+v", ec)
	}
	dupF, ok := m["quality-duplicated-block"]
	if !ok || dupF.Kind != finding.KindQuality || !strings.Contains(dupF.Title, "x.go") {
		t.Errorf("duplication bridge wrong: %+v", dupF)
	}
	hc, ok := m["quality-high-complexity"]
	if !ok || !strings.Contains(hc.Title, "25") {
		t.Errorf("complexity bridge should flag the cyclomatic-25 function: %+v", hc)
	}
	// The cyclomatic-2 function must NOT be flagged.
	for _, f := range fs {
		if strings.Contains(f.Title, "small") {
			t.Errorf("low-complexity function must not be flagged: %+v", f)
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
