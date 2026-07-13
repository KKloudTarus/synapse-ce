package codequality

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/rulecatalog"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeDup2 struct{}

func (f fakeDup2) Duplication(context.Context, string) (measure.DuplicationReport, error) {
	return measure.DuplicationReport{Blocks: []measure.DuplicationBlock{{Tokens: 100, Occurrences: []measure.CodeRange{{File: "a", StartLine: 1, EndLine: 2}, {File: "b", StartLine: 1, EndLine: 2}}}}}, nil
}

type fakeMetrics2 struct{}

func (f fakeMetrics2) Complexity(context.Context, string) (measure.ComplexityReport, bool, error) {
	return measure.ComplexityReport{Functions: []measure.FunctionComplexity{{File: "a", Line: 1, Name: "b", Cyclomatic: 50}}}, true, nil
}

type fakeBugs2 struct{}

func (f fakeBugs2) Bugs(context.Context, string) ([]ports.BugFinding, bool, error) {
	return []ports.BugFinding{
		{Rule: "reliability-unreachable-code", File: "a", Line: 1},
		{Rule: "reliability-constant-condition", File: "a", Line: 2},
	}, true, nil
}

type fakeAnalyzer2 struct{}

func (f fakeAnalyzer2) Analyze(context.Context, string) ([]ports.CodeAnalysisRawFinding, error) {
	return nil, nil
}

func TestCatalogParity(t *testing.T) {
	cat, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("Failed to load catalog: %v", err)
	}

	rules, err := cat.List(context.Background())
	if err != nil {
		t.Fatalf("Failed to list catalog: %v", err)
	}

	catalogMap := make(map[string]rule.Rule)
	for _, r := range rules {
		catalogMap[string(r.Key)] = r
	}

	svc := New(fakeAnalyzer2{}, WithDuplication(fakeDup2{}), WithComplexity(fakeMetrics2{}, 15), WithBugs(fakeBugs2{}))
	fs, err := svc.Analyze(context.Background(), "root")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}

	for _, f := range fs {
		ruleID := f.RuleKey
		if ruleID == "" {
			t.Errorf("Finding missing RuleKey: %s", f.DedupKey)
			continue
		}
		catRule, ok := catalogMap[ruleID]
		if !ok {
			t.Errorf("Rule %s missing from catalog", ruleID)
			continue
		}

		if catRule.DefaultSeverity != f.Severity {
			t.Errorf("Rule %s Severity mismatch: catalog=%v engine=%v", ruleID, catRule.DefaultSeverity, f.Severity)
		}

		// Contract assertions mapping engine output to catalog metadata
		var expectedType rule.Type
		var expectedQuality rule.Quality
		var expectedDetection rule.Detection

		switch ruleID {
		case "quality-duplicated-block", "quality-high-complexity":
			expectedType = rule.TypeCodeSmell
			expectedQuality = rule.QualityMaintainability
			expectedDetection = rule.DetectionMetric
		case "reliability-unreachable-code", "reliability-constant-condition":
			expectedType = rule.TypeBug
			expectedQuality = rule.QualityReliability
			expectedDetection = rule.DetectionAST
		default:
			t.Errorf("Unknown rule ID %s", ruleID)
		}

		if catRule.Type != expectedType {
			t.Errorf("Rule %s Type mismatch: expected %v", ruleID, expectedType)
		}
		if len(catRule.Qualities) != 1 || catRule.Qualities[0] != expectedQuality {
			t.Errorf("Rule %s Quality mismatch: expected %v", ruleID, expectedQuality)
		}
		if catRule.Detection != expectedDetection {
			t.Errorf("Rule %s Detection mode mismatch: expected %v", ruleID, expectedDetection)
		}

		// The service engine emitted finding kind must match the catalog's quality tag.
		if (f.Kind == finding.KindQuality && expectedQuality != rule.QualityMaintainability) ||
			(f.Kind == finding.KindReliability && expectedQuality != rule.QualityReliability) {
			t.Errorf("Rule %s finding Kind %s conflicts with expected catalog Quality %v", ruleID, f.Kind, expectedQuality)
		}
	}

	// Ensure all 4 rules were tested
	if len(fs) != 4 {
		t.Errorf("Expected 4 findings, got %d", len(fs))
	}
}
