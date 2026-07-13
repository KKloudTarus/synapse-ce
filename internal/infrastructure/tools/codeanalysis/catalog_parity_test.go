package codeanalysis

import (
	"context"
	"strings"
	"testing"

	domainrule "github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/rulecatalog"
)

func TestCatalogParity(t *testing.T) {
	cat, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("Failed to load catalog: %v", err)
	}

	rules, err := cat.List(context.Background())
	if err != nil {
		t.Fatalf("Failed to list catalog: %v", err)
	}

	catalogMap := make(map[string]domainrule.Rule)
	for _, r := range rules {
		catalogMap[string(r.Key)] = r
	}

	builtin := builtinRules()
	if len(builtin) == 0 {
		t.Fatal("builtinRules() is empty")
	}

	for _, tc := range builtin {
		catRule, ok := catalogMap[tc.id]
		if !ok {
			t.Errorf("Rule %s missing from catalog", tc.id)
			continue
		}

		if catRule.Name != tc.title {
			t.Errorf("Rule %s Title mismatch: catalog=%q engine=%q", tc.id, catRule.Name, tc.title)
		}
		if catRule.DefaultSeverity != tc.severity {
			t.Errorf("Rule %s Severity mismatch: catalog=%v engine=%v", tc.id, catRule.DefaultSeverity, tc.severity)
		}

		// Contract for CodeAnalysis
		if tc.id == "quality-todo-comment" || tc.id == "quality-commented-out-code" {
			if catRule.Type != domainrule.TypeCodeSmell {
				t.Errorf("Rule %s Type mismatch: expected CodeSmell", tc.id)
			}
			if len(catRule.Qualities) != 1 || catRule.Qualities[0] != domainrule.QualityMaintainability {
				t.Errorf("Rule %s Quality mismatch: expected Maintainability", tc.id)
			}
			if catRule.Detection != domainrule.DetectionPattern {
				t.Errorf("Rule %s Detection mode mismatch: expected Pattern", tc.id)
			}
		}

		if tc.id == "reliability-empty-catch" || tc.id == "reliability-self-assignment" || tc.id == "reliability-self-comparison" {
			if catRule.Type != domainrule.TypeBug {
				t.Errorf("Rule %s Type mismatch: expected Bug", tc.id)
			}
			if len(catRule.Qualities) != 1 || catRule.Qualities[0] != domainrule.QualityReliability {
				t.Errorf("Rule %s Quality mismatch: expected Reliability", tc.id)
			}
			if catRule.Detection != domainrule.DetectionPattern {
				t.Errorf("Rule %s Detection mode mismatch: expected Pattern", tc.id)
			}
			if catRule.Detection != domainrule.DetectionPattern {
				t.Errorf("Rule %s Detection mode mismatch: expected Pattern", tc.id)
			}
		}

		if tc.id == "quality-commented-out-code" {
			continue // multiline heuristic
		}

		for _, line := range strings.Split(catRule.NoncompliantExample, "\n") {
			if strings.TrimSpace(line) != "" && tc.hit(line) {
				goto non_ok
			}
		}
		t.Errorf("Rule %s noncompliant example does not trigger detector", tc.id)
	non_ok:

		for _, line := range strings.Split(catRule.CompliantExample, "\n") {
			if strings.TrimSpace(line) != "" && tc.hit(line) {
				t.Errorf("Rule %s compliant example unexpectedly triggered detector", tc.id)
				break
			}
		}
	}

	for _, r := range rules {
		if r.Key == "quality-todo-comment" || r.Key == "quality-commented-out-code" || r.Key == "reliability-empty-catch" || r.Key == "reliability-self-assignment" || r.Key == "reliability-self-comparison" {
			found := false
			for _, tc := range builtin {
				if tc.id == string(r.Key) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Rule %s in catalog but missing from builtinRules", r.Key)
			}
		}
	}
}
