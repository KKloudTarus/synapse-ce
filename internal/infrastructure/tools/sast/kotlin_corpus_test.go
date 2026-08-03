package sast

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	domainrule "github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/rulecatalog"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestKotlinPatternCorpusRunsThroughAnalyzer(t *testing.T) {
	cat, err := rulecatalog.Default()
	if err != nil {
		t.Fatal(err)
	}
	rules, err := cat.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	analyzer := New()
	for _, catalogRule := range rules {
		if catalogRule.Language != "Kotlin" || catalogRule.Detection != domainrule.DetectionPattern {
			continue
		}
		engineRule := patternRule(analyzer, string(catalogRule.Key))
		if engineRule == nil {
			t.Errorf("%s missing from pattern analyzer", catalogRule.Key)
			continue
		}
		t.Run(string(catalogRule.Key), func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "Noncompliant.kt"), []byte(catalogRule.NoncompliantExample+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			hits, err := analyzer.AnalyzeSource(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			if !hasSASTRule(hits, string(catalogRule.Key)) {
				t.Errorf("noncompliant Kotlin did not emit %s: %+v", catalogRule.Key, hits)
			}

			root = t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "Compliant.kt"), []byte(catalogRule.CompliantExample+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			hits, err = analyzer.AnalyzeSource(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			if hasSASTRule(hits, string(catalogRule.Key)) {
				t.Errorf("compliant Kotlin emitted %s: %+v", catalogRule.Key, hits)
			}
		})
	}
}

func patternRule(analyzer *Analyzer, id string) *rule {
	for i := range analyzer.rules {
		if analyzer.rules[i].id == id {
			return &analyzer.rules[i]
		}
	}
	return nil
}

func hasSASTRule(findings []ports.SASTRawFinding, id string) bool {
	for _, finding := range findings {
		if finding.RuleID == id {
			return true
		}
	}
	return false
}
