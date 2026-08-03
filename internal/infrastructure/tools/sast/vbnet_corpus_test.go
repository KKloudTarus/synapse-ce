package sast

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	domainrule "github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/rulecatalog"
)

func TestVBNetPatternCorpusRunsThroughAnalyzer(t *testing.T) {
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
		if catalogRule.Language != "VB.NET" || catalogRule.Detection != domainrule.DetectionPattern {
			continue
		}
		if patternRule(analyzer, string(catalogRule.Key)) == nil {
			t.Errorf("%s missing from pattern analyzer", catalogRule.Key)
			continue
		}
		t.Run(string(catalogRule.Key), func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "Noncompliant.vb"), []byte(catalogRule.NoncompliantExample+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			hits, err := analyzer.AnalyzeSource(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			if !hasSASTRule(hits, string(catalogRule.Key)) {
				t.Errorf("noncompliant VB.NET did not emit %s: %+v", catalogRule.Key, hits)
			}

			root = t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "Compliant.vb"), []byte(catalogRule.CompliantExample+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			hits, err = analyzer.AnalyzeSource(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			if hasSASTRule(hits, string(catalogRule.Key)) {
				t.Errorf("compliant VB.NET emitted %s: %+v", catalogRule.Key, hits)
			}
		})
	}
}
