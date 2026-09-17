package sast

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	domainrule "github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/rulecatalog"
)

// TestNewLangpackCorpusRunsThroughAnalyzer proves the #1135 acceptance: every Terraform and Dart
// language-pack pattern rule fires on its noncompliant example and stays silent on its compliant
// example when the example is written to a real file with the language's natural extension. (Dockerfile
// is deliberately not a language-pack language: the IaC misconfig engine already covers it.)
func TestNewLangpackCorpusRunsThroughAnalyzer(t *testing.T) {
	cat, err := rulecatalog.Default()
	if err != nil {
		t.Fatal(err)
	}
	rules, err := cat.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	analyzer := New()

	cases := []struct {
		language string
		ncFile   string
		cFile    string
	}{
		{"Terraform", "main.tf", "main.tf"},
		{"Dart", "main.dart", "main.dart"},
	}
	for _, tc := range cases {
		matched := 0
		for _, catalogRule := range rules {
			if catalogRule.Language != tc.language || catalogRule.Detection != domainrule.DetectionPattern {
				continue
			}
			// A rule of this language that is not in the SAST analyzer belongs to another engine (the IaC
			// misconfig engine also emits Terraform/Dockerfile rules); this test only covers the SAST
			// language-pack rules, which are exactly the ones the analyzer holds.
			if patternRule(analyzer, string(catalogRule.Key)) == nil {
				continue
			}
			matched++
			t.Run(string(catalogRule.Key), func(t *testing.T) {
				root := t.TempDir()
				if err := os.WriteFile(filepath.Join(root, tc.ncFile), []byte(catalogRule.NoncompliantExample+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				hits, err := analyzer.AnalyzeSource(context.Background(), root)
				if err != nil {
					t.Fatal(err)
				}
				if !hasSASTRule(hits, string(catalogRule.Key)) {
					t.Errorf("noncompliant %s did not emit %s: %+v", tc.language, catalogRule.Key, hits)
				}

				root = t.TempDir()
				if err := os.WriteFile(filepath.Join(root, tc.cFile), []byte(catalogRule.CompliantExample+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				hits, err = analyzer.AnalyzeSource(context.Background(), root)
				if err != nil {
					t.Fatal(err)
				}
				if hasSASTRule(hits, string(catalogRule.Key)) {
					t.Errorf("compliant %s emitted %s: %+v", tc.language, catalogRule.Key, hits)
				}
			})
		}
		if matched == 0 {
			t.Errorf("no %s pattern rules found in the catalog; the language was not wired", tc.language)
		}
	}
}
