//go:build cgo

package astwalk

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/rulecatalog"
)

func TestScalaCognitiveComplexity(t *testing.T) {
	dir := t.TempDir()
	src := `object Service {
  def risky(x: Int): Int = {
    if (x > 0) {
      if (x > 1) {
        if (x > 2) {
          if (x > 3) {
            if (x > 4) {
              if (x > 5) x else 0
            } else 0
          } else 0
        } else 0
      } else 0
    } else 0
  }

  def safe(x: Int): Int =
    if (x > 0) x else 0
}
`
	if err := os.WriteFile(filepath.Join(dir, "Service.scala"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := QualityFor(context.Background(), dir)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}

	count := 0
	for _, finding := range got.Findings {
		if finding.Rule != "scala:cognitive-complexity" {
			continue
		}
		count++
		if finding.File != "Service.scala" {
			t.Errorf("file = %q, want Service.scala", finding.File)
		}
		if finding.Line != 2 {
			t.Errorf("line = %d, want 2", finding.Line)
		}
		if finding.Title != "Function has high cognitive complexity" {
			t.Errorf("unexpected title %q", finding.Title)
		}
	}
	if count != 1 {
		t.Fatalf("Scala cognitive findings = %d, want 1; all findings: %+v", count, got.Findings)
	}
}

func TestScalaASTCatalogParity(t *testing.T) {
	ctx := context.Background()
	cat, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("rulecatalog.Default: %v", err)
	}
	catalogRule, err := cat.Get(ctx, rule.Key("scala:cognitive-complexity"))
	if err != nil {
		t.Fatalf("Scala AST rule missing from catalog: %v", err)
	}
	if catalogRule.Language != "Scala" {
		t.Fatalf("language = %q, want Scala", catalogRule.Language)
	}
	if catalogRule.Detection != rule.DetectionAST {
		t.Fatalf("detection = %q, want AST", catalogRule.Detection)
	}

	scanExample := func(name, source string) []QualityFinding {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := QualityFor(ctx, dir)
		if err != nil {
			t.Fatalf("QualityFor: %v", err)
		}
		return got.Findings
	}

	found := false
	for _, finding := range scanExample("Noncompliant.scala", catalogRule.NoncompliantExample) {
		if finding.Rule != string(catalogRule.Key) {
			continue
		}
		found = true
		if finding.Title != catalogRule.Name {
			t.Fatalf("title mismatch: runtime=%q catalog=%q", finding.Title, catalogRule.Name)
		}
		if finding.Severity != string(catalogRule.DefaultSeverity) {
			t.Fatalf("severity mismatch: runtime=%q catalog=%q", finding.Severity, catalogRule.DefaultSeverity)
		}
	}
	if !found {
		t.Fatal("catalog noncompliant example did not trigger scala:cognitive-complexity")
	}

	for _, finding := range scanExample("Compliant.scala", catalogRule.CompliantExample) {
		if finding.Rule == string(catalogRule.Key) {
			t.Fatal("catalog compliant example triggered scala:cognitive-complexity")
		}
	}
}

func TestScalaCognitiveComplexityCap(t *testing.T) {
	dir := t.TempDir()
	var src strings.Builder
	src.WriteString("object Many {\n")
	for i := 0; i < maxScalaCognitiveFindingsPerFile+5; i++ {
		src.WriteString("def f")
		src.WriteString(string(rune('A' + i)))
		src.WriteString(`(x: Int): Int = {
if (x > 0) { if (x > 1) { if (x > 2) { if (x > 3) { if (x > 4) { if (x > 5) x else 0 } else 0 } else 0 } else 0 } else 0 } else 0
}
`)
	}
	src.WriteString("}\n")
	if err := os.WriteFile(filepath.Join(dir, "Many.scala"), []byte(src.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := QualityFor(context.Background(), dir)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	count := 0
	for _, finding := range got.Findings {
		if finding.Rule == "scala:cognitive-complexity" {
			count++
		}
	}
	if count != maxScalaCognitiveFindingsPerFile {
		t.Fatalf("Scala cognitive finding cap = %d, want %d", count, maxScalaCognitiveFindingsPerFile)
	}
}
