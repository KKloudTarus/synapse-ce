//go:build cgo

package astwalk

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/rulecatalog"
)

func TestRubyCognitiveComplexity(t *testing.T) {
	dir := t.TempDir()
	src := `class Service
  def risky(value)
    if value > 0
      if value > 1
        if value > 2
          if value > 3
            if value > 4
              if value > 5
                value
              else
                0
              end
            else
              0
            end
          else
            0
          end
        else
          0
        end
      else
        0
      end
    else
      0
    end
  end

  def safe(value)
    value.positive? ? value : 0
  end
end
`
	if err := os.WriteFile(filepath.Join(dir, "service.rb"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := QualityFor(context.Background(), dir)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}

	count := 0
	for _, finding := range got.Findings {
		if finding.Rule != "rb:cognitive-complexity" {
			continue
		}
		count++
		if finding.File != "service.rb" {
			t.Errorf("file = %q, want service.rb", finding.File)
		}
		if finding.Line != 2 {
			t.Errorf("line = %d, want 2", finding.Line)
		}
		if finding.Title != "Method has high cognitive complexity" {
			t.Errorf("unexpected title %q", finding.Title)
		}
	}
	if count != 1 {
		t.Fatalf("Ruby cognitive findings = %d, want 1; all findings: %+v", count, got.Findings)
	}
}

func TestRubyASTCatalogParity(t *testing.T) {
	ctx := context.Background()
	cat, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("rulecatalog.Default: %v", err)
	}
	catalogRule, err := cat.Get(ctx, rule.Key("rb:cognitive-complexity"))
	if err != nil {
		t.Fatalf("Ruby AST rule missing from catalog: %v", err)
	}
	if catalogRule.Language != "Ruby" {
		t.Fatalf("language = %q, want Ruby", catalogRule.Language)
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
	for _, finding := range scanExample("noncompliant.rb", catalogRule.NoncompliantExample) {
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
		t.Fatal("catalog noncompliant example did not trigger rb:cognitive-complexity")
	}

	for _, finding := range scanExample("compliant.rb", catalogRule.CompliantExample) {
		if finding.Rule == string(catalogRule.Key) {
			t.Fatal("catalog compliant example triggered rb:cognitive-complexity")
		}
	}
}

func TestRubyCognitiveComplexityCap(t *testing.T) {
	dir := t.TempDir()
	var src strings.Builder
	src.WriteString("class Many\n")
	for i := 0; i < maxRubyCognitiveFindingsPerFile+5; i++ {
		fmt.Fprintf(&src, "def f%d(value)\n", i)
		src.WriteString(`if value > 0
if value > 1
if value > 2
if value > 3
if value > 4
if value > 5
value
else
0
end
else
0
end
else
0
end
else
0
end
else
0
end
else
0
end
end
`)
	}
	src.WriteString("end\n")
	if err := os.WriteFile(filepath.Join(dir, "many.rb"), []byte(src.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := QualityFor(context.Background(), dir)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	count := 0
	for _, finding := range got.Findings {
		if finding.Rule == "rb:cognitive-complexity" {
			count++
		}
	}
	if count != maxRubyCognitiveFindingsPerFile {
		t.Fatalf("Ruby cognitive finding cap = %d, want %d", count, maxRubyCognitiveFindingsPerFile)
	}
}
