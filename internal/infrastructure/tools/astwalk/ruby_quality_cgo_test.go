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

func TestRubyDuplicateWhenCondition(t *testing.T) {
	scan := func(name, source string) []QualityFinding {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := QualityFor(context.Background(), dir)
		if err != nil {
			t.Fatalf("QualityFor: %v", err)
		}
		return got.Findings
	}
	dupLines := func(fs []QualityFinding) []int {
		var ls []int
		for _, f := range fs {
			if f.Rule == "rb:duplicate-when-condition" {
				ls = append(ls, f.Line)
			}
		}
		return ls
	}
	countDup := func(fs []QualityFinding) int { return len(dupLines(fs)) }

	// A duplicated when condition fires exactly once, anchored at the duplicate branch (not the first).
	// dup.rb: `when 1` on line 3 then line 4, so the finding is at line 4.
	if got := dupLines(scan("dup.rb", "def f(x)\n  case x\n  when 1 then 'a'\n  when 1 then 'b'\n  else 'c'\n  end\nend\n")); len(got) != 1 || got[0] != 4 {
		t.Errorf("literal duplicate when: got lines %v, want [4]", got)
	}
	// multi.rb: `when 2, 3` (line 3) then `when 3` (line 4); the finding anchors at the duplicate on line 4.
	if got := dupLines(scan("multi.rb", "def f(x)\n  case x\n  when 2, 3 then 'a'\n  when 3 then 'b'\n  end\nend\n")); len(got) != 1 || got[0] != 4 {
		t.Errorf("multi-value duplicate when: got lines %v, want [4]", got)
	}
	if n := countDup(scan("sym.rb", "def f(s)\n  case s\n  when :active then 1\n  when :active then 2\n  end\nend\n")); n != 1 {
		t.Errorf("symbol duplicate when: got %d findings, want 1", n)
	}

	// Distinct conditions and the same literal reused across two independent case expressions do not fire.
	if n := countDup(scan("clean.rb", "def f(x)\n  case x\n  when 1 then 'a'\n  when 2 then 'b'\n  else 'c'\n  end\nend\n")); n != 0 {
		t.Errorf("distinct when conditions: got %d findings, want 0", n)
	}
	if n := countDup(scan("two.rb", "def f(x, y)\n  case x\n  when 1 then 'a'\n  end\n  case y\n  when 1 then 'b'\n  end\nend\n")); n != 0 {
		t.Errorf("same literal in separate case expressions: got %d findings, want 0", n)
	}
}

func TestRubyDuplicateWhenCatalogParity(t *testing.T) {
	ctx := context.Background()
	cat, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("rulecatalog.Default: %v", err)
	}
	catalogRule, err := cat.Get(ctx, rule.Key("rb:duplicate-when-condition"))
	if err != nil {
		t.Fatalf("rb:duplicate-when-condition missing from catalog: %v", err)
	}
	if catalogRule.Type != rule.TypeBug || catalogRule.Detection != rule.DetectionAST {
		t.Fatalf("catalog rule type=%q detection=%q, want bug/AST", catalogRule.Type, catalogRule.Detection)
	}
	scan := func(name, source string) []QualityFinding {
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
	for _, f := range scan("noncompliant.rb", catalogRule.NoncompliantExample) {
		if f.Rule == string(catalogRule.Key) {
			found = true
			if f.Title != catalogRule.Name || f.Severity != string(catalogRule.DefaultSeverity) {
				t.Fatalf("runtime/catalog mismatch: title=%q sev=%q vs %q/%q", f.Title, f.Severity, catalogRule.Name, catalogRule.DefaultSeverity)
			}
		}
	}
	if !found {
		t.Fatal("catalog noncompliant example did not trigger rb:duplicate-when-condition")
	}
	for _, f := range scan("compliant.rb", catalogRule.CompliantExample) {
		if f.Rule == string(catalogRule.Key) {
			t.Fatal("catalog compliant example triggered rb:duplicate-when-condition")
		}
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
