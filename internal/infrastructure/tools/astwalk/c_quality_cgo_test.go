//go:build cgo

package astwalk

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sitter "github.com/smacker/go-tree-sitter"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/rulecatalog"
)

func cFixtureFindings(t *testing.T, source string) []QualityFinding {
	t.Helper()
	root := parseRoot(context.Background(), specs["C"], []byte(source))
	if root == nil || root.HasError() {
		t.Fatalf("C fixture is not syntactically complete: %q", source)
	}
	findings, _ := cFindingsLimit(root, []byte(source), "fixture.c", 100)
	return findings
}

func cHasRule(findings []QualityFinding, wantKey string) bool {
	for _, f := range findings {
		if f.Rule == wantKey {
			return true
		}
	}
	return false
}

func TestCGrammarContractReachability(t *testing.T) {
	const source = `
#include <stdio.h>
struct Point { int x; int y; };
int main(void) {
    int val = 10;
    if (val > 0) {
        val++;
    }
    return 0;
}
`
	root := parseRoot(context.Background(), specs["C"], []byte(source))
	if root == nil || root.HasError() {
		t.Fatal("C grammar did not parse contract fixture")
	}
	seen := map[string]bool{}
	stack := []*sitter.Node{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		seen[n.Type()] = true
		for i := 0; i < int(n.ChildCount()); i++ {
			stack = append(stack, n.Child(i))
		}
	}
	for _, want := range []string{"function_definition", "declaration", "if_statement", "compound_statement", "return_statement"} {
		if !seen[want] {
			t.Errorf("bundled C grammar lacks reachable %q: %v", want, seen)
		}
	}
}

func TestCRuntimeKeyRegistryCompleteness(t *testing.T) {
	cat, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("rulecatalog.Default(): %v", err)
	}
	rules, err := cat.List(context.Background())
	if err != nil {
		t.Fatalf("cat.List(): %v", err)
	}
	cCount := 0
	for _, r := range rules {
		if r.Language == "C" && r.Detection == rule.DetectionAST {
			cCount++
			shortKey := strings.TrimPrefix(string(r.Key), "c:")
			if _, ok := cRuntimeRules[shortKey]; !ok {
				t.Errorf("C runtime registry missing key for catalog rule %q", r.Key)
			}
		}
	}
	if cCount != len(cRuntimeRules) {
		t.Errorf("C catalog AST rule count (%d) != runtime rule count (%d)", cCount, len(cRuntimeRules))
	}
}

func TestCASTCatalogExamples(t *testing.T) {
	cat, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("rulecatalog.Default(): %v", err)
	}
	rules, err := cat.List(context.Background())
	if err != nil {
		t.Fatalf("cat.List(): %v", err)
	}

	for _, r := range rules {
		if r.Language != "C" || r.Detection != rule.DetectionAST {
			continue
		}
		key := string(r.Key)
		t.Run(strings.TrimPrefix(key, "c:"), func(t *testing.T) {
			noncompliant := cExampleProgram(r.NoncompliantExample)
			findings := cFixtureFindings(t, noncompliant)
			if !cHasRule(findings, key) {
				t.Fatalf("noncompliant catalog example did not emit %s: %q (got findings: %+v)", key, r.NoncompliantExample, findings)
			}

			compliant := cExampleProgram(r.CompliantExample)
			compliantFindings := cFixtureFindings(t, compliant)
			if cHasRule(compliantFindings, key) {
				t.Fatalf("compliant catalog example emitted %s: %q", key, r.CompliantExample)
			}
		})
	}
}

func cExampleProgram(example string) string {
	trimmed := strings.TrimSpace(example)
	if strings.HasPrefix(trimmed, "void ") || strings.HasPrefix(trimmed, "int ") || strings.HasPrefix(trimmed, "char ") || strings.HasPrefix(trimmed, "struct ") || strings.HasPrefix(trimmed, "#define") || strings.HasPrefix(trimmed, "__attribute__") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "//") {
		if strings.HasPrefix(trimmed, "__attribute__") && !strings.Contains(trimmed, "{") {
			return trimmed + "\nvoid fixture(void) {}"
		}
		if (strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "//")) && !strings.Contains(trimmed, "void ") {
			return trimmed + "\nvoid fixture(void) {}"
		}
		return trimmed
	}
	return "void fixture(void) {\n" + trimmed + "\n}"
}

func TestCQualityForDispatch(t *testing.T) {
	dir := t.TempDir()
	src := `
#include <stdio.h>
void test_vla(int len) {
    char buf[len];
}
`
	if err := os.WriteFile(filepath.Join(dir, "vla.c"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := QualityFor(context.Background(), dir)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	found := false
	for _, f := range got.Findings {
		if f.Rule == "c:vla-stack-allocation" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("QualityFor did not find c:vla-stack-allocation in C file: %+v", got.Findings)
	}
}
